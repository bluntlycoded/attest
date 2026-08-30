"""What a reviewer actually sees when the scheduler decides to interrupt them.

Deciding *when* to ask is only useful if the asking is answerable. A prompt
reading "agent-7 wants to access billing - approve?" cannot be reasoned about,
so it gets approved reflexively, and a system whose interruptions are always
approved has the appearance of governance and none of the substance. Timing the
question well and then asking it badly produces a rubber stamp on a schedule.

A packet therefore carries what a person needs to answer: the specific tool and
the resources it touches, whether the action can be undone, how far it reaches,
why the engine is asking now, and the steps that led here.

Risk is computed here, from the operator's catalogue
----------------------------------------------------
Nothing in a packet is derived from what the agent says about itself. Tool
descriptions and annotations arrive over the same channel as the request and
are attacker-controllable; an agent that could label its own action "read-only"
would simply do so. Risk comes from :class:`ToolCatalog`, which the operator
owns, and an unrecognised tool is treated as dangerous rather than as ordinary.

Escalation is on the intersection, not on any single axis
---------------------------------------------------------
Magnitude alone flags every large routine transfer. Novelty alone flags every
first use of a legitimate new tool. Irreversibility alone flags every delete.
What warrants a person is the combination: large *and* irreversible *and*
unlike anything this agent has done before.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "Reversibility",
    "Tier",
    "ToolRisk",
    "ToolCatalog",
    "ActionRisk",
    "Step",
    "DecisionPacket",
    "PacketBuilder",
]


class Reversibility(str, Enum):
    """Whether the action can be taken back, and at what cost."""

    REVERSIBLE = "reversible"
    """Undone cleanly - a draft saved, a cache warmed."""

    RECOVERABLE = "recoverable"
    """Undone with effort - a row deleted but in backup, a message retractable."""

    IRREVERSIBLE = "irreversible"
    """Cannot be undone - funds sent, data exfiltrated, a record purged."""

    UNKNOWN = "unknown"
    """Not in the catalogue. Treated as irreversible, because assuming
    otherwise is only ever wrong in the expensive direction."""

    @property
    def weight(self) -> float:
        return {
            Reversibility.REVERSIBLE: 0.0,
            Reversibility.RECOVERABLE: 0.5,
            Reversibility.IRREVERSIBLE: 1.0,
            Reversibility.UNKNOWN: 1.0,
        }[self]


class Tier(str, Enum):
    """Who, if anyone, is asked."""

    AUTO = "auto"
    """No human. Enforced and logged. Has to be the overwhelming majority or
    the system is unusable."""

    OWNER = "owner"
    """Whoever owns this agent - the engineer who deployed it - reached where
    they already work. Routing this to a central queue kills it on latency;
    agents do not wait politely."""

    AUTHORITY = "authority"
    """A named person with actual authority. Kept rare enough that it can be
    read properly. Collapsing this into OWNER is the mistake to avoid: the
    same overloaded on-call treats a routine oddity and a consequential action
    with the same low attention, and it is the second one that needed care."""


@dataclass(frozen=True)
class ToolRisk:
    """Operator-declared properties of one tool.

    Args:
        reversibility: Whether its effects can be undone.
        magnitude: Inherent consequence on a 0-1 scale, independent of
            arguments. Reading a public doc is near zero; wiring money is one.
        sensitive: Whether it touches regulated or personal data.
        description: Shown to the reviewer. Written by the operator, never by
            the agent.
    """

    reversibility: Reversibility = Reversibility.UNKNOWN
    magnitude: float = 1.0
    sensitive: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.magnitude <= 1.0:
            raise ValueError(f"magnitude must lie in [0, 1], got {self.magnitude}")


# An unrecognised tool is not a low-risk tool. Failing closed here is what
# stops an agent from reaching something dangerous simply by reaching for
# something nobody catalogued.
UNKNOWN_TOOL = ToolRisk(
    reversibility=Reversibility.UNKNOWN,
    magnitude=1.0,
    sensitive=True,
    description="not in the catalogue",
)


@dataclass
class ToolCatalog:
    """The operator's declaration of what each tool can do.

    This is the trusted source. It is deliberately separate from anything the
    agent transmits, because tool annotations arrive over the same channel as
    the request and an agent able to label its own action "read-only" would.
    """

    tools: dict[str, ToolRisk] = field(default_factory=dict)

    def declare(self, name: str, risk: ToolRisk) -> "ToolCatalog":
        self.tools[name] = risk
        return self

    def risk_for(self, tool: str) -> ToolRisk:
        """Declared risk, or the fail-closed default for anything unknown."""
        return self.tools.get(tool, UNKNOWN_TOOL)

    def known(self, tool: str) -> bool:
        return tool in self.tools

    def __len__(self) -> int:
        return len(self.tools)


@dataclass(frozen=True)
class ActionRisk:
    """How consequential this particular action is.

    Attributes:
        novelty: How unlike this agent's history the action is, in [0, 1].
        score: Combined severity, in [0, 1].
        tier: Who should be asked.
    """

    magnitude: float
    reversibility: Reversibility
    novelty: float
    sensitive: bool
    score: float
    tier: Tier

    @property
    def drivers(self) -> list[str]:
        """Plain-language reasons this was escalated, for the packet."""
        out = []
        if self.reversibility in (
            Reversibility.IRREVERSIBLE,
            Reversibility.UNKNOWN,
        ):
            out.append(f"cannot be undone ({self.reversibility.value})")
        if self.magnitude >= 0.7:
            out.append("high-consequence tool")
        if self.novelty >= 0.7:
            out.append("unlike anything this agent has done before")
        if self.sensitive:
            out.append("touches sensitive data")
        return out


@dataclass(frozen=True)
class Step:
    """One earlier action, for the trail that led here."""

    at: float
    tool: str
    resource: str
    allowed: bool

    def render(self) -> str:
        mark = "ok " if self.allowed else "held"
        return f"    [{mark}] {self.tool} -> {self.resource or '-'}"


@dataclass(frozen=True)
class DecisionPacket:
    """Everything a reviewer needs, and nothing they have to take on faith."""

    agent_id: str
    target: str
    requested_at: float
    expires_at: float
    tool: str
    resource: str
    intent: str
    argument_digest: str
    trust: float
    effective_trust: float
    chain: tuple[str, ...]
    reason: str
    risk: ActionRisk
    tool_description: str
    recent: tuple[Step, ...] = ()

    @property
    def seconds_remaining(self) -> float:
        return max(0.0, self.expires_at - self.requested_at)

    @property
    def delegated(self) -> bool:
        return len(self.chain) > 1

    def to_dict(self) -> dict[str, Any]:
        """Structured form, for a UI or an audit record."""
        return {
            "agent_id": self.agent_id,
            "target": self.target,
            "requested_at": self.requested_at,
            "expires_at": self.expires_at,
            "tool": self.tool,
            "resource": self.resource,
            "intent": self.intent,
            "argument_digest": self.argument_digest,
            "trust": self.trust,
            "effective_trust": self.effective_trust,
            "chain": list(self.chain),
            "reason": self.reason,
            "tier": self.risk.tier.value,
            "risk_score": self.risk.score,
            "reversibility": self.risk.reversibility.value,
            "novelty": self.risk.novelty,
            "drivers": self.risk.drivers,
            "tool_description": self.tool_description,
            "recent": [
                {"at": s.at, "tool": s.tool, "resource": s.resource, "allowed": s.allowed}
                for s in self.recent
            ],
        }

    def render(self) -> str:
        """Plain text, for Slack or a terminal.

        Deliberately leads with what is being asked and what it would do,
        rather than with the score. A reviewer needs to decide about the
        action; the trust figure is context for that, not the subject.
        """
        lines = [
            f"{self.agent_id} wants to run: {self.tool}",
        ]
        if self.tool_description:
            lines.append(f"  {self.tool_description}")
        if self.resource:
            lines.append(f"  on: {self.resource}")
        if self.intent and self.intent != "unknown":
            lines.append(f"  stated intent: {self.intent}")

        lines.append("")
        lines.append(f"  reversibility : {self.risk.reversibility.value}")
        if self.risk.drivers:
            lines.append(f"  escalated because: {'; '.join(self.risk.drivers)}")
        lines.append(
            f"  trust         : {self.trust:.3f}"
            + (
                f" (chain {self.effective_trust:.3f} via {' > '.join(self.chain[:-1])})"
                if self.delegated
                else ""
            )
        )
        if self.target != self.agent_id:
            lines.append(
                f"  note          : the weak link is {self.target}, not the sender"
            )
        lines.append(f"  engine reason : {self.reason}")
        lines.append(f"  arguments     : sha256 {self.argument_digest[:16]}")

        if self.recent:
            lines.append("")
            lines.append("  what led here:")
            lines.extend(step.render() for step in self.recent)

        lines.append("")
        lines.append(
            f"  expires in {self.seconds_remaining:.0f}s - "
            "no answer means the action is abandoned, not allowed"
        )
        return "\n".join(lines)


def digest(arguments: Any) -> str:
    """Stable hash of the arguments, so a reviewer can tell two calls apart.

    The arguments themselves are not carried into the packet. They routinely
    contain exactly the customer data an approval workflow should not be
    copying into a chat channel, and the reviewer's question is what the action
    does rather than what the payload contains.
    """
    try:
        encoded = json.dumps(arguments, sort_keys=True, default=str)
    except (TypeError, ValueError):
        encoded = repr(arguments)
    return hashlib.sha256(encoded.encode()).hexdigest()


@dataclass
class PacketBuilder:
    """Assembles packets, and decides which tier each one belongs to.

    Args:
        catalog: Operator-declared tool risk.
        owner_threshold: Combined score at or above which the agent's owner is
            asked.
        authority_threshold: Score at or above which a named authority is.
        hold_seconds: How long a request waits before it is abandoned.
        history: Earlier steps retained per agent for the trail.
    """

    catalog: ToolCatalog = field(default_factory=ToolCatalog)
    owner_threshold: float = 0.35
    authority_threshold: float = 0.7
    hold_seconds: float = 300.0
    history: int = 6
    _seen: dict[str, set[str]] = field(default_factory=dict, init=False)
    _recent: dict[str, list[Step]] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        if not 0.0 <= self.owner_threshold <= self.authority_threshold <= 1.0:
            raise ValueError(
                "require 0 <= owner_threshold <= authority_threshold <= 1"
            )

    def observe(self, agent_id: str, tool: str, resource: str, at: float, allowed: bool) -> None:
        """Record an action, whether or not it needed approval.

        The trail has to include actions that were allowed. A reviewer shown
        only the held requests sees an agent that appears to do nothing but
        dangerous things.
        """
        self._seen.setdefault(agent_id, set()).add(tool)
        trail = self._recent.setdefault(agent_id, [])
        trail.append(Step(at=at, tool=tool, resource=resource, allowed=allowed))
        if len(trail) > self.history:
            trail.pop(0)

    def forget(self) -> None:
        """Drop every agent's tool history and trail. Demo reset only."""
        self._seen.clear()
        self._recent.clear()

    def novelty(self, agent_id: str, tool: str) -> float:
        """How unfamiliar this tool is for this agent."""
        seen = self._seen.get(agent_id, set())
        if not seen:
            # A brand-new agent has no history to be unlike. Treating that as
            # maximum novelty would escalate every first action it ever takes.
            return 0.5
        return 0.0 if tool in seen else 1.0

    def assess(self, agent_id: str, tool: str, *, trust: float) -> ActionRisk:
        """Score one action and place it in a tier."""
        risk = self.catalog.risk_for(tool)
        novelty = self.novelty(agent_id, tool)

        # A geometric mean, so a low value on any axis pulls the result down.
        # An arithmetic mean would let a very large but routine and reversible
        # action escalate on magnitude alone, which is the behaviour that
        # produces constant interruptions at high traffic.
        axes = [
            max(risk.magnitude, 1e-6),
            max(risk.reversibility.weight, 1e-6),
            max(novelty, 1e-6),
        ]
        combined = math.exp(sum(math.log(a) for a in axes) / len(axes))

        # Low trust raises severity but cannot create it on its own: a
        # distrusted agent reading a public document is still reading a public
        # document.
        score = min(1.0, combined * (1.0 + (1.0 - trust)))
        if risk.sensitive:
            score = min(1.0, score * 1.25)

        if score >= self.authority_threshold:
            tier = Tier.AUTHORITY
        elif score >= self.owner_threshold:
            tier = Tier.OWNER
        else:
            tier = Tier.AUTO

        return ActionRisk(
            magnitude=risk.magnitude,
            reversibility=risk.reversibility,
            novelty=novelty,
            sensitive=risk.sensitive,
            score=score,
            tier=tier,
        )

    def build(
        self,
        decision,
        *,
        tool: str,
        resource: str = "",
        arguments: Any = None,
        intent: str = "",
    ) -> DecisionPacket:
        """Assemble a packet for a decision the engine chose to escalate.

        Args:
            decision: The engine's :class:`~attest.Decision`.
            tool: Tool the agent is asking to run, as seen at the enforcement
                point rather than as the agent described it.
        """
        risk = self.assess(
            decision.agent_id,
            tool,
            trust=decision.effective_trust
            if decision.effective_trust is not None
            else decision.trust,
        )
        declared = self.catalog.risk_for(tool)

        return DecisionPacket(
            agent_id=decision.agent_id,
            target=decision.verification_target,
            requested_at=decision.timestamp,
            expires_at=decision.timestamp + self.hold_seconds,
            tool=tool,
            resource=resource,
            intent=intent,
            argument_digest=digest(arguments),
            trust=decision.trust,
            effective_trust=(
                decision.effective_trust
                if decision.effective_trust is not None
                else decision.trust
            ),
            chain=decision.chain or (decision.agent_id,),
            reason=decision.reason.value,
            risk=risk,
            tool_description=declared.description,
            recent=tuple(self._recent.get(decision.agent_id, ())),
        )
