"""Policy middleware for an agent gateway.

Every major agent runtime now speaks MCP, and gateways sitting between agents
and their tools are becoming the place enterprise policy is enforced. What
those gateways carry is identity, rate limits and spend caps. What none of them
carry is a decision about *when* a person should be asked - which is the one
question this project answers.

This is the integration point rather than a gateway of its own. It takes an
intercepted tool call and returns allow, hold or deny. Wiring it to a specific
transport is a small adapter; :func:`from_mcp_request` is one for MCP's
``tools/call``.

Two independent questions, deliberately not merged
--------------------------------------------------
*Is this agent behaving?* is temporal and belongs to the engine. *Is this
action consequential?* is a property of the action and belongs to the tool
catalogue. Both have to be asked, because they fail in opposite directions: a
trusted agent can still be asked to do something irreversible it has never done
before, and a distrusted agent reading a public document is not worth
interrupting anyone over.

The budget governs one of them and not the other
------------------------------------------------
The verification budget limits how many *proactive* checks the monitor spends
chasing agents whose behaviour has drifted. It does not gate consequential
actions. Conflating the two would mean a fleet that had used up its budget
waved a wire transfer through because it could not afford to look - which is
precisely backwards, since budget is exhausted when things are going badly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .approval import Outcome
from .engine import AttestEngine, Decision
from .evidence import Envelope
from .packet import DecisionPacket, PacketBuilder, Tier
from .policy import Action
from .queue import ApprovalQueue

__all__ = ["ToolCall", "Verdict", "GatewayDecision", "AttestGateway", "from_mcp_request"]


class Verdict(str, Enum):
    """What the gateway tells the caller to do."""

    ALLOW = "allow"
    """Proceed. Recorded, not interrupted."""

    HOLD = "hold"
    """Wait for a person. The call does not proceed until answered, and an
    unanswered hold ends as a denial rather than as permission."""

    DENY = "deny"
    """Refuse without asking. Someone has already said no about this agent;
    asking again for every subsequent call is how a reviewer is trained to
    stop reading."""


@dataclass(frozen=True)
class ToolCall:
    """One intercepted invocation.

    Attributes:
        agent_id: Caller identity, as established by the gateway's own
            authentication - never as claimed in the payload.
        tool: Tool being invoked, resolved at the gateway.
        arguments: Call arguments. Digested for the packet, never carried into
            it.
        authenticated: Whether the gateway verified the caller's credential.
        credential_valid: Whether that credential was unexpired and unrevoked.
        on_behalf_of: Delegation chain above the caller, root first.
    """

    agent_id: str
    tool: str
    arguments: Any = None
    resource: str = ""
    intent: str = ""
    timestamp: float = 0.0
    authenticated: bool = True
    credential_valid: bool = True
    logged: bool = True
    on_behalf_of: tuple[str, ...] = ()

    def to_envelope(self) -> Envelope:
        """The evidence form the trust engine consumes."""
        return Envelope(
            sender=self.agent_id,
            recipient=self.tool,
            intent=self.intent or "tool_call",
            action=self.tool,
            timestamp=self.timestamp,
            signature_valid=self.authenticated,
            credential_valid=self.credential_valid,
            audit_proof=f"gateway:{self.timestamp}" if self.logged else None,
            on_behalf_of=tuple(self.on_behalf_of),
        )


@dataclass(frozen=True)
class GatewayDecision:
    """What the gateway decided, and why.

    Attributes:
        request_id: Approval request raised, when the verdict was HOLD.
        packet: What a reviewer will be shown, when one is being asked.
        explain: One line an operator - or the agent's developer - can read.
    """

    verdict: Verdict
    call: ToolCall
    decision: Decision
    explain: str
    request_id: str | None = None
    packet: DecisionPacket | None = None
    tier: Tier = Tier.AUTO

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW


@dataclass
class AttestGateway:
    """Decides allow, hold or deny for each intercepted tool call.

    Args:
        engine: Trust and scheduling.
        builder: Assembles packets and assigns tiers.
        queue: Where held requests wait for an answer.
        deny_below: Trust at or below which calls are refused outright rather
            than escalated. Once a reviewer has rejected an agent, raising a
            fresh approval for its every subsequent call is how a person is
            taught to stop reading.
        hold_on_verify: Whether a scheduled verification also holds the call
            that triggered it. True is the safer reading and the default;
            False lets the check proceed out of band while the agent keeps
            working, which suits a shadow rollout.
    """

    engine: AttestEngine
    builder: PacketBuilder
    queue: ApprovalQueue = field(default_factory=ApprovalQueue)
    deny_below: float = 0.15
    hold_on_verify: bool = True

    def __post_init__(self) -> None:
        if not 0.0 <= self.deny_below <= 1.0:
            raise ValueError(f"deny_below must lie in [0, 1], got {self.deny_below}")

    def evaluate(self, call: ToolCall) -> GatewayDecision:
        """Judge one tool call."""
        decision = self.engine.observe(call.to_envelope())
        trust = (
            decision.effective_trust
            if decision.effective_trust is not None
            else decision.trust
        )
        risk = self.builder.assess(call.agent_id, call.tool, trust=trust)

        # Refuse outright before considering anything else. An agent this far
        # down has already been judged, and re-asking is noise.
        if trust <= self.deny_below:
            self.builder.observe(
                call.agent_id, call.tool, call.resource, call.timestamp, False
            )
            return GatewayDecision(
                verdict=Verdict.DENY,
                call=call,
                decision=decision,
                tier=risk.tier,
                explain=(
                    f"denied: {decision.verification_target} is at trust "
                    f"{trust:.3f}, at or below the {self.deny_below:.2f} floor"
                ),
            )

        needs_person = risk.tier is not Tier.AUTO
        scheduled = self.hold_on_verify and decision.action is Action.VERIFY

        if needs_person or scheduled:
            packet = self.builder.build(
                decision,
                tool=call.tool,
                resource=call.resource,
                arguments=call.arguments,
                intent=call.intent,
            )
            request = self.queue.open(packet)
            self.builder.observe(
                call.agent_id, call.tool, call.resource, call.timestamp, False
            )
            why = (
                "; ".join(risk.drivers)
                if needs_person
                else f"scheduled check ({decision.reason.value})"
            )
            return GatewayDecision(
                verdict=Verdict.HOLD,
                call=call,
                decision=decision,
                tier=risk.tier,
                request_id=request.request_id,
                packet=packet,
                explain=f"held for {risk.tier.value}: {why}",
            )

        self.builder.observe(
            call.agent_id, call.tool, call.resource, call.timestamp, True
        )
        return GatewayDecision(
            verdict=Verdict.ALLOW,
            call=call,
            decision=decision,
            tier=risk.tier,
            explain=f"allowed: routine for this agent, trust {trust:.3f}",
        )

    def decide(
        self, request_id: str, approver: str, outcome: Outcome, at: float
    ) -> Verdict:
        """Apply a reviewer's answer and release or refuse the held call."""
        record = self.queue.decide(request_id, approver, outcome, at)
        self.engine.resolve(
            record.agent_id,
            record.outcome,
            at,
            approver=record.approver,
            latency_seconds=record.latency_seconds,
        )
        return Verdict.ALLOW if outcome is Outcome.APPROVED else Verdict.DENY

    def sweep(self, now: float) -> list[str]:
        """Age out unanswered holds.

        Returns:
            Request ids that timed out. Every one of them is a denial: the
            call never ran. A gateway that released them instead would be
            most permissive exactly when its reviewers were most overwhelmed.
        """
        expired = self.queue.expire(now)
        for request in expired:
            self.engine.resolve(request.packet.target, Outcome.TIMEOUT, now)
        return [r.request_id for r in expired]

    def status(self, request_id: str) -> Verdict:
        """Where a held call stands, for a caller polling on it."""
        request = self.queue.get(request_id)
        if request is None:
            raise KeyError(f"unknown approval request {request_id!r}")
        if not request.resolved:
            return Verdict.HOLD
        return (
            Verdict.ALLOW if request.outcome is Outcome.APPROVED else Verdict.DENY
        )


def from_mcp_request(
    payload: dict[str, Any],
    *,
    agent_id: str,
    timestamp: float,
    authenticated: bool = True,
    credential_valid: bool = True,
    on_behalf_of: tuple[str, ...] = (),
) -> ToolCall:
    """Build a :class:`ToolCall` from an MCP ``tools/call`` request.

    ``agent_id`` is supplied by the caller rather than read from the payload,
    because identity has to come from whatever the gateway authenticated. A
    request that could name its own caller would let any agent act as any
    other.

    Args:
        payload: The JSON-RPC request object.
    """
    params = payload.get("params") or {}
    arguments = params.get("arguments") or {}
    # A resource hint is useful context for a reviewer and is treated as
    # exactly that - a hint. Nothing in the risk assessment reads it.
    resource = ""
    for key in ("resource", "uri", "path", "table", "target"):
        value = arguments.get(key)
        if isinstance(value, str) and value:
            resource = value
            break

    return ToolCall(
        agent_id=agent_id,
        tool=str(params.get("name") or "unknown"),
        arguments=arguments,
        resource=resource,
        intent=str(payload.get("method") or "tools/call"),
        timestamp=timestamp,
        authenticated=authenticated,
        credential_valid=credential_valid,
        on_behalf_of=tuple(on_behalf_of),
    )
