"""Does the self-tuning loop converge, and what happens when nobody is reading?

Feeding a verification outcome back into the score that triggered it is a
closed loop, and closed loops on a control signal can run away. Two failure
modes matter more than any competitive risk:

Runaway latitude
    Every approval loosens an agent's threshold. An agent approved often
    enough could drift to a threshold that never fires, stop being checked,
    and therefore stop generating the approvals that would ever move it back.
    A compromise after that point runs unopposed. ``threshold_bound`` exists to
    cap this, and the point of this module is to check that it does.

Hollow approval
    If reviewers stop reading and approve everything, the loop is being fed
    noise while behaving as though it were signal - and it will widen latitude
    for compromised agents specifically, because those are the ones generating
    the requests. This is the case where a self-tuning system is actively worse
    than a static threshold, and the only defence is noticing.

Three reviewers are simulated: one who reads, one who clicks through, and one
who never answers. If the loop only behaves against the first, it is not ready.
"""

from __future__ import annotations

import random
import statistics
from dataclasses import dataclass, field

from .approval import ApprovalPolicy, Outcome
from .engine import AttestEngine, Verification
from .evidence import Envelope
from .policy import Action, PolicyParams
from .trust import TrustParams

__all__ = ["LoopScenario", "LoopOutcome", "run_loop", "compare_reviewers"]

_BENIGN = ("tool-search", "tool-docs", "tool-calendar")
_HOSTILE = ("tool-exfil", "host-external", "tool-shell")


@dataclass(frozen=True)
class LoopScenario:
    """Fleet and compromise settings for a feedback-loop run."""

    agents: int = 12
    steps: int = 4000
    attack_hazard: float = 0.0015
    episode_mean: float = 60.0
    guard_steps: int = 40
    detector_quality: float = 9.0
    step_seconds: float = 1.0


@dataclass
class LoopOutcome:
    """What the loop did over the run.

    Attributes:
        offsets: Final per-agent threshold drift. Negative means the agent
            earned latitude.
        offset_reversals: How many times an agent's drift changed direction.
            High counts mean oscillation rather than convergence.
        exposure: Fraction of compromised steps that ran uncontained.
        hollow_flagged: Whether rubber-stamp detection fired.
    """

    reviewer: str
    verifications: int
    approvals: int
    rejections: int
    timeouts: int
    episodes: int
    contained: int
    exposure: float
    offsets: dict[str, float] = field(default_factory=dict)
    offset_reversals: int = 0
    hollow_flagged: bool = False

    @property
    def mean_offset(self) -> float:
        return (
            statistics.mean(self.offsets.values()) if self.offsets else 0.0
        )

    @property
    def min_offset(self) -> float:
        return min(self.offsets.values()) if self.offsets else 0.0

    def summary(self) -> str:
        return (
            f"{self.reviewer:<14} {self.verifications:>5} checks | "
            f"{self.approvals:>4} ok / {self.rejections:>3} no / "
            f"{self.timeouts:>3} to | "
            f"contained {self.contained}/{self.episodes} | "
            f"exposure {self.exposure:.3f} | "
            f"offset mean {self.mean_offset:+.3f} min {self.min_offset:+.3f} | "
            f"reversals {self.offset_reversals} | "
            f"hollow {'YES' if self.hollow_flagged else 'no'}"
        )


@dataclass
class _Agent:
    agent_id: str
    remaining: int = 0
    guard: int = 0
    exposed: int = 0
    intended: int = 0

    @property
    def compromised(self) -> bool:
        return self.remaining > 0


def _reviewer(kind: str, rng: random.Random, truth: set[str]):
    """Build a reviewer of the requested character."""

    def attentive(agent_id, decision):
        # Reads the request, answers correctly, and takes a variable amount of
        # time depending on how hard the call was.
        compromised = agent_id in truth
        return Verification(
            agent_id=agent_id,
            timestamp=decision.timestamp,
            compromised=compromised,
            outcome=Outcome.REJECTED if compromised else Outcome.APPROVED,
            approver="attentive",
            latency_seconds=rng.uniform(20.0, 240.0),
        )

    def rubber_stamp(agent_id, decision):
        # Approves everything, fast, and in almost exactly the same time each
        # time - the signature the detector is looking for.
        return Verification(
            agent_id=agent_id,
            timestamp=decision.timestamp,
            compromised=False,
            outcome=Outcome.APPROVED,
            approver="rubber-stamp",
            latency_seconds=rng.uniform(1.0, 2.0),
        )

    def absent(agent_id, decision):
        return Verification(
            agent_id=agent_id,
            timestamp=decision.timestamp,
            compromised=False,
            outcome=Outcome.TIMEOUT,
            approver="absent",
            latency_seconds=3600.0,
        )

    return {"attentive": attentive, "rubber-stamp": rubber_stamp, "absent": absent}[
        kind
    ]


def run_loop(
    reviewer: str = "attentive",
    scenario: LoopScenario | None = None,
    *,
    policy: ApprovalPolicy | None = None,
    seed: int = 0,
) -> LoopOutcome:
    """Run the fleet with one kind of reviewer answering every request."""
    cfg = scenario or LoopScenario()
    rng = random.Random(seed)
    truth: set[str] = set()

    # Wrap the reviewer so the loop reads what was actually decided rather
    # than re-deriving it, which is how the first version of this miscounted
    # every timeout as an approval.
    answered: list[Verification] = []
    inner = _reviewer(reviewer, rng, truth)

    def recording(agent_id, decision):
        result = inner(agent_id, decision)
        answered.append(result)
        return result

    engine = AttestEngine(
        trust_params=TrustParams.from_event_interval(cfg.step_seconds),
        policy_params=PolicyParams(cooldown_seconds=8 * cfg.step_seconds),
        verifier=recording,
        shadow=False,
        approval=policy or ApprovalPolicy(),
    )

    fleet = [_Agent(f"agent-{i:02d}") for i in range(cfg.agents)]
    visibility = cfg.detector_quality / (cfg.detector_quality + 1.0)

    verifications = approvals = rejections = timeouts = 0
    episodes = contained = 0
    exposed = intended = 0
    # Sampled periodically so oscillation shows up as direction changes rather
    # than only as a final value.
    history: dict[str, list[float]] = {a.agent_id: [] for a in fleet}

    for step in range(cfg.steps):
        now = step * cfg.step_seconds

        for agent in fleet:
            if agent.remaining > 0:
                agent.remaining -= 1
                if agent.remaining == 0:
                    agent.guard = cfg.guard_steps
                    truth.discard(agent.agent_id)
            elif agent.guard > 0:
                agent.guard -= 1
            elif rng.random() < cfg.attack_hazard:
                length = max(5, int(rng.expovariate(1.0 / cfg.episode_mean)))
                agent.remaining = length
                truth.add(agent.agent_id)
                episodes += 1
                intended += length

            if agent.compromised:
                exposed += 1

            hostile = agent.compromised and rng.random() < visibility
            decision = engine.observe(
                Envelope(
                    sender=agent.agent_id,
                    recipient=rng.choice(_HOSTILE if hostile else _BENIGN),
                    intent="core",
                    action="bulk_export" if hostile else "query",
                    timestamp=now,
                    signature_valid=not hostile,
                    credential_valid=not hostile,
                    audit_proof=None if hostile else f"merkle:{step}",
                )
            )

            if decision.action is Action.VERIFY:
                verifications += 1
                outcome = answered[-1].resolved() if answered else Outcome.UNKNOWN
                if outcome is Outcome.REJECTED:
                    rejections += 1
                    # A rejection is the only outcome that ends an episode.
                    # An approval - correct or not - lets the agent carry on.
                    if agent.compromised:
                        contained += 1
                        agent.remaining = 0
                        agent.guard = cfg.guard_steps
                        truth.discard(agent.agent_id)
                elif outcome is Outcome.APPROVED:
                    approvals += 1
                else:
                    timeouts += 1

        if step % 100 == 0:
            for agent in fleet:
                history[agent.agent_id].append(
                    engine.thresholds.offset(agent.agent_id)
                )

    reversals = 0
    for series in history.values():
        deltas = [b - a for a, b in zip(series, series[1:]) if b != a]
        reversals += sum(
            1 for a, b in zip(deltas, deltas[1:]) if (a > 0) != (b > 0)
        )

    return LoopOutcome(
        reviewer=reviewer,
        verifications=verifications,
        approvals=approvals,
        rejections=rejections,
        timeouts=timeouts,
        episodes=episodes,
        contained=contained,
        exposure=exposed / intended if intended else 0.0,
        offsets={
            a.agent_id: engine.thresholds.offset(a.agent_id) for a in fleet
        },
        offset_reversals=reversals,
        hollow_flagged=bool(engine.rubber_stamp.hollow_approvers()),
    )


def compare_reviewers(
    scenario: LoopScenario | None = None, *, seed: int = 0
) -> dict[str, LoopOutcome]:
    """Run the same fleet past all three kinds of reviewer."""
    return {
        kind: run_loop(kind, scenario, seed=seed)
        for kind in ("attentive", "rubber-stamp", "absent")
    }
