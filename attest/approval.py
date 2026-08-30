"""Closing the loop on what a verification actually found.

The scheduler decides when to interrupt someone. That is only half a system:
the answer that comes back is evidence too, and discarding it means an agent a
human has just vouched for is treated exactly like one a human has just
rejected. Both reset to the neutral prior, both get interrupted again on the
same schedule, and the person doing the approving learns that their answer
changed nothing.

Three pieces here.

Outcomes carry different weight
    Approval is good evidence and leaves the agent above the prior. Rejection
    is strong bad evidence. A timeout is *not* an approval - treating silence
    as consent is the failure that turns a governance control into decoration,
    so it has to be opted into explicitly.

Thresholds adapt per agent
    An agent that keeps being approved should be interrupted less often, which
    is the documented fix for approval fatigue: expand the auto-approve
    boundary rather than holding a static threshold and hoping people keep
    reading. Adaptation is bounded, and the bound matters - see
    :class:`ApprovalPolicy`.

Rubber-stamping is measured, not assumed
    A gate that has gone hollow looks identical to a healthy one from the
    outside: approvals still arrive, the audit log still fills. The tell is in
    the timing. An approver reading each request produces latencies that vary
    with how hard the decision was; one clicking through produces latencies
    that are short and all alike. :class:`RubberStampDetector` reports that,
    because a control nobody reads is worse than no control - it is false
    assurance that something is being watched.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "Outcome",
    "ApprovalPolicy",
    "ApprovalRecord",
    "AdaptiveThresholds",
    "ApproverStats",
    "RubberStampDetector",
]


class Outcome(str, Enum):
    """What came back from a verification."""

    APPROVED = "approved"
    """A human looked and said the agent was behaving legitimately."""

    REJECTED = "rejected"
    """A human looked and said it was not, or an attestation failed outright."""

    TIMEOUT = "timeout"
    """Nobody answered. Carries no information about the agent."""

    FAILED = "failed"
    """The check could not be performed - an infrastructure problem, not
    evidence about the agent."""

    UNKNOWN = "unknown"
    """No outcome was reported. Treated exactly like FAILED."""

    @property
    def informative(self) -> bool:
        """Whether this outcome says anything about the agent itself."""
        return self in (Outcome.APPROVED, Outcome.REJECTED)


@dataclass(frozen=True)
class ApprovalPolicy:
    """How a verification outcome feeds back.

    Args:
        approval_vouch: Good evidence credited on approval, in units of clean
            observations. Zero disables positive feedback entirely.
        rejection_penalty: Probability mass charged on rejection, before the
            misbehaviour weight is applied.
        timeout_is_approval: Whether an unanswered request counts as consent.
            Defaults to False and should stay there. Silence means a person was
            busy, and a system that reads that as approval will approve
            everything precisely when its reviewers are most overloaded.
        threshold_step: How far the per-agent verify threshold moves per
            informative outcome.
        offset_half_life: Seconds over which earned drift decays back toward
            the configured threshold.

            Without this the loop is a one-way ratchet. In a well-tuned system
            verifications land almost exclusively on agents that really are
            misbehaving, so nearly every outcome is a rejection and every
            agent tightens monotonically until it hits the bound - an agent
            compromised once is then treated as suspicious forever. That
            contradicts the recurrence it sits on top of, which forgives
            slowly but does forgive. Decay restores that: judgements fade, so
            the drift reflects recent reviewer opinion rather than an agent's
            entire history.
        threshold_bound: Maximum distance the threshold may drift from its
            configured value, in either direction.

            This bound is the safety property of the whole mechanism. Without
            it, an agent approved often enough drifts to a threshold that never
            fires, stops being checked, and therefore stops accumulating the
            approvals that would ever move it back - a compromise after that
            point runs unopposed. The bound caps how much trust the loop is
            allowed to extend on its own.
    """

    approval_vouch: float = 3.0
    rejection_penalty: float = 1.0
    timeout_is_approval: bool = False
    threshold_step: float = 0.02
    threshold_bound: float = 0.15
    offset_half_life: float = 7 * 86400.0

    def __post_init__(self) -> None:
        if self.approval_vouch < 0.0:
            raise ValueError("approval_vouch must be non-negative")
        if not 0.0 <= self.rejection_penalty <= 1.0:
            raise ValueError("rejection_penalty must lie in [0, 1]")
        if self.threshold_step < 0.0:
            raise ValueError("threshold_step must be non-negative")
        if not 0.0 <= self.threshold_bound <= 0.5:
            raise ValueError("threshold_bound must lie in [0, 0.5]")
        if self.offset_half_life <= 0.0:
            raise ValueError("offset_half_life must be positive")


@dataclass(frozen=True)
class ApprovalRecord:
    """One approval decision, as made by a person.

    Attributes:
        agent_id: Agent the request was about.
        approver: Who answered. The unit rubber-stamping is measured over.
        outcome: What they decided.
        requested_at: When the request was raised.
        latency_seconds: How long they took. The signal that matters - a
            reviewer who is reading produces latencies that vary with the
            difficulty of the decision.
    """

    agent_id: str
    approver: str
    outcome: Outcome
    requested_at: float
    latency_seconds: float

    @property
    def approved(self) -> bool:
        return self.outcome is Outcome.APPROVED


class AdaptiveThresholds:
    """Per-agent drift on the verify threshold, bounded in both directions.

    Adaptation is deliberately slow relative to the trust dynamics: it moves
    only on verifications, which the scheduler already makes rare. A loop that
    updated on every message would chase the trust score rather than the
    reviewers' judgement of it.
    """

    def __init__(self, policy: ApprovalPolicy | None = None) -> None:
        self.policy = policy or ApprovalPolicy()
        self._offsets: dict[str, float] = {}
        self._updated: dict[str, float] = {}

    def offset(self, agent_id: str, now: float | None = None) -> float:
        """Current drift for ``agent_id``. Negative means interrupt less.

        Args:
            now: When given, decays the drift for elapsed time first, so a
                judgement made months ago no longer governs today.
        """
        value = self._offsets.get(agent_id, 0.0)
        if now is None or value == 0.0:
            return value
        last = self._updated.get(agent_id)
        if last is None or now <= last:
            return value
        return value * 0.5 ** ((now - last) / self.policy.offset_half_life)

    def theta_low_for(
        self, agent_id: str, base: float, now: float | None = None
    ) -> float:
        """The verify threshold this agent has earned."""
        return min(1.0, max(0.0, base + self.offset(agent_id, now)))

    def record(self, agent_id: str, outcome: Outcome, now: float | None = None) -> float:
        """Apply one outcome and return the new offset.

        Approval lowers the threshold, so the agent is interrupted less.
        Rejection raises it. Anything uninformative leaves it alone - a
        timeout must not quietly widen an agent's latitude.
        """
        policy = self.policy
        if outcome is Outcome.APPROVED or (
            outcome is Outcome.TIMEOUT and policy.timeout_is_approval
        ):
            delta = -policy.threshold_step
        elif outcome is Outcome.REJECTED:
            delta = policy.threshold_step
        else:
            return self.offset(agent_id, now)

        bound = policy.threshold_bound
        updated = min(bound, max(-bound, self.offset(agent_id, now) + delta))
        self._offsets[agent_id] = updated
        if now is not None:
            self._updated[agent_id] = now
        return updated

    def reset(self, agent_id: str) -> None:
        """Forget an agent's earned latitude, e.g. after re-enrolment."""
        self._offsets.pop(agent_id, None)
        self._updated.pop(agent_id, None)

    def __len__(self) -> int:
        return len(self._offsets)


@dataclass(frozen=True)
class ApproverStats:
    """Whether one approver still appears to be reading.

    Attributes:
        hollow: True when the pattern matches rubber-stamping. Never proof -
            an approver on a genuinely healthy fleet legitimately approves
            almost everything - which is why latency spread is weighted
            alongside approval rate rather than either alone.
    """

    approver: str
    decisions: int
    approval_rate: float
    median_latency: float
    latency_cv: float
    hollow_score: float
    hollow: bool

    def summary(self) -> str:
        verdict = "LOOKS HOLLOW" if self.hollow else "reading"
        return (
            f"{self.approver}: {self.decisions} decisions | "
            f"approved {self.approval_rate:.1%} | "
            f"median {self.median_latency:.1f}s | "
            f"spread {self.latency_cv:.2f} | {verdict}"
        )


@dataclass
class RubberStampDetector:
    """Reports whether human oversight has decayed into reflex.

    Three signals, and all three have to point the same way. Approval rate
    alone convicts anyone with a healthy fleet; speed alone convicts anyone
    experienced. What no attentive reviewer produces is *all three at once* -
    approving nearly everything, quickly, and taking almost exactly the same
    time regardless of what was asked.

    Args:
        min_decisions: Below this, no verdict is offered. Three fast approvals
            are not evidence of anything.
        fast_seconds: Median latency at or below which review is implausible.
        uniform_cv: Coefficient of variation at or below which latencies are
            suspiciously alike. Real decisions vary in difficulty.
        high_rate: Approval rate at or above which the gate is rejecting
            almost nothing.
    """

    min_decisions: int = 20
    fast_seconds: float = 5.0
    uniform_cv: float = 0.25
    high_rate: float = 0.98
    _records: list[ApprovalRecord] = field(default_factory=list, init=False)

    def record(self, record: ApprovalRecord) -> None:
        """Log one approval decision."""
        self._records.append(record)

    def extend(self, records) -> None:
        self._records.extend(records)

    def stats(self) -> list[ApproverStats]:
        """Per-approver assessment, most suspicious first."""
        by_approver: dict[str, list[ApprovalRecord]] = {}
        for record in self._records:
            by_approver.setdefault(record.approver, []).append(record)

        out = [
            self._assess(approver, records)
            for approver, records in by_approver.items()
        ]
        return sorted(out, key=lambda s: -s.hollow_score)

    def _assess(self, approver: str, records: list[ApprovalRecord]) -> ApproverStats:
        latencies = [max(0.0, r.latency_seconds) for r in records]
        rate = sum(r.approved for r in records) / len(records)
        median = statistics.median(latencies)
        mean = sum(latencies) / len(latencies)
        # Coefficient of variation: spread relative to size, so a reviewer who
        # is simply quick is not confused with one who is not looking.
        cv = (statistics.pstdev(latencies) / mean) if mean > 0 else 0.0

        enough = len(records) >= self.min_decisions
        fast = median <= self.fast_seconds
        uniform = cv <= self.uniform_cv
        permissive = rate >= self.high_rate

        score = 0.0 if not enough else (fast + uniform + permissive) / 3.0
        return ApproverStats(
            approver=approver,
            decisions=len(records),
            approval_rate=rate,
            median_latency=median,
            latency_cv=cv,
            hollow_score=score,
            hollow=enough and fast and uniform and permissive,
        )

    def hollow_approvers(self) -> list[ApproverStats]:
        """Only those whose gate appears to have stopped functioning."""
        return [s for s in self.stats() if s.hollow]

    def __len__(self) -> int:
        return len(self._records)
