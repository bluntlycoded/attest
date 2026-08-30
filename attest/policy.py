"""Stage 3 - the trigger policy.

A two-threshold hysteresis rule with a cooldown, evaluated against a verification
budget. Three parameters, one comparison, no learned component: an operator can
read the trust value, the two thresholds and the cooldown and know exactly why a
given verification fired.

The hysteresis gap exists to stop the policy chattering - firing repeatedly
around a single boundary value. Once a verification fires the trigger disarms,
and it only re-arms after trust climbs back above ``theta_high``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = ["Action", "PolicyParams", "PolicyState", "Budget", "decide"]


class Action(str, Enum):
    """What the policy decided to do at a step."""

    OBSERVE = "observe"
    VERIFY = "verify"


class Reason(str, Enum):
    """Why the policy reached its decision. Recorded for audit."""

    TRUSTED = "trusted"
    DISARMED = "disarmed"
    COOLDOWN = "cooldown"
    BUDGET_EXHAUSTED = "budget_exhausted"
    BELOW_THRESHOLD = "below_threshold"


@dataclass(frozen=True)
class PolicyParams:
    """Frozen trigger-policy parameters.

    Args:
        theta_low: Trust level below which a verification fires.
        theta_high: Trust level above which a spent trigger re-arms. Must be at
            least ``theta_low``; the gap between them is the hysteresis band.
        cooldown_seconds: Minimum wall-clock gap between two verifications of
            the same agent.
    """

    theta_low: float = 0.5
    theta_high: float = 0.65
    cooldown_seconds: float = 8.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.theta_low <= 1.0:
            raise ValueError(f"theta_low must lie in [0, 1], got {self.theta_low}")
        if not 0.0 <= self.theta_high <= 1.0:
            raise ValueError(f"theta_high must lie in [0, 1], got {self.theta_high}")
        if self.theta_high < self.theta_low:
            raise ValueError(
                f"theta_high ({self.theta_high}) must be >= theta_low "
                f"({self.theta_low})"
            )
        if self.cooldown_seconds < 0.0:
            raise ValueError(
                f"cooldown_seconds must be non-negative, got {self.cooldown_seconds}"
            )


@dataclass(frozen=True)
class PolicyState:
    """Per-agent trigger state.

    Attributes:
        armed: Whether the trigger is eligible to fire. Set False after a
            verification, True again once trust exceeds ``theta_high``.
        cooldown_until: Unix timestamp before which no verification may fire.
    """

    armed: bool = True
    cooldown_until: float = 0.0


class Budget:
    """A token bucket capping how many verifications may be spent.

    The budget is the point of the whole system: verification costs something -
    a re-attestation handshake, a rotated credential, an interrupted human - so
    a monitor cannot verify everything all the time and has to pick its moments.
    Making the cap explicit means the exposure numbers the engine reports are
    always attached to a stated spend.

    Args:
        capacity: Maximum number of verifications available in a burst.
        refill_per_second: Rate at which spent budget is replenished.
    """

    def __init__(self, capacity: float, refill_per_second: float) -> None:
        if capacity <= 0.0:
            raise ValueError(f"capacity must be positive, got {capacity}")
        if refill_per_second < 0.0:
            raise ValueError(
                f"refill_per_second must be non-negative, got {refill_per_second}"
            )
        self.capacity = float(capacity)
        self.refill_per_second = float(refill_per_second)
        self._tokens = float(capacity)
        self._updated_at: float | None = None

    @classmethod
    def per_thousand_steps(
        cls,
        rate: float,
        step_seconds: float,
        *,
        capacity: float | None = None,
    ) -> "Budget":
        """Build a budget from a verifications-per-1000-steps figure.

        This is the unit the evaluation reports in, so configuring in the same
        unit avoids a conversion every time an operating point is chosen.

        Args:
            rate: Verifications permitted per 1000 steps.
            step_seconds: Wall-clock duration of one step.
            capacity: Burst size. Defaults to ``rate``, i.e. one 1000-step
                window's worth.
        """
        if step_seconds <= 0.0:
            raise ValueError(f"step_seconds must be positive, got {step_seconds}")
        window_seconds = 1000.0 * step_seconds
        return cls(
            capacity=rate if capacity is None else capacity,
            refill_per_second=rate / window_seconds,
        )

    @classmethod
    def unlimited(cls) -> "Budget":
        """A budget that never denies. Useful for measuring an unconstrained policy."""
        return cls(capacity=float("inf"), refill_per_second=float("inf"))

    @property
    def tokens(self) -> float:
        """Budget currently available, as of the last call to ``available``."""
        return self._tokens

    def _refill(self, now: float) -> None:
        if self._updated_at is None:
            self._updated_at = now
            return
        dt = now - self._updated_at
        if dt <= 0.0:
            return
        self._tokens = min(self.capacity, self._tokens + dt * self.refill_per_second)
        self._updated_at = now

    def available(self, now: float) -> bool:
        """Whether at least one verification can be afforded at ``now``."""
        self._refill(now)
        return self._tokens >= 1.0

    def spend(self, now: float) -> bool:
        """Consume one verification. Returns False if none was available."""
        if not self.available(now):
            return False
        self._tokens -= 1.0
        return True


def decide(
    state: PolicyState,
    trust: float,
    now: float,
    params: PolicyParams,
    *,
    budget: Budget | None = None,
) -> tuple[Action, PolicyState, Reason]:
    """Choose between observing and verifying.

    Args:
        state: Current per-agent trigger state.
        trust: Bounded trust score in [0, 1].
        now: Unix timestamp of the decision.
        params: Frozen policy parameters.
        budget: Optional verification budget. When supplied and exhausted, the
            policy observes even though it would otherwise have fired, and the
            returned reason records that.

    Returns:
        The action, the successor policy state, and the reason for the decision.
        Budget is *not* spent here - the caller commits it - so that a decision
        can be evaluated in shadow mode without consuming real budget.
    """
    if trust >= params.theta_low:
        # Re-arm on the way up, but only once clear of the hysteresis band.
        armed = state.armed or trust > params.theta_high
        return (
            Action.OBSERVE,
            PolicyState(armed=armed, cooldown_until=state.cooldown_until),
            Reason.TRUSTED,
        )

    if not state.armed:
        return Action.OBSERVE, state, Reason.DISARMED

    if now < state.cooldown_until:
        return Action.OBSERVE, state, Reason.COOLDOWN

    if budget is not None and not budget.available(now):
        return Action.OBSERVE, state, Reason.BUDGET_EXHAUSTED

    return (
        Action.VERIFY,
        PolicyState(armed=False, cooldown_until=now + params.cooldown_seconds),
        Reason.BELOW_THRESHOLD,
    )
