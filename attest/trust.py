"""Stage 2 - the trust calculus.

An exponentially-forgetting Beta-reputation update. Its entire state is two
running counters, and nothing about it is learned. Given a stream of calibrated
compromise probabilities it produces a bounded trust score that falls quickly
under bad evidence and recovers slowly once behaviour looks clean again.

The recurrence is::

    r <- decay * r + (1 - p)
    s <- decay * s + w * p
    tau = (r + 1) / (r + s + 2)

where ``decay = gamma ** (dt / step_seconds)``.

The original formulation applies ``gamma`` once per discrete step, which is
sound when steps arrive at a fixed rate. Agent traffic does not: an agent may
emit fifty envelopes in a second and then nothing for an hour. Raising gamma to
``dt / step_seconds`` makes forgetting a function of elapsed time instead, so
the same parameters mean the same thing regardless of arrival rate.

One consequence is worth stating because it is the property that makes this
suitable for a zero-trust setting. With no evidence at all both counters decay
toward zero, so ``tau`` returns to ``1/2`` - the neutral prior. An idle agent
drifts back to neither-trusted-nor-distrusted rather than remaining trusted on
the strength of a verification that happened hours ago.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

__all__ = [
    "TrustParams",
    "TrustState",
    "STEPS_TO_DECAY",
    "STEPS_TO_RECOVER",
]

# Empirical step counts for the reference parameters (gamma=0.94, w=2), measured
# on the sustained-attack and sustained-benign limits. Used to convert a stated
# recovery requirement into a step interval.
STEPS_TO_DECAY = 6
STEPS_TO_RECOVER = 33


@dataclass(frozen=True)
class TrustParams:
    """Frozen parameters of the trust recurrence.

    Args:
        gamma: Forgetting factor applied per ``step_seconds`` of elapsed time.
            Controls how much history the score retains.
        w: Misbehaviour weight. Values above 1 make bad evidence count for more
            than good evidence, which is what produces the burn-fast /
            forgive-slow asymmetry.
        step_seconds: Wall-clock duration that one unit of ``gamma`` decay
            corresponds to.
    """

    gamma: float = 0.94
    w: float = 2.0
    step_seconds: float = 1.0

    def __post_init__(self) -> None:
        if not 0.0 < self.gamma < 1.0:
            raise ValueError(f"gamma must lie in (0, 1), got {self.gamma}")
        if self.w <= 0.0:
            raise ValueError(f"w must be positive, got {self.w}")
        if self.step_seconds <= 0.0:
            raise ValueError(f"step_seconds must be positive, got {self.step_seconds}")

    @classmethod
    def from_event_interval(
        cls,
        seconds: float,
        *,
        gamma: float = 0.94,
        w: float = 2.0,
    ) -> "TrustParams":
        """Build parameters from an agent's typical gap between messages.

        ``step_seconds`` has to track the rate an agent actually emits at, and
        getting this wrong is the most common way to make the trust layer look
        broken. Steady-state evidence accumulates to roughly
        ``1 / (1 - gamma ** (interval / step_seconds))``: set ``step_seconds``
        far above the real interval and that figure explodes, so a compromise
        episode can never accumulate enough bad evidence to overcome the good
        evidence already banked, and the trigger never fires.

        As a rule, ``step_seconds`` should be about one inter-arrival gap.

        Args:
            seconds: Typical gap between consecutive messages from one agent.
        """
        if seconds <= 0.0:
            raise ValueError(f"seconds must be positive, got {seconds}")
        return cls(gamma=gamma, w=w, step_seconds=seconds)

    @classmethod
    def from_recovery_time(
        cls,
        recovery_seconds: float,
        *,
        gamma: float = 0.94,
        w: float = 2.0,
    ) -> "TrustParams":
        """Build parameters from a stated recovery requirement.

        This is the intended way to configure the engine: an operator says how
        long a misbehaving agent should take to earn full trust back, rather
        than picking a decay constant off a validation curve.

        Args:
            recovery_seconds: Time a fully-distrusted agent under clean traffic
                should take to return to a trusted score.
        """
        if recovery_seconds <= 0.0:
            raise ValueError(
                f"recovery_seconds must be positive, got {recovery_seconds}"
            )
        return cls(
            gamma=gamma,
            w=w,
            step_seconds=recovery_seconds / STEPS_TO_RECOVER,
        )

    @property
    def decay_seconds(self) -> float:
        """Approximate time for trust to collapse under sustained bad evidence."""
        return self.step_seconds * STEPS_TO_DECAY

    @property
    def recovery_seconds(self) -> float:
        """Approximate time for trust to recover under sustained clean evidence."""
        return self.step_seconds * STEPS_TO_RECOVER

    @property
    def half_life_seconds(self) -> float:
        """Time over which accumulated evidence loses half its weight."""
        return self.step_seconds * math.log(0.5) / math.log(self.gamma)


@dataclass(frozen=True)
class TrustState:
    """Accumulated evidence for a single agent.

    Attributes:
        r: Discounted count of good evidence.
        s: Discounted count of bad evidence, weighted by ``w``.
        updated_at: Unix timestamp of the last update, or None if never updated.
    """

    r: float = 0.0
    s: float = 0.0
    updated_at: float | None = None

    @property
    def score(self) -> float:
        """Bounded trust in [0, 1]. Returns the 0.5 prior with no evidence."""
        return (self.r + 1.0) / (self.r + self.s + 2.0)

    def _decay_factor(self, at: float, params: TrustParams) -> float:
        if self.updated_at is None:
            return 1.0
        dt = at - self.updated_at
        if dt < 0.0:
            raise ValueError(
                f"timestamp {at} precedes last update {self.updated_at}; "
                "evidence must be supplied in order"
            )
        if dt == 0.0:
            return 1.0
        return params.gamma ** (dt / params.step_seconds)

    def observe(self, p: float, at: float, params: TrustParams) -> "TrustState":
        """Fold one calibrated compromise probability into the trust score.

        Args:
            p: Probability in [0, 1] that the agent is currently compromised.
                Must be calibrated, not merely monotonic - the recurrence
                treats it as an expected count of bad evidence.
            at: Unix timestamp of the observation. Must not precede the last
                update.
            params: Frozen trust parameters.

        Returns:
            The updated state. The receiver is left unchanged.
        """
        if not 0.0 <= p <= 1.0:
            raise ValueError(f"p must lie in [0, 1], got {p}")
        decay = self._decay_factor(at, params)
        return TrustState(
            r=decay * self.r + (1.0 - p),
            s=decay * self.s + params.w * p,
            updated_at=at,
        )

    def penalize(self, p: float, at: float, params: TrustParams) -> "TrustState":
        """Fold in bad evidence only, without crediting the good half.

        :meth:`observe` adds ``1 - p`` to the good counter as well as ``w * p``
        to the bad one, which is right for evidence about the agent itself. It
        is wrong for evidence delegated upward: a principal charged for a
        delegate's misbehaviour would also be *credited* for the delegate's
        good conduct on the same call, which is exactly the laundering route
        upward propagation exists to close.

        Args:
            p: Probability mass to charge, already scaled by any propagation
                weight.
            at: Unix timestamp of the observation.
        """
        if not 0.0 <= p <= 1.0:
            raise ValueError(f"p must lie in [0, 1], got {p}")
        decay = self._decay_factor(at, params)
        return TrustState(
            r=decay * self.r,
            s=decay * self.s + params.w * p,
            updated_at=at,
        )

    def vouch(self, weight: float, at: float, params: TrustParams) -> "TrustState":
        """Fold in good evidence only, the mirror of :meth:`penalize`.

        A human approving an action is not the same kind of evidence as another
        quiet message. It is a person having looked and said this was fine, and
        it should leave the agent better off than a neutral prior rather than
        merely un-penalised.

        Args:
            weight: Good evidence to add, in units of clean observations. Three
                is roughly "as reassuring as three uneventful messages".
            at: Unix timestamp of the approval.
        """
        if weight < 0.0:
            raise ValueError(f"weight must be non-negative, got {weight}")
        decay = self._decay_factor(at, params)
        return TrustState(
            r=decay * self.r + weight,
            s=decay * self.s,
            updated_at=at,
        )

    def decayed(self, at: float, params: TrustParams) -> "TrustState":
        """Apply forgetting without folding in new evidence.

        Used to age an idle agent's score. With no traffic this drives both
        counters toward zero and the score back toward the 0.5 prior.
        """
        decay = self._decay_factor(at, params)
        return TrustState(r=decay * self.r, s=decay * self.s, updated_at=at)

    def reset(self, at: float) -> "TrustState":
        """Return to the neutral prior.

        Called after a verification resolves. Both a clean result and a
        remediation restart the relationship from scratch, so trust returns to
        the prior rather than to either extreme.
        """
        return TrustState(r=0.0, s=0.0, updated_at=at)
