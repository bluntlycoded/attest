"""The four operational metrics.

Discrimination scores say whether a classifier can tell attack traffic from
benign traffic. They do not say how long an attacker stayed unchallenged, or
what the challenges cost. Two detectors with identical AUC can leave very
different amounts of attacker dwell time on the table once both are held to the
same number of permitted verifications per hour - and that number is almost
never reported.

These are the numbers a scheduler has to be judged on:

exposure
    Fraction of attack steps during which the agent was not yet contained.
    Lower is better.
onset delay
    Steps between an episode starting and the verification that ends it.
containment
    Fraction of episodes ended by a verification at all.
budget
    Verifications spent per 1000 steps. The ongoing cost of the policy.
false verifications
    Verifications spent per 1000 benign steps. Pure cost, no security benefit:
    a challenge sent to an agent that was behaving perfectly well.

Confidence intervals come from a session-grouped bootstrap. Steps within a
session are not independent of one another, so resampling individual steps
would produce intervals several times too narrow.
"""

from __future__ import annotations

import random
import statistics
from dataclasses import dataclass, field

__all__ = ["StepRecord", "Metrics", "evaluate", "bootstrap_ci"]


@dataclass(frozen=True)
class StepRecord:
    """One evaluated step of one session.

    Attributes:
        session: Session identifier. The unit the bootstrap resamples.
        is_attack: Ground truth - whether the agent was compromised at this step.
        episode: Identifier of the attack episode this step belongs to, or None
            for benign steps.
        verified: Whether a verification fired at this step.
        group: Optional label - attack family, tenant, agent class - for a
            per-group breakdown.
    """

    session: str
    is_attack: bool
    episode: str | None = None
    verified: bool = False
    group: str | None = None


@dataclass(frozen=True)
class Metrics:
    """Evaluated policy performance over a set of sessions."""

    steps: int
    attack_steps: int
    benign_steps: int
    episodes: int
    verifications: int
    exposure: float
    containment: float
    median_onset_delay: float | None
    budget_per_1k_steps: float
    false_verifications_per_1k_benign: float
    by_group: dict[str, "Metrics"] = field(default_factory=dict)

    def summary(self) -> str:
        """One-line human-readable form."""
        delay = "n/a" if self.median_onset_delay is None else f"{self.median_onset_delay:.1f}"
        return (
            f"exposure {self.exposure:.3f} | "
            f"contained {self.containment:.3f} | "
            f"delay {delay} | "
            f"budget {self.budget_per_1k_steps:.2f}/1k | "
            f"false {self.false_verifications_per_1k_benign:.3f}/1k benign"
        )


@dataclass
class _Tally:
    """Additive counts over a set of steps.

    Every metric except the median delay is a ratio of sums, so tallies from
    disjoint session sets can be added rather than recomputed. That is what lets
    the bootstrap resample sessions in O(sessions) instead of O(steps).
    """

    attack_steps: int = 0
    benign_steps: int = 0
    exposed_steps: int = 0
    verifications: int = 0
    false_verifications: int = 0
    episodes: int = 0
    contained: int = 0
    delays: list[int] = field(default_factory=list)

    def __add__(self, other: "_Tally") -> "_Tally":
        return _Tally(
            attack_steps=self.attack_steps + other.attack_steps,
            benign_steps=self.benign_steps + other.benign_steps,
            exposed_steps=self.exposed_steps + other.exposed_steps,
            verifications=self.verifications + other.verifications,
            false_verifications=self.false_verifications + other.false_verifications,
            episodes=self.episodes + other.episodes,
            contained=self.contained + other.contained,
            delays=self.delays + other.delays,
        )


def _tally(records: list[StepRecord]) -> _Tally:
    """Single pass over ``records``, accumulating everything the metrics need."""
    t = _Tally()

    # Episodes are keyed by (session, episode) so that two sessions reusing the
    # same episode label are never merged into one.
    contained: dict[tuple[str, str], bool] = {}
    since_onset: dict[tuple[str, str], int] = {}

    for rec in records:
        if rec.is_attack:
            t.attack_steps += 1
            if rec.episode is None:
                raise ValueError(
                    f"attack step in session {rec.session!r} has no episode id"
                )
            key = (rec.session, rec.episode)
            if key not in contained:
                contained[key] = False
                since_onset[key] = 0
                t.episodes += 1
            # Exposure is counted before containment is applied: the attacker
            # did act on the step that finally triggered the verification.
            if not contained[key]:
                t.exposed_steps += 1
                if rec.verified:
                    contained[key] = True
                    t.contained += 1
                    t.delays.append(since_onset[key])
            since_onset[key] += 1
        else:
            t.benign_steps += 1
            if rec.verified:
                t.false_verifications += 1

        if rec.verified:
            t.verifications += 1

    return t


def _finalize(t: _Tally) -> Metrics:
    """Turn accumulated counts into the reported metrics."""
    steps = t.attack_steps + t.benign_steps
    return Metrics(
        steps=steps,
        attack_steps=t.attack_steps,
        benign_steps=t.benign_steps,
        episodes=t.episodes,
        verifications=t.verifications,
        exposure=t.exposed_steps / t.attack_steps if t.attack_steps else 0.0,
        containment=t.contained / t.episodes if t.episodes else 0.0,
        median_onset_delay=statistics.median(t.delays) if t.delays else None,
        budget_per_1k_steps=1000.0 * t.verifications / steps if steps else 0.0,
        false_verifications_per_1k_benign=(
            1000.0 * t.false_verifications / t.benign_steps if t.benign_steps else 0.0
        ),
    )


def _evaluate_flat(records: list[StepRecord]) -> Metrics:
    """Evaluate without recursing into per-group breakdowns."""
    return _finalize(_tally(records))


def evaluate(records: list[StepRecord], *, by_group: bool = False) -> Metrics:
    """Compute the operational metrics over ``records``.

    Args:
        records: Steps in chronological order within each session.
        by_group: When True, also compute the metrics separately for each
            distinct ``group`` label.
    """
    if not records:
        raise ValueError("cannot evaluate an empty record set")

    result = _evaluate_flat(records)
    if not by_group:
        return result

    groups: dict[str, list[StepRecord]] = {}
    for rec in records:
        if rec.group is not None:
            groups.setdefault(rec.group, []).append(rec)

    return Metrics(
        steps=result.steps,
        attack_steps=result.attack_steps,
        benign_steps=result.benign_steps,
        episodes=result.episodes,
        verifications=result.verifications,
        exposure=result.exposure,
        containment=result.containment,
        median_onset_delay=result.median_onset_delay,
        budget_per_1k_steps=result.budget_per_1k_steps,
        false_verifications_per_1k_benign=result.false_verifications_per_1k_benign,
        by_group={name: _evaluate_flat(rows) for name, rows in sorted(groups.items())},
    )


def bootstrap_ci(
    records: list[StepRecord],
    *,
    metric: str = "exposure",
    resamples: int = 1000,
    confidence: float = 0.95,
    seed: int = 0,
) -> tuple[float, float]:
    """Session-grouped bootstrap confidence interval for one metric.

    Whole sessions are resampled with replacement, never individual steps,
    because consecutive steps within a session are strongly dependent.

    Args:
        records: Steps to resample.
        metric: Attribute name on :class:`Metrics` to bootstrap.
        resamples: Number of bootstrap replicates.
        confidence: Coverage of the returned interval.
        seed: Seed for reproducibility.

    Returns:
        Lower and upper percentile bounds.
    """
    if not 0.0 < confidence < 1.0:
        raise ValueError(f"confidence must lie in (0, 1), got {confidence}")
    if resamples < 2:
        raise ValueError(f"resamples must be at least 2, got {resamples}")

    sessions: dict[str, list[StepRecord]] = {}
    for rec in records:
        sessions.setdefault(rec.session, []).append(rec)
    keys = sorted(sessions)
    if not keys:
        raise ValueError("cannot bootstrap an empty record set")

    # Tally each session once. A resample is then a sum of per-session tallies,
    # which is both far cheaper than re-walking every step and correct when the
    # same session is drawn more than once - counts add, where re-walking would
    # have let the duplicate inherit the original's episode containment.
    tallies = [_tally(sessions[key]) for key in keys]

    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(resamples):
        total = _Tally()
        for _ in range(len(keys)):
            total = total + tallies[rng.randrange(len(tallies))]
        value = getattr(_finalize(total), metric)
        if value is not None:
            values.append(float(value))

    if not values:
        raise ValueError(f"metric {metric!r} was undefined in every resample")

    values.sort()
    tail = (1.0 - confidence) / 2.0
    lo = values[min(len(values) - 1, int(tail * len(values)))]
    hi = values[min(len(values) - 1, int((1.0 - tail) * len(values)))]
    return lo, hi
