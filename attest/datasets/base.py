"""Turning a real labelled corpus into something the scheduler can be scored on.

Every number this project has published so far comes from a generator written
alongside the thing being measured. That is a real weakness, and the fix is not
a better generator - it is a corpus somebody else collected, with labels
somebody else assigned.

A loader's job is to produce :class:`Timeline` objects: one entity, its events
in order, and ground truth about when that entity was compromised. Everything
downstream - the risk model, the four policies, the four metrics, the bootstrap
- is shared with the synthetic path, so a real-data result and a synthetic one
are computed by identical code and are directly comparable.

The split is entity-grouped, always. Splitting by event would put the same
account on both sides and report a number that means nothing.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, Protocol, Sequence

from ..learn import LogisticModel
from ..simulate import Session

__all__ = ["Timeline", "TimelineLoader", "split_entities", "fit_scorer", "to_sessions"]


@dataclass
class Timeline:
    """One entity's event history with ground truth.

    Attributes:
        entity_id: Account, host or agent the events belong to.
        times: Event timestamps, non-decreasing.
        features: Numeric feature dict per event, produced by the loader.
        is_attack: Whether the entity was compromised at each event.
        episode: Identifier of the compromise episode an attack event belongs
            to, or None. Contiguous attack events sharing an id form one
            episode, which is what containment and onset delay are measured
            over.
    """

    entity_id: str
    times: list[float]
    features: list[dict[str, float]]
    is_attack: list[bool]
    episode: list[str | None]

    def __post_init__(self) -> None:
        n = len(self.times)
        if not (len(self.features) == len(self.is_attack) == len(self.episode) == n):
            raise ValueError(
                f"timeline {self.entity_id!r} has ragged columns: "
                f"{n} times, {len(self.features)} features, "
                f"{len(self.is_attack)} labels, {len(self.episode)} episodes"
            )
        if any(b < a for a, b in zip(self.times, self.times[1:])):
            raise ValueError(f"timeline {self.entity_id!r} is not time-ordered")

    def __len__(self) -> int:
        return len(self.times)

    @property
    def attack_events(self) -> int:
        return sum(self.is_attack)

    @property
    def episodes(self) -> int:
        return len({e for e in self.episode if e is not None})


class TimelineLoader(Protocol):
    """A corpus reader."""

    name: str

    def load(self, **kwargs) -> list[Timeline]:
        """Read the corpus and return per-entity timelines."""
        ...


def split_entities(
    timelines: Sequence[Timeline],
    *,
    train: float = 0.5,
    calibrate: float = 0.2,
    seed: int = 0,
) -> tuple[list[Timeline], list[Timeline], list[Timeline]]:
    """Split by entity into train, calibration and test sets.

    Entities are stratified by whether they were ever compromised, because
    compromise is rare enough that a naive split routinely puts every labelled
    episode on one side.

    Returns:
        Training, calibration and test timelines.
    """
    if not 0.0 < train < 1.0 or not 0.0 <= calibrate < 1.0:
        raise ValueError("train must be in (0, 1) and calibrate in [0, 1)")
    if train + calibrate >= 1.0:
        raise ValueError("train + calibrate must leave a non-empty test set")

    rng = random.Random(seed)
    attacked = [t for t in timelines if t.attack_events]
    clean = [t for t in timelines if not t.attack_events]

    buckets: list[list[Timeline]] = [[], [], []]
    for group in (attacked, clean):
        group = list(group)
        rng.shuffle(group)
        n = len(group)
        n_train = int(n * train)
        n_cal = int(n * calibrate)
        buckets[0] += group[:n_train]
        buckets[1] += group[n_train : n_train + n_cal]
        buckets[2] += group[n_train + n_cal :]

    return buckets[0], buckets[1], buckets[2]


def fit_scorer(
    train: Sequence[Timeline],
    calibration: Sequence[Timeline],
    *,
    seed: int = 0,
    **model_kwargs,
) -> LogisticModel:
    """Fit and calibrate the perception stage on disjoint entity sets.

    Args:
        train: Timelines the coefficients are fitted on.
        calibration: Timelines the temperature is fitted on. Must not overlap
            ``train``, or the model will look better calibrated than it is.
    """
    rows = [f for t in train for f in t.features]
    labels = [int(a) for t in train for a in t.is_attack]
    if not rows:
        raise ValueError("training split contains no events")

    model = LogisticModel(**model_kwargs).fit(rows, labels, seed=seed)

    cal_rows = [f for t in calibration for f in t.features]
    cal_labels = [int(a) for t in calibration for a in t.is_attack]
    if cal_rows and 0 < sum(cal_labels) < len(cal_labels):
        model.calibrate(cal_rows, cal_labels)
    return model


def to_sessions(
    timelines: Sequence[Timeline],
    scorer: LogisticModel | Callable[[dict[str, float]], float],
) -> list[Session]:
    """Score timelines into the session form the policy runner consumes.

    This is what lets a real corpus be evaluated by exactly the same code as
    the synthetic benchmark, rather than by a parallel implementation that
    might quietly differ.
    """
    score = scorer.score if isinstance(scorer, LogisticModel) else scorer
    sessions = []
    for timeline in timelines:
        sessions.append(
            Session(
                session_id=timeline.entity_id,
                is_attack=list(timeline.is_attack),
                episode=list(timeline.episode),
                p=[score(f) for f in timeline.features],
                times=list(timeline.times),
            )
        )
    return sessions
