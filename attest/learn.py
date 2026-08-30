"""A small fittable perception stage.

The synthetic benchmark hands the scheduler a probability directly. Real data
does not: something has to turn raw events into a calibrated compromise
probability first, and the trust recurrence is only meaningful if that number
is genuinely calibrated rather than merely ranked correctly.

This is deliberately the smallest thing that can do that job honestly - logistic
regression fitted by minibatch gradient descent, followed by temperature
scaling on a held-out split. No dependencies, a handful of parameters, and
every coefficient inspectable. If a bigger model is warranted later it can
replace this behind the same interface; the point of the architecture is that
only this stage is ever learned.

Two facilities that real event streams need and a static feature table does
not:

:class:`RollingFeatures` derives novelty, burst and breadth signals from an
entity's own history, so "this account reached a machine it has never touched"
is measured against that account rather than against a global average.

:class:`Standardizer` is fitted on the training split only, because scaling
statistics computed over the whole corpus leak test information into training.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

from .evidence import Calibrator

__all__ = ["Standardizer", "RollingFeatures", "LogisticModel"]


@dataclass
class Standardizer:
    """Per-feature mean/scale, fitted on training rows only."""

    names: list[str] = field(default_factory=list)
    mean: list[float] = field(default_factory=list)
    scale: list[float] = field(default_factory=list)

    def fit(self, rows: list[dict[str, float]]) -> "Standardizer":
        if not rows:
            raise ValueError("cannot fit a standardizer on no rows")
        self.names = sorted({key for row in rows for key in row})
        self.mean, self.scale = [], []
        for name in self.names:
            values = [float(row.get(name, 0.0)) for row in rows]
            mu = sum(values) / len(values)
            var = sum((v - mu) ** 2 for v in values) / len(values)
            self.mean.append(mu)
            # A constant feature would divide by zero; leaving its scale at 1
            # simply zeroes the column, which is the right outcome.
            self.scale.append(math.sqrt(var) or 1.0)
        return self

    def transform(self, row: dict[str, float]) -> list[float]:
        return [
            (float(row.get(name, 0.0)) - mu) / sd
            for name, mu, sd in zip(self.names, self.mean, self.scale)
        ]


@dataclass
class RollingFeatures:
    """Novelty, burst and breadth derived from one entity's own history.

    Args:
        breadth_window: Seconds over which distinct peers are counted. Reaching
            many distinct destinations in a short window is the classic lateral
            movement signature, and it is invisible to any per-event view.
        warmup: Events before novelty counts at full weight. Everything is new
            to a fresh entity by construction, so counting that as evidence
            would flood every newcomer.
    """

    breadth_window: float = 3600.0
    warmup: int = 50
    _seen: dict[str, set[str]] = field(default_factory=dict, init=False)
    _recent: list[tuple[float, str]] = field(default_factory=list, init=False)
    _count: int = field(default=0, init=False)
    _last: float | None = field(default=None, init=False)
    _mean_gap: float | None = field(default=None, init=False)

    def observe(
        self, at: float, categorical: dict[str, str], peer: str | None = None
    ) -> dict[str, float]:
        """Return features for this event, then fold it into the history.

        Args:
            at: Event timestamp.
            categorical: Named categorical fields whose novelty is tracked.
            peer: Counterparty identifier for the breadth window, if any.
        """
        weight = 1.0 if self.warmup <= 0 else min(1.0, self._count / self.warmup)
        out: dict[str, float] = {}

        for name, value in categorical.items():
            known = self._seen.setdefault(name, set())
            out[f"new_{name}"] = weight if value not in known else 0.0

        gap = None if self._last is None else at - self._last
        burst = 0.0
        if gap is not None and self._mean_gap and self._mean_gap > 0.0 and gap >= 0.0:
            burst = max(0.0, (self._mean_gap - gap) / self._mean_gap)
        out["burst"] = burst * weight

        if peer is not None:
            cutoff = at - self.breadth_window
            self._recent = [(t, p) for t, p in self._recent if t >= cutoff]
            self._recent.append((at, peer))
            # Log-scaled: the jump from one peer to five matters far more than
            # the jump from fifty to fifty-four.
            out["breadth"] = math.log1p(len({p for _, p in self._recent}))
        out["cold_start"] = 0.0 if self._count >= self.warmup else 1.0

        for name, value in categorical.items():
            self._seen.setdefault(name, set()).add(value)
        if gap is not None and gap >= 0.0:
            self._mean_gap = (
                gap if self._mean_gap is None else 0.9 * self._mean_gap + 0.1 * gap
            )
        self._last = at
        self._count += 1
        return out


@dataclass
class LogisticModel:
    """Logistic regression with temperature calibration.

    Args:
        l2: Ridge penalty. Keeps coefficients finite on separable features,
            which event data frequently is.
        epochs: Passes over the training set.
        lr: Initial learning rate, decayed across epochs.
        batch_size: Minibatch size.
        pos_weight: Weight applied to positive examples. Compromise is rare
            enough that unweighted training collapses to predicting "clean".
            None derives it from the training split's class balance.
    """

    l2: float = 1e-4
    epochs: int = 25
    lr: float = 0.2
    batch_size: int = 256
    pos_weight: float | None = None
    weights: list[float] = field(default_factory=list)
    bias: float = 0.0
    standardizer: Standardizer = field(default_factory=Standardizer)
    calibrator: Calibrator = field(default_factory=Calibrator)

    def _logit(self, x: list[float]) -> float:
        return self.bias + sum(w * v for w, v in zip(self.weights, x))

    def fit(
        self,
        rows: list[dict[str, float]],
        labels: list[int],
        *,
        seed: int = 0,
    ) -> "LogisticModel":
        """Fit coefficients on ``rows``.

        Calibration is deliberately *not* done here - fitting a temperature on
        the same rows the coefficients came from would report a model as
        better calibrated than it is. Call :meth:`calibrate` on a held-out
        split.
        """
        if len(rows) != len(labels):
            raise ValueError(
                f"rows and labels differ in length: {len(rows)} vs {len(labels)}"
            )
        if not rows:
            raise ValueError("cannot fit on an empty training set")

        self.standardizer.fit(rows)
        design = [self.standardizer.transform(row) for row in rows]
        n_features = len(self.standardizer.names)
        self.weights = [0.0] * n_features
        self.bias = 0.0

        positives = sum(labels)
        if self.pos_weight is not None:
            pos_weight = self.pos_weight
        elif positives == 0 or positives == len(labels):
            pos_weight = 1.0
        else:
            pos_weight = (len(labels) - positives) / positives

        rng = random.Random(seed)
        order = list(range(len(design)))

        for epoch in range(self.epochs):
            rng.shuffle(order)
            # 1/sqrt decay: 1/(1+epoch) starves the fit long before it
            # converges, which on a small training set leaves the model
            # badly underconfident in both directions.
            lr = self.lr / math.sqrt(1.0 + epoch)
            for start in range(0, len(order), self.batch_size):
                batch = order[start : start + self.batch_size]
                grad_w = [0.0] * n_features
                grad_b = 0.0
                for i in batch:
                    x, y = design[i], labels[i]
                    z = self._logit(x)
                    pred = 1.0 / (1.0 + math.exp(-z)) if z >= 0 else (
                        math.exp(z) / (1.0 + math.exp(z))
                    )
                    weight = pos_weight if y else 1.0
                    err = weight * (pred - y)
                    grad_b += err
                    for j, v in enumerate(x):
                        grad_w[j] += err * v
                scale = lr / len(batch)
                self.bias -= scale * grad_b
                for j in range(n_features):
                    self.weights[j] -= scale * (grad_w[j] + self.l2 * self.weights[j])

        # Undo the class weighting's effect on the prior. Training with a
        # positive weight of w fits the odds of a reweighted population in
        # which compromise is w times more common than it really is, so the
        # raw scores come out inflated. Temperature scaling cannot fix this -
        # it rescales the logit but cannot shift it - so the correction has to
        # happen here, by subtracting log(w) from the intercept. Without it the
        # trust recurrence, which reads p as an expected count of bad evidence,
        # is fed numbers that are systematically too large.
        if pos_weight > 0.0:
            self.bias -= math.log(pos_weight)
        return self

    def calibrate(
        self, rows: list[dict[str, float]], labels: list[int]
    ) -> "LogisticModel":
        """Fit the temperature on a split the coefficients never saw."""
        logits = [self._logit(self.standardizer.transform(row)) for row in rows]
        self.calibrator.fit(logits, labels)
        return self

    def score(self, row: dict[str, float]) -> float:
        """Calibrated probability that this event indicates compromise."""
        if not self.weights:
            raise RuntimeError("model has not been fitted")
        return self.calibrator(self._logit(self.standardizer.transform(row)))

    def coefficients(self) -> list[tuple[str, float]]:
        """Feature weights, largest magnitude first. The whole model, readable."""
        return sorted(
            zip(self.standardizer.names, self.weights),
            key=lambda pair: -abs(pair[1]),
        )
