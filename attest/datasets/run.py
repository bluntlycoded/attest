"""Running the full evaluation over a real corpus.

Fits the perception stage on one set of entities, calibrates it on a second,
and evaluates the scheduler on a third that neither has touched. The four
policies and four metrics are the same objects the synthetic benchmark uses.

Detection quality is reported alongside the scheduling result on purpose. A
scheduler sitting on a weak risk model will look bad for reasons that have
nothing to do with scheduling, and separating the two is the only way the
number means anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from ..metrics import Metrics, bootstrap_ci, evaluate
from ..policy import Budget, PolicyParams
from ..simulate import (
    BetaTrustPolicy,
    EwmaThresholdPolicy,
    PeriodicPolicy,
    RawThresholdPolicy,
    run_policy,
)
from ..trust import TrustParams
from .base import Timeline, fit_scorer, split_entities, to_sessions

__all__ = [
    "Detection",
    "CorpusReport",
    "ShadowReport",
    "evaluate_corpus",
    "shadow_corpus",
]


@dataclass(frozen=True)
class Detection:
    """How well the perception stage separates compromise from normal use."""

    roc_auc: float
    pr_auc: float
    ece: float
    positives: int
    negatives: int
    base_rate: float

    def summary(self) -> str:
        return (
            f"ROC-AUC {self.roc_auc:.4f} | PR-AUC {self.pr_auc:.4f} | "
            f"ECE {self.ece:.4f} | base rate {self.base_rate:.5f}"
        )


@dataclass
class CorpusReport:
    """Everything one evaluation run produced."""

    dataset: str
    entities: int
    events: int
    episodes: int
    attack_events: int
    train_entities: int
    test_entities: int
    detection: Detection
    coefficients: list[tuple[str, float]]
    policies: dict[str, Metrics] = field(default_factory=dict)
    exposure_ci: dict[str, tuple[float, float]] = field(default_factory=dict)

    def summary(self) -> str:
        lines = [
            f"{self.dataset}: {self.entities} entities, {self.events:,} events, "
            f"{self.episodes} episodes, {self.attack_events:,} compromised events",
            f"detection (held out): {self.detection.summary()}",
            "",
        ]
        for name, m in self.policies.items():
            ci = self.exposure_ci.get(name)
            band = f" [{ci[0]:.3f}, {ci[1]:.3f}]" if ci else ""
            lines.append(f"  {name:<16} {m.summary()}{band}")
        return "\n".join(lines)


def _roc_auc(scores: Sequence[float], labels: Sequence[int]) -> float:
    """Rank-based AUC, ties averaged. Equivalent to the Mann-Whitney statistic."""
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return float("nan")

    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        average = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = average
        i = j + 1

    rank_sum = sum(r for r, y in zip(ranks, labels) if y)
    return (rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


def _pr_auc(scores: Sequence[float], labels: Sequence[int]) -> float:
    """Average precision. The metric that survives a severe class imbalance."""
    positives = sum(labels)
    if positives == 0:
        return float("nan")

    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    tp = 0
    total = 0.0
    for seen, index in enumerate(order, start=1):
        if labels[index]:
            tp += 1
            total += tp / seen
    return total / positives


def _ece(scores: Sequence[float], labels: Sequence[int], bins: int = 15) -> float:
    """Expected calibration error - the gap between confidence and reality."""
    if not scores:
        return float("nan")
    buckets: list[list[tuple[float, int]]] = [[] for _ in range(bins)]
    for p, y in zip(scores, labels):
        buckets[min(bins - 1, int(p * bins))].append((p, y))

    error = 0.0
    for bucket in buckets:
        if not bucket:
            continue
        confidence = sum(p for p, _ in bucket) / len(bucket)
        accuracy = sum(y for _, y in bucket) / len(bucket)
        error += len(bucket) / len(scores) * abs(confidence - accuracy)
    return error


def evaluate_corpus(
    timelines: Sequence[Timeline],
    *,
    dataset: str = "corpus",
    theta_low: float = 0.5,
    theta_high: float = 0.65,
    cooldown_seconds: float = 8.0,
    step_seconds: float | None = None,
    budget_per_1k: float | None = None,
    resamples: int = 200,
    seed: int = 0,
) -> CorpusReport:
    """Fit, calibrate and evaluate on entity-disjoint splits.

    Args:
        timelines: Loaded corpus.
        step_seconds: Trust step interval. Defaults to the corpus's median
            inter-event gap, which is the value that makes the recurrence
            behave - see :meth:`attest.TrustParams.from_event_interval`.
        budget_per_1k: Verification cap. None measures each policy
            unconstrained, which is what isolates how many checks each needs.
        resamples: Bootstrap replicates; 0 skips confidence intervals.
    """
    if not timelines:
        raise ValueError("no timelines to evaluate")

    train, calibration, test = split_entities(timelines, seed=seed)
    if not test:
        raise ValueError("the entity split left an empty test set")
    if not any(t.attack_events for t in test):
        raise ValueError(
            "no compromised entity landed in the test split; try another seed "
            "or a corpus with more labelled episodes"
        )

    model = fit_scorer(train, calibration or train, seed=seed)

    test_rows = [f for t in test for f in t.features]
    test_labels = [int(a) for t in test for a in t.is_attack]
    test_scores = [model.score(row) for row in test_rows]
    positives = sum(test_labels)

    detection = Detection(
        roc_auc=_roc_auc(test_scores, test_labels),
        pr_auc=_pr_auc(test_scores, test_labels),
        ece=_ece(test_scores, test_labels),
        positives=positives,
        negatives=len(test_labels) - positives,
        base_rate=positives / len(test_labels) if test_labels else 0.0,
    )

    sessions = to_sessions(test, model)

    if step_seconds is None:
        gaps = sorted(
            b - a
            for session in sessions
            for a, b in zip(session.times, session.times[1:])
            if b > a
        )
        step_seconds = gaps[len(gaps) // 2] if gaps else 1.0

    trust_params = TrustParams.from_event_interval(step_seconds)
    budget = None
    if budget_per_1k is not None:
        budget = lambda: Budget.per_thousand_steps(  # noqa: E731
            budget_per_1k, step_seconds
        )

    policies = [
        BetaTrustPolicy(
            trust_params=trust_params,
            policy_params=PolicyParams(
                theta_low=theta_low,
                theta_high=theta_high,
                cooldown_seconds=cooldown_seconds,
            ),
        ),
        RawThresholdPolicy(theta=0.9),
        EwmaThresholdPolicy(),
        PeriodicPolicy(k=16),
    ]

    report = CorpusReport(
        dataset=dataset,
        entities=len(timelines),
        events=sum(len(t) for t in timelines),
        episodes=sum(t.episodes for t in timelines),
        attack_events=sum(t.attack_events for t in timelines),
        train_entities=len(train),
        test_entities=len(test),
        detection=detection,
        coefficients=model.coefficients(),
    )

    for policy in policies:
        records = run_policy(
            sessions, policy, cooldown_seconds=cooldown_seconds, budget=budget
        )
        report.policies[policy.name] = evaluate(records)
        if resamples:
            report.exposure_ci[policy.name] = bootstrap_ci(
                records, resamples=resamples, seed=seed
            )

    return report


@dataclass
class ShadowReport:
    """What an unlabelled corpus can honestly tell you.

    Deliberately missing: exposure, containment and onset delay. All three are
    defined against ground truth about when an entity was compromised, and a
    corpus without labels does not have it. Reporting them anyway would mean
    inventing the denominator.

    What remains is still worth having. Budget is the ongoing cost of a policy,
    and on a fleet believed to be largely healthy the verification rate is a
    direct read on how often the policy would interrupt someone for nothing.
    """

    dataset: str
    entities: int
    events: int
    step_seconds: float
    verifications: dict[str, int] = field(default_factory=dict)
    budget_per_1k_steps: dict[str, float] = field(default_factory=dict)
    entities_verified: dict[str, int] = field(default_factory=dict)
    mean_trust: float = 0.5

    def summary(self) -> str:
        lines = [
            f"{self.dataset}: {self.entities} entities, {self.events:,} events "
            f"(unlabelled - no exposure, containment or delay available)",
            f"step interval {self.step_seconds:.3f}s | mean trust {self.mean_trust:.3f}",
            "",
        ]
        for name in self.verifications:
            lines.append(
                f"  {name:<16} {self.verifications[name]:>6} checks | "
                f"{self.budget_per_1k_steps[name]:>7.2f}/1k steps | "
                f"{self.entities_verified[name]:>4}/{self.entities} entities touched"
            )
        return "\n".join(lines)


def shadow_corpus(
    timelines: Sequence[Timeline],
    scorer,
    *,
    dataset: str = "corpus",
    theta_low: float = 0.5,
    theta_high: float = 0.65,
    cooldown_seconds: float = 8.0,
    step_seconds: float | None = None,
) -> ShadowReport:
    """Measure verification cost on a corpus with no ground truth.

    Args:
        timelines: Loaded corpus, labels ignored entirely.
        scorer: Callable mapping a feature row to a probability. Nothing can be
            fitted here - without labels there is no training signal - so this
            has to be supplied, typically a hand-specified one such as
            :func:`attest.datasets.nodewatch.host_scorer`.
    """
    if not timelines:
        raise ValueError("no timelines to evaluate")

    sessions = to_sessions(timelines, scorer)

    if step_seconds is None:
        gaps = sorted(
            b - a
            for session in sessions
            for a, b in zip(session.times, session.times[1:])
            if b > a
        )
        step_seconds = gaps[len(gaps) // 2] if gaps else 1.0

    trust_params = TrustParams.from_event_interval(step_seconds)
    policies = [
        BetaTrustPolicy(
            trust_params=trust_params,
            policy_params=PolicyParams(
                theta_low=theta_low,
                theta_high=theta_high,
                cooldown_seconds=cooldown_seconds,
            ),
        ),
        RawThresholdPolicy(theta=0.9),
        EwmaThresholdPolicy(),
        PeriodicPolicy(k=16),
    ]

    scores = [p for session in sessions for p in session.p]
    report = ShadowReport(
        dataset=dataset,
        entities=len(timelines),
        events=sum(len(t) for t in timelines),
        step_seconds=step_seconds,
        mean_trust=1.0 - (sum(scores) / len(scores) if scores else 0.5),
    )

    for policy in policies:
        records = run_policy(sessions, policy, cooldown_seconds=cooldown_seconds)
        fired = [r for r in records if r.verified]
        report.verifications[policy.name] = len(fired)
        report.budget_per_1k_steps[policy.name] = (
            1000.0 * len(fired) / len(records) if records else 0.0
        )
        report.entities_verified[policy.name] = len({r.session for r in fired})

    return report
