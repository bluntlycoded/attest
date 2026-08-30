"""Stage 1 - perception, as a hand-specified risk model.

The trust calculus consumes a *calibrated* compromise probability. It treats
``p`` as an expected count of bad evidence, so a merely monotonic score - one
that ranks correctly but is not on a probability scale - produces a trust
trajectory that is wrong by an arbitrary factor.

Nobody has a labelled corpus of compromised AI agents yet, so there is nothing
to fit a model against. This module therefore ships a logistic score with
explicitly stated prior weights rather than a learned one. Every weight is a
guess, documented as such, and meant to be replaced. What matters is that the
interface is the one a trained model will have, and that the calibration step
exists from the start rather than being retrofitted.

Run this in shadow mode, collect outcomes, then fit :class:`Calibrator` on real
labels and, eventually, replace :class:`LogisticRiskScorer` entirely.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

__all__ = ["Envelope", "AgentProfile", "Calibrator", "LogisticRiskScorer"]


@dataclass(frozen=True)
class Envelope:
    """One SAMACP message, reduced to the fields that carry risk signal.

    Attributes:
        sender: Agent identifier that produced the envelope.
        recipient: Agent or tool the envelope is addressed to.
        intent: Declared intent from the negotiated context.
        action: Declared action within that intent.
        timestamp: Unix timestamp the envelope was emitted.
        signature_valid: Whether the Ed25519 signature verified.
        credential_valid: Whether the sender's verifiable credential was
            unexpired and unrevoked at emission time.
        audit_proof: Merkle inclusion proof reference, or None if the envelope
            was never logged.
        on_behalf_of: Delegation chain above the sender - root principal first,
            immediate delegator last. Empty when the agent acts only for
            itself, in which case everything reduces to per-agent scoring.
    """

    sender: str
    recipient: str
    intent: str
    action: str
    timestamp: float
    signature_valid: bool = True
    credential_valid: bool = True
    audit_proof: str | None = None
    on_behalf_of: tuple[str, ...] = ()


@dataclass
class AgentProfile:
    """Rolling behavioural baseline for one agent.

    Novelty is measured against what this agent has done before, not against a
    global norm, because agents differ enormously in scope. A build agent that
    talks to fifty tools is not suspicious; a summarisation agent that suddenly
    talks to its first tool is.

    Attributes:
        agent_id: Identifier this profile describes.
        warmup_events: Number of envelopes before novelty signals count at full
            weight. During warm-up everything is novel by construction, so the
            novelty features are damped to avoid flooding a new agent with
            verifications it cannot avoid.
    """

    agent_id: str
    warmup_events: int = 50
    _peers: set[str] = field(default_factory=set)
    _intents: set[str] = field(default_factory=set)
    _actions: set[str] = field(default_factory=set)
    _count: int = 0
    _last_seen: float | None = None
    _mean_gap: float | None = None

    @property
    def count(self) -> int:
        """Number of envelopes folded into this profile."""
        return self._count

    @property
    def warm(self) -> bool:
        """Whether the profile has seen enough traffic to trust its novelty signals."""
        return self._count >= self.warmup_events

    @property
    def _novelty_weight(self) -> float:
        """Ramp novelty from 0 to 1 across the warm-up window."""
        if self.warmup_events <= 0:
            return 1.0
        return min(1.0, self._count / self.warmup_events)

    def features(self, env: Envelope) -> dict[str, float]:
        """Extract risk features for ``env`` without mutating the profile.

        Returns:
            Feature name to value in [0, 1], except ``burst`` which is an
            unbounded non-negative ratio.
        """
        nw = self._novelty_weight
        gap = None if self._last_seen is None else env.timestamp - self._last_seen

        # Burst: how much faster than usual this envelope arrived. Zero when
        # there is no baseline yet or the agent is slower than its own norm.
        burst = 0.0
        if gap is not None and self._mean_gap is not None and self._mean_gap > 0.0:
            if gap >= 0.0:
                burst = max(0.0, (self._mean_gap - gap) / self._mean_gap)

        return {
            "bad_signature": 0.0 if env.signature_valid else 1.0,
            "bad_credential": 0.0 if env.credential_valid else 1.0,
            "unlogged": 0.0 if env.audit_proof else 1.0,
            "new_peer": nw if env.recipient not in self._peers else 0.0,
            "new_intent": nw if env.intent not in self._intents else 0.0,
            "new_action": nw if env.action not in self._actions else 0.0,
            "burst": burst * nw,
        }

    def update(self, env: Envelope) -> None:
        """Fold ``env`` into the baseline. Call after scoring, not before."""
        if self._last_seen is not None:
            gap = env.timestamp - self._last_seen
            if gap >= 0.0:
                # EWMA over inter-arrival gaps, alpha fixed at 0.1.
                self._mean_gap = (
                    gap if self._mean_gap is None else 0.9 * self._mean_gap + 0.1 * gap
                )
        self._peers.add(env.recipient)
        self._intents.add(env.intent)
        self._actions.add(env.action)
        self._last_seen = env.timestamp
        self._count += 1


@dataclass
class Calibrator:
    """Temperature scaling applied to a risk logit.

    A single scalar divides the logit before the sigmoid. Above 1 it softens
    overconfident scores, below 1 it sharpens underconfident ones. Fit it on
    held-out labelled outcomes; until then the identity temperature leaves the
    prior weights untouched.
    """

    temperature: float = 1.0

    def __post_init__(self) -> None:
        if self.temperature <= 0.0:
            raise ValueError(f"temperature must be positive, got {self.temperature}")

    def __call__(self, logit: float) -> float:
        """Map a logit to a calibrated probability in [0, 1]."""
        z = logit / self.temperature
        # Branch to keep exp() from overflowing on large-magnitude logits.
        if z >= 0.0:
            return 1.0 / (1.0 + math.exp(-z))
        e = math.exp(z)
        return e / (1.0 + e)

    def fit(
        self,
        logits: list[float],
        labels: list[int],
        *,
        grid: tuple[float, float, int] = (0.05, 10.0, 400),
    ) -> "Calibrator":
        """Fit the temperature by grid search on negative log likelihood.

        A grid search rather than gradient descent because there is exactly one
        parameter and the objective is cheap.

        Args:
            logits: Uncalibrated logits.
            labels: Matching binary outcomes, 1 for compromised.

        Returns:
            Self, with ``temperature`` updated.
        """
        if len(logits) != len(labels):
            raise ValueError(
                f"logits and labels differ in length: {len(logits)} vs {len(labels)}"
            )
        if not logits:
            raise ValueError("cannot fit a calibrator on an empty sample")

        lo, hi, n = grid
        best_t, best_nll = self.temperature, float("inf")
        eps = 1e-12
        for i in range(n):
            t = lo + (hi - lo) * i / (n - 1)
            probe = Calibrator(temperature=t)
            nll = 0.0
            for logit, y in zip(logits, labels):
                p = min(1.0 - eps, max(eps, probe(logit)))
                nll -= math.log(p) if y else math.log(1.0 - p)
            if nll < best_nll:
                best_nll, best_t = nll, t
        self.temperature = best_t
        return self


# Prior weights, in logit units. These are stated guesses, not fitted values.
# Cryptographic failures dominate because they are close to proof rather than
# inference; behavioural novelty contributes far less because a legitimate agent
# encountering a new tool is entirely ordinary.
DEFAULT_WEIGHTS: dict[str, float] = {
    "bad_signature": 4.0,
    "bad_credential": 3.0,
    "unlogged": 1.5,
    "new_peer": 0.7,
    "new_intent": 0.9,
    "new_action": 0.6,
    "burst": 0.8,
}

# Chosen so that an envelope with no risk signal at all scores about 0.02.
DEFAULT_BIAS = -3.9


@dataclass
class LogisticRiskScorer:
    """Maps an envelope to a calibrated compromise probability.

    Args:
        weights: Feature weights in logit units.
        bias: Intercept, setting the score of a wholly unremarkable envelope.
        calibrator: Applied to the logit before the sigmoid.
    """

    weights: dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_WEIGHTS)
    )
    bias: float = DEFAULT_BIAS
    calibrator: Calibrator = field(default_factory=Calibrator)

    def logit(self, env: Envelope, profile: AgentProfile) -> float:
        """Uncalibrated risk logit for ``env``."""
        feats = profile.features(env)
        unknown = set(self.weights) - set(feats)
        if unknown:
            raise KeyError(f"weights reference unknown features: {sorted(unknown)}")
        return self.bias + sum(w * feats[name] for name, w in self.weights.items())

    def score(self, env: Envelope, profile: AgentProfile) -> float:
        """Calibrated probability in [0, 1] that the sender is compromised."""
        return self.calibrator(self.logit(env, profile))
