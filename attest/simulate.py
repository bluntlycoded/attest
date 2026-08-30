"""Session generation and policy benchmarking.

There is no public corpus of compromised AI agents, so there is nothing to
evaluate a scheduler against directly. This module builds the missing thing
explicitly rather than pretending otherwise: a seeded, documented two-state
generator that produces agent timelines with benign operation, a compromise
onset, a sustained episode, and a recovery.

The dynamics are synthetic and fully disclosed. The detector output is modelled
too - a pair of Beta distributions whose separation stands in for detector
quality - which means a benchmark run measures the *scheduler*, holding the
perception stage fixed. That is the intended use. It is not evidence about how
well any particular risk model detects real compromise, and nothing here should
be reported as though it were.

Sweeping ``detector_quality`` is the honest way to use this: it answers "how
much does the scheduling layer buy me, given a detector of roughly this
quality", which is a question the generator can legitimately speak to.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Callable, Protocol

from .metrics import Metrics, StepRecord, evaluate
from .policy import Budget, PolicyParams, PolicyState, Action, decide
from .trust import TrustParams, TrustState

__all__ = [
    "GeneratorConfig",
    "Session",
    "generate_sessions",
    "TriggerPolicy",
    "BetaTrustPolicy",
    "RawThresholdPolicy",
    "EwmaThresholdPolicy",
    "PeriodicPolicy",
    "run_policy",
    "benchmark",
]


@dataclass(frozen=True)
class GeneratorConfig:
    """Reference configuration for the session generator.

    Attributes:
        session_length: Steps per session.
        attack_hazard: Per-step probability that a benign regime turns into an
            attack episode.
        episode_mean: Mean episode length, geometrically distributed.
        episode_min: Lower clip on episode length.
        episode_max: Upper clip on episode length.
        guard_steps: Forced benign period after every episode ends, so episodes
            do not run together.
        benign_session_share: Fraction of sessions containing no attack at all,
            included as a false-trigger stress test.
        detector_quality: Concentration of the Beta distributions the detector
            is modelled with. Higher means cleaner separation between benign
            and attack scores. At 9.0 the means sit near 0.1 and 0.9.
        step_seconds: Wall-clock spacing between steps.
    """

    session_length: int = 256
    attack_hazard: float = 0.02
    episode_mean: float = 24.0
    episode_min: int = 6
    episode_max: int = 96
    guard_steps: int = 8
    benign_session_share: float = 0.10
    detector_quality: float = 9.0
    step_seconds: float = 1.0

    def __post_init__(self) -> None:
        if self.session_length < 1:
            raise ValueError("session_length must be at least 1")
        if not 0.0 < self.attack_hazard < 1.0:
            raise ValueError("attack_hazard must lie in (0, 1)")
        if self.episode_mean <= 1.0:
            raise ValueError("episode_mean must exceed 1")
        if not 0 < self.episode_min <= self.episode_max:
            raise ValueError("require 0 < episode_min <= episode_max")
        if not 0.0 <= self.benign_session_share <= 1.0:
            raise ValueError("benign_session_share must lie in [0, 1]")
        if self.detector_quality <= 0.0:
            raise ValueError("detector_quality must be positive")
        if self.step_seconds <= 0.0:
            raise ValueError("step_seconds must be positive")


@dataclass
class Session:
    """One generated agent timeline.

    Attributes:
        session_id: Unique identifier, used as the bootstrap resampling unit.
        is_attack: Ground-truth compromise indicator per step.
        episode: Episode identifier per step, None where benign.
        p: Modelled detector output per step.
        times: Unix timestamp per step.
    """

    session_id: str
    is_attack: list[bool]
    episode: list[str | None]
    p: list[float]
    times: list[float]

    def __len__(self) -> int:
        return len(self.is_attack)


def _geometric(rng: random.Random, mean: float, lo: int, hi: int) -> int:
    """Draw a geometric length with the given mean, clipped to [lo, hi]."""
    q = 1.0 / mean
    u = rng.random()
    # Guard against log(0) when u rounds to exactly 1.
    n = math.ceil(math.log(max(1e-12, 1.0 - u)) / math.log(1.0 - q))
    return max(lo, min(hi, int(n)))


def generate_sessions(
    n: int,
    config: GeneratorConfig | None = None,
    *,
    seed: int = 0,
    start_time: float = 0.0,
) -> list[Session]:
    """Generate ``n`` independent agent sessions.

    Args:
        n: Number of sessions.
        config: Generator settings. Defaults to the reference configuration.
        seed: Seed for reproducibility. The same seed always yields the same
            sessions.
        start_time: Unix timestamp of the first step of every session.
    """
    if n < 1:
        raise ValueError(f"n must be at least 1, got {n}")
    cfg = config or GeneratorConfig()
    rng = random.Random(seed)
    k = cfg.detector_quality
    sessions: list[Session] = []

    for i in range(n):
        session_id = f"s{i:05d}"
        fully_benign = rng.random() < cfg.benign_session_share

        is_attack: list[bool] = []
        episode: list[str | None] = []
        remaining = 0
        guard = 0
        current: str | None = None
        n_episodes = 0

        for _ in range(cfg.session_length):
            if remaining > 0:
                remaining -= 1
                is_attack.append(True)
                episode.append(current)
                if remaining == 0:
                    guard = cfg.guard_steps
                    current = None
                continue

            if guard > 0:
                guard -= 1
            elif not fully_benign and rng.random() < cfg.attack_hazard:
                length = _geometric(
                    rng, cfg.episode_mean, cfg.episode_min, cfg.episode_max
                )
                current = f"{session_id}-e{n_episodes}"
                n_episodes += 1
                remaining = length - 1
                is_attack.append(True)
                episode.append(current)
                if remaining == 0:
                    guard = cfg.guard_steps
                    current = None
                continue

            is_attack.append(False)
            episode.append(None)

        # Model the detector: benign scores concentrate low, attack scores high.
        p = [
            rng.betavariate(k, 1.0) if a else rng.betavariate(1.0, k)
            for a in is_attack
        ]
        times = [
            start_time + j * cfg.step_seconds for j in range(cfg.session_length)
        ]
        sessions.append(Session(session_id, is_attack, episode, p, times))

    return sessions


class TriggerPolicy(Protocol):
    """A rule that decides, from the probability stream, when to verify.

    Implementations differ only in what quantity they threshold. Cooldown,
    budget and containment semantics are applied uniformly by :func:`run_policy`
    so that comparisons between them are like for like.
    """

    name: str

    def reset(self) -> None:
        """Clear all per-session state. Called once before each session."""
        ...

    def wants_verify(self, p: float, t: float) -> bool:
        """Whether this policy would verify at this step, ignoring cooldown."""
        ...

    def on_verify(self, t: float) -> None:
        """Notify that a verification actually fired, so state can reset."""
        ...


@dataclass
class BetaTrustPolicy:
    """The proposed policy: Beta-reputation trust with hysteresis.

    Integrates the probability stream with asymmetric memory rather than
    thresholding it instant by instant, so evidence too weak to trip a
    per-step threshold still accumulates into a containment.
    """

    trust_params: TrustParams = field(default_factory=TrustParams)
    policy_params: PolicyParams = field(default_factory=PolicyParams)
    name: str = "beta-trust"
    _trust: TrustState = field(default_factory=TrustState, init=False)
    _state: PolicyState = field(default_factory=PolicyState, init=False)

    def reset(self) -> None:
        self._trust = TrustState()
        self._state = PolicyState()

    def wants_verify(self, p: float, t: float) -> bool:
        self._trust = self._trust.observe(p, t, self.trust_params)
        action, state, _ = decide(
            self._state, self._trust.score, t, self.policy_params
        )
        self._state = state
        return action is Action.VERIFY

    def on_verify(self, t: float) -> None:
        self._trust = self._trust.reset(t)

    @property
    def trust(self) -> float:
        """Current trust score, for plotting a trajectory."""
        return self._trust.score


@dataclass
class RawThresholdPolicy:
    """Verify whenever the instantaneous probability exceeds a threshold.

    This is conventional risk-based authentication: score the event, escalate
    above a cutoff, keep no memory between events.
    """

    theta: float = 0.9
    name: str = "raw-threshold"

    def reset(self) -> None:
        return None

    def wants_verify(self, p: float, t: float) -> bool:
        return p > self.theta

    def on_verify(self, t: float) -> None:
        return None


@dataclass
class EwmaThresholdPolicy:
    """Verify when an exponentially-weighted mean of ``1 - p`` falls too low.

    Has memory, but symmetric memory: it forgives exactly as fast as it burns.
    Included to isolate how much of the trust layer's advantage comes from
    smoothing and how much from the asymmetry.
    """

    alpha: float = 0.3
    theta: float = 0.5
    name: str = "ewma-threshold"
    _value: float | None = field(default=None, init=False)

    def reset(self) -> None:
        self._value = None

    def wants_verify(self, p: float, t: float) -> bool:
        good = 1.0 - p
        self._value = good if self._value is None else (
            self.alpha * good + (1.0 - self.alpha) * self._value
        )
        return self._value < self.theta

    def on_verify(self, t: float) -> None:
        self._value = None


@dataclass
class PeriodicPolicy:
    """Verify every ``k`` steps regardless of behaviour.

    The control. This is what fixed session expiry and calendar-based
    credential rotation actually are, and it is the thing an adaptive policy
    has to beat on budget to be worth deploying.
    """

    k: int = 16
    name: str = "periodic"
    _count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if self.k < 1:
            raise ValueError(f"k must be at least 1, got {self.k}")

    def reset(self) -> None:
        self._count = 0

    def wants_verify(self, p: float, t: float) -> bool:
        self._count += 1
        return self._count % self.k == 0

    def on_verify(self, t: float) -> None:
        return None


def run_policy(
    sessions: list[Session],
    policy: TriggerPolicy,
    *,
    cooldown_seconds: float = 8.0,
    budget: Callable[[], Budget] | None = None,
) -> list[StepRecord]:
    """Replay ``sessions`` through ``policy`` and return evaluated steps.

    Cooldown and budget are applied here rather than inside each policy, so
    every policy is held to identical constraints and only the thresholded
    quantity differs.

    Args:
        sessions: Sessions to replay.
        policy: The trigger rule under test.
        cooldown_seconds: Minimum gap between verifications within a session.
        budget: Factory producing a fresh budget per session, or None for
            unlimited.
    """
    records: list[StepRecord] = []

    for session in sessions:
        policy.reset()
        session_budget = budget() if budget is not None else None
        cooldown_until = float("-inf")

        for j in range(len(session)):
            t = session.times[j]
            wants = policy.wants_verify(session.p[j], t)
            fired = False
            if wants and t >= cooldown_until:
                if session_budget is None or session_budget.spend(t):
                    fired = True
                    cooldown_until = t + cooldown_seconds
                    policy.on_verify(t)
            records.append(
                StepRecord(
                    session=session.session_id,
                    is_attack=session.is_attack[j],
                    episode=session.episode[j],
                    verified=fired,
                )
            )

    return records


def benchmark(
    sessions: list[Session],
    policies: list[TriggerPolicy],
    *,
    cooldown_seconds: float = 8.0,
    budget: Callable[[], Budget] | None = None,
) -> dict[str, Metrics]:
    """Evaluate several policies over the same sessions.

    Returns:
        Policy name to its metrics, in the order the policies were given.
    """
    return {
        policy.name: evaluate(
            run_policy(
                sessions,
                policy,
                cooldown_seconds=cooldown_seconds,
                budget=budget,
            )
        )
        for policy in policies
    }
