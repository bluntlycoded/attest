import pytest

from attest.metrics import evaluate
from attest.policy import Budget, PolicyParams
from attest.simulate import (
    BetaTrustPolicy,
    EwmaThresholdPolicy,
    GeneratorConfig,
    PeriodicPolicy,
    RawThresholdPolicy,
    benchmark,
    generate_sessions,
    run_policy,
)


def test_generation_is_reproducible():
    a = generate_sessions(20, seed=1)
    b = generate_sessions(20, seed=1)
    assert [s.is_attack for s in a] == [s.is_attack for s in b]
    assert [s.p for s in a] == [s.p for s in b]


def test_different_seeds_give_different_sessions():
    a = generate_sessions(20, seed=1)
    b = generate_sessions(20, seed=2)
    assert [s.is_attack for s in a] != [s.is_attack for s in b]


def test_sessions_have_the_configured_shape():
    cfg = GeneratorConfig(session_length=128)
    sessions = generate_sessions(10, cfg, seed=0)
    assert len(sessions) == 10
    for s in sessions:
        assert len(s) == 128
        assert len(s.p) == len(s.times) == len(s.episode) == 128
        assert all(0.0 <= p <= 1.0 for p in s.p)


def test_episode_lengths_respect_the_configured_clips():
    cfg = GeneratorConfig(episode_min=6, episode_max=96)
    sessions = generate_sessions(200, cfg, seed=3)

    lengths = {}
    for s in sessions:
        for eid in s.episode:
            if eid is not None:
                lengths[eid] = lengths.get(eid, 0) + 1

    assert lengths
    # An episode can be truncated by the end of its session, so only the upper
    # clip is guaranteed to hold exactly.
    assert max(lengths.values()) <= cfg.episode_max


def test_benign_steps_carry_no_episode_id():
    for s in generate_sessions(30, seed=5):
        for attack, eid in zip(s.is_attack, s.episode):
            assert (eid is None) == (not attack)


def test_some_sessions_are_entirely_benign():
    sessions = generate_sessions(300, GeneratorConfig(benign_session_share=0.10), seed=11)
    clean = sum(1 for s in sessions if not any(s.is_attack))
    assert clean > 0


def test_detector_quality_separates_the_score_distributions():
    sessions = generate_sessions(100, GeneratorConfig(detector_quality=9.0), seed=2)
    attack = [p for s in sessions for p, a in zip(s.p, s.is_attack) if a]
    benign = [p for s in sessions for p, a in zip(s.p, s.is_attack) if not a]
    assert sum(attack) / len(attack) > 0.8
    assert sum(benign) / len(benign) < 0.2


def test_periodic_policy_fires_on_schedule():
    sessions = generate_sessions(5, GeneratorConfig(session_length=100), seed=0)
    records = run_policy(sessions, PeriodicPolicy(k=10), cooldown_seconds=0.0)
    assert sum(1 for r in records if r.verified) == 5 * 10


def test_cooldown_suppresses_rapid_refiring():
    sessions = generate_sessions(5, GeneratorConfig(session_length=100), seed=0)
    loose = run_policy(sessions, PeriodicPolicy(k=2), cooldown_seconds=0.0)
    tight = run_policy(sessions, PeriodicPolicy(k=2), cooldown_seconds=20.0)
    assert sum(r.verified for r in tight) < sum(r.verified for r in loose)


def test_budget_caps_verifications_per_session():
    sessions = generate_sessions(10, GeneratorConfig(session_length=200), seed=0)
    records = run_policy(
        sessions,
        PeriodicPolicy(k=2),
        cooldown_seconds=0.0,
        budget=lambda: Budget(capacity=3, refill_per_second=0.0),
    )
    assert sum(r.verified for r in records) == 30


def test_adaptive_policy_beats_periodic_on_budget_at_similar_exposure():
    """The result the whole design exists to produce."""
    sessions = generate_sessions(400, seed=0)

    adaptive = evaluate(
        run_policy(sessions, BetaTrustPolicy(policy_params=PolicyParams(theta_low=0.5)))
    )
    # A periodic control granted enough budget to reach comparable exposure.
    periodic = evaluate(run_policy(sessions, PeriodicPolicy(k=16)))

    assert adaptive.exposure < 0.6
    assert adaptive.budget_per_1k_steps < periodic.budget_per_1k_steps
    assert (
        adaptive.false_verifications_per_1k_benign
        < periodic.false_verifications_per_1k_benign
    )


def test_trust_layer_beats_thresholding_at_matched_budget():
    """Integrating evidence beats thresholding it, spend held equal.

    The comparison only means something at a matched budget. Raw thresholding
    at a low cutoff contains almost everything - by verifying constantly. Held
    to the same spend, it has to sit so close to certainty that it throws away
    all the sub-certain evidence, and misses roughly half the episodes.
    """
    sessions = generate_sessions(400, seed=0)

    trust = evaluate(run_policy(sessions, BetaTrustPolicy()))
    # theta chosen to land within ~10% of the trust policy's budget.
    raw = evaluate(run_policy(sessions, RawThresholdPolicy(theta=0.995)))

    assert abs(raw.budget_per_1k_steps - trust.budget_per_1k_steps) < 1.0
    assert trust.exposure < raw.exposure
    assert trust.containment > raw.containment


def test_trust_layer_degrades_when_probabilities_are_poorly_calibrated():
    """A documented failure mode, not an accident.

    The recurrence treats p as an expected count of bad evidence. If a benign
    agent's scores average far above zero, w scales that into a steady-state
    trust below theta_low, and the policy fires on well-behaved agents and then
    disarms. Calibration is a precondition, and this test pins that down so the
    limitation cannot quietly disappear.
    """
    weak = generate_sessions(300, GeneratorConfig(detector_quality=1.5), seed=0)
    strong = generate_sessions(300, GeneratorConfig(detector_quality=9.0), seed=0)

    on_weak = evaluate(run_policy(weak, BetaTrustPolicy()))
    on_strong = evaluate(run_policy(strong, BetaTrustPolicy()))

    assert on_weak.containment < 0.1
    assert on_weak.false_verifications_per_1k_benign > 1.0
    assert on_strong.containment > 0.7
    assert on_strong.false_verifications_per_1k_benign < 1.0


def test_benchmark_reports_every_policy():
    sessions = generate_sessions(50, seed=0)
    results = benchmark(
        sessions,
        [
            BetaTrustPolicy(),
            RawThresholdPolicy(),
            EwmaThresholdPolicy(),
            PeriodicPolicy(k=16),
        ],
    )
    assert set(results) == {"beta-trust", "raw-threshold", "ewma-threshold", "periodic"}
    for m in results.values():
        assert m.steps == 50 * 256


@pytest.mark.parametrize(
    "kwargs",
    [
        {"session_length": 0},
        {"attack_hazard": 0.0},
        {"attack_hazard": 1.0},
        {"episode_mean": 1.0},
        {"episode_min": 0},
        {"episode_min": 50, "episode_max": 10},
        {"benign_session_share": 1.5},
        {"detector_quality": 0.0},
        {"step_seconds": 0.0},
    ],
)
def test_invalid_generator_config_is_rejected(kwargs):
    with pytest.raises(ValueError):
        GeneratorConfig(**kwargs)


def test_generate_requires_at_least_one_session():
    with pytest.raises(ValueError, match="n must be at least 1"):
        generate_sessions(0)
