import math

import pytest

from attest.trust import STEPS_TO_RECOVER, TrustParams, TrustState


def _run(ps, params, start=None, t0=0.0):
    """Fold a probability sequence into a state, one step per step_seconds."""
    state = start or TrustState()
    for i, p in enumerate(ps):
        state = state.observe(p, t0 + i * params.step_seconds, params)
    return state


def test_no_evidence_is_the_neutral_prior():
    assert TrustState().score == 0.5


def test_sustained_clean_traffic_saturates_high():
    params = TrustParams()
    state = _run([0.0] * 400, params)
    # r -> 1/(1-gamma) = 16.67, s -> 0, so tau -> 17.67/18.67
    assert state.score == pytest.approx(0.946, abs=0.005)


def test_sustained_attack_collapses_low():
    params = TrustParams()
    state = _run([1.0] * 400, params)
    # s -> w/(1-gamma) = 33.3, r -> 0, so tau -> 1/35.3
    assert state.score < 0.03


def test_trust_burns_faster_than_it_recovers():
    """The asymmetry is the whole point: quick to burn, slow to rebuild."""
    params = TrustParams()

    state = TrustState()
    burn = 0
    while state.score > 0.3:
        state = state.observe(1.0, burn * params.step_seconds, params)
        burn += 1

    t = burn * params.step_seconds
    recover = 0
    while state.score < 0.65:
        state = state.observe(0.0, t + recover * params.step_seconds, params)
        recover += 1

    assert recover > burn * 2


def test_idle_agents_decay_toward_the_prior_not_toward_trusted():
    """A stale verification must not keep conferring trust."""
    params = TrustParams()
    trusted = _run([0.0] * 200, params)
    assert trusted.score > 0.9

    idle = trusted.decayed(1e6, params)
    assert idle.score == pytest.approx(0.5, abs=1e-6)


def test_distrusted_agents_also_decay_toward_the_prior():
    params = TrustParams()
    burned = _run([1.0] * 200, params)
    assert burned.score < 0.05
    assert burned.decayed(1e6, params).score == pytest.approx(0.5, abs=1e-6)


def test_decay_depends_on_elapsed_time_not_step_count():
    """Ten fast envelopes must not age the score like ten slow ones."""
    params = TrustParams(step_seconds=10.0)

    burst = TrustState()
    for i in range(10):
        burst = burst.observe(1.0, i * 0.1, params)

    spread = TrustState()
    for i in range(10):
        spread = spread.observe(1.0, i * 60.0, params)

    # Same evidence, but the spread-out stream has forgotten most of it.
    assert burst.score < spread.score


def test_reset_returns_to_prior():
    params = TrustParams()
    state = _run([1.0] * 50, params)
    assert state.reset(999.0).score == 0.5


def test_out_of_order_evidence_is_rejected():
    params = TrustParams()
    state = TrustState().observe(0.1, 100.0, params)
    with pytest.raises(ValueError, match="precedes last update"):
        state.observe(0.1, 99.0, params)


@pytest.mark.parametrize("p", [-0.01, 1.01, 2.0])
def test_probability_must_be_in_unit_interval(p):
    with pytest.raises(ValueError, match=r"p must lie in \[0, 1\]"):
        TrustState().observe(p, 0.0, TrustParams())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"gamma": 0.0},
        {"gamma": 1.0},
        {"gamma": 1.5},
        {"w": 0.0},
        {"step_seconds": 0.0},
    ],
)
def test_invalid_params_are_rejected(kwargs):
    with pytest.raises(ValueError):
        TrustParams(**kwargs)


def test_from_recovery_time_matches_the_stated_requirement():
    day = 24 * 3600.0
    params = TrustParams.from_recovery_time(day)
    assert params.recovery_seconds == pytest.approx(day)
    assert params.step_seconds == pytest.approx(day / STEPS_TO_RECOVER)


def test_half_life_is_consistent_with_gamma():
    params = TrustParams(gamma=0.5, step_seconds=1.0)
    assert params.half_life_seconds == pytest.approx(1.0)

    params = TrustParams(gamma=0.94, step_seconds=1.0)
    assert params.gamma ** (params.half_life_seconds) == pytest.approx(0.5)
    assert params.half_life_seconds == pytest.approx(
        math.log(0.5) / math.log(0.94)
    )
