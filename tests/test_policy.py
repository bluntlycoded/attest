import pytest

from attest.policy import Action, Budget, PolicyParams, PolicyState, Reason, decide


PARAMS = PolicyParams(theta_low=0.5, theta_high=0.65, cooldown_seconds=8.0)


def test_trusted_agent_is_observed():
    action, _, reason = decide(PolicyState(), 0.9, 0.0, PARAMS)
    assert action is Action.OBSERVE
    assert reason is Reason.TRUSTED


def test_fires_below_the_low_threshold():
    action, state, reason = decide(PolicyState(), 0.4, 100.0, PARAMS)
    assert action is Action.VERIFY
    assert reason is Reason.BELOW_THRESHOLD
    assert not state.armed
    assert state.cooldown_until == 108.0


def test_does_not_refire_while_disarmed_even_after_cooldown():
    """Hysteresis: trust has to climb clear of theta_high before re-arming."""
    _, state, _ = decide(PolicyState(), 0.4, 0.0, PARAMS)

    action, state, reason = decide(state, 0.4, 1000.0, PARAMS)
    assert action is Action.OBSERVE
    assert reason is Reason.DISARMED

    # Recovering into the hysteresis band is not enough.
    _, state, _ = decide(state, 0.60, 1001.0, PARAMS)
    assert not state.armed

    # Clearing theta_high re-arms.
    _, state, _ = decide(state, 0.70, 1002.0, PARAMS)
    assert state.armed

    action, _, _ = decide(state, 0.4, 1003.0, PARAMS)
    assert action is Action.VERIFY


def test_cooldown_blocks_a_rearmed_trigger():
    _, state, _ = decide(PolicyState(), 0.4, 0.0, PARAMS)
    state = PolicyState(armed=True, cooldown_until=state.cooldown_until)

    action, _, reason = decide(state, 0.4, 3.0, PARAMS)
    assert action is Action.OBSERVE
    assert reason is Reason.COOLDOWN

    action, _, _ = decide(state, 0.4, 8.0, PARAMS)
    assert action is Action.VERIFY


def test_exhausted_budget_suppresses_the_trigger():
    budget = Budget(capacity=1, refill_per_second=0.0)
    assert budget.spend(0.0)

    action, state, reason = decide(PolicyState(), 0.1, 0.0, PARAMS, budget=budget)
    assert action is Action.OBSERVE
    assert reason is Reason.BUDGET_EXHAUSTED
    # The trigger stays armed, so it fires as soon as budget returns.
    assert state.armed


def test_decide_does_not_spend_budget():
    """Deciding must be free, so shadow mode can evaluate without consuming."""
    budget = Budget(capacity=1, refill_per_second=0.0)
    for _ in range(5):
        action, _, _ = decide(PolicyState(), 0.1, 0.0, PARAMS, budget=budget)
        assert action is Action.VERIFY
    assert budget.tokens == pytest.approx(1.0)


def test_budget_refills_over_time():
    budget = Budget(capacity=2, refill_per_second=0.5)
    assert budget.spend(0.0)
    assert budget.spend(0.0)
    assert not budget.spend(0.0)
    assert not budget.spend(1.0)
    assert budget.spend(2.0)


def test_budget_does_not_refill_above_capacity():
    budget = Budget(capacity=2, refill_per_second=10.0)
    assert budget.spend(0.0)
    budget.available(1000.0)
    assert budget.tokens == pytest.approx(2.0)


def test_budget_per_thousand_steps_yields_the_requested_rate():
    budget = Budget.per_thousand_steps(rate=8.5, step_seconds=1.0)
    window = 1000.0
    spent = 0
    for i in range(1000):
        if budget.spend(float(i)):
            spent += 1
    # Capacity 8.5 up front plus one window of refill.
    assert 8 <= spent <= 18
    assert budget.refill_per_second == pytest.approx(8.5 / window)


def test_unlimited_budget_never_denies():
    budget = Budget.unlimited()
    for i in range(1000):
        assert budget.spend(float(i))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"theta_low": -0.1},
        {"theta_high": 1.1},
        {"theta_low": 0.8, "theta_high": 0.2},
        {"cooldown_seconds": -1.0},
    ],
)
def test_invalid_policy_params_are_rejected(kwargs):
    with pytest.raises(ValueError):
        PolicyParams(**kwargs)


@pytest.mark.parametrize(
    "kwargs", [{"capacity": 0.0, "refill_per_second": 1.0}, {"capacity": 1.0, "refill_per_second": -1.0}]
)
def test_invalid_budget_is_rejected(kwargs):
    with pytest.raises(ValueError):
        Budget(**kwargs)
