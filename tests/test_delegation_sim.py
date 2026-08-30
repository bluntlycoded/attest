import pytest

from attest import AttestEngine, Envelope
from attest.delegation import DelegationParams
from attest.delegation_sim import DelegationScenario, compare, run_scenario
from attest.policy import Action


SMALL = DelegationScenario(orchestrators=3, workers_each=4, steps=900)


def test_scenario_is_reproducible():
    a = run_scenario(SMALL, chain_aware=True, seed=4)
    b = run_scenario(SMALL, chain_aware=True, seed=4)
    assert a == b


def test_chain_blind_scheduling_contains_nothing_in_this_scenario():
    """By construction: the principal's own traffic never looks wrong.

    Every check the blind arm spends lands on a worker that really is clean,
    comes back clean, and leaves the orchestrator directing it untouched.
    """
    outcome = run_scenario(SMALL, chain_aware=False, seed=0)
    assert outcome.episodes > 0
    assert outcome.contained == 0
    assert outcome.useful == 0
    assert outcome.wasted == outcome.verifications
    assert outcome.exposure > 0.8


def test_chain_aware_scheduling_contains_the_same_episodes():
    outcome = run_scenario(SMALL, chain_aware=True, seed=0)
    assert outcome.episodes > 0
    assert outcome.contained / outcome.episodes > 0.8
    assert outcome.exposure < 0.3
    assert outcome.median_delay is not None


def test_chain_awareness_costs_less_not_more():
    """The saving: one correctly aimed check beats many misaimed ones."""
    both = compare(SMALL, seed=0)
    aware, blind = both["chain-aware"], both["chain-blind"]

    assert aware.budget_per_1k_steps < blind.budget_per_1k_steps
    assert aware.wasted_fraction < blind.wasted_fraction
    assert aware.exposure < blind.exposure


@pytest.mark.parametrize("seed", [0, 1, 2, 3])
def test_the_advantage_holds_across_seeds(seed):
    both = compare(SMALL, seed=seed)
    assert both["chain-aware"].contained > both["chain-blind"].contained


def test_weak_backflow_reproduces_the_blind_failure():
    """Upward propagation is what makes chain awareness work at all.

    With it disabled the principal never becomes the weakest link, so the
    chain-aware arm degenerates into the blind one.
    """
    import attest.delegation_sim as sim

    original = sim.AttestEngine

    class NoBackflow(original):
        def __init__(self, **kwargs):
            super().__init__(**kwargs, delegation=DelegationParams(backflow=0.0))

    sim.AttestEngine = NoBackflow
    try:
        outcome = run_scenario(SMALL, chain_aware=True, seed=0)
    finally:
        sim.AttestEngine = original

    assert outcome.contained == 0


def test_an_independently_compromised_worker_is_targeted_not_its_principal():
    """Chain awareness must not shift blame upward when the delegate is at fault."""
    engine = AttestEngine()

    def env(sender, t, healthy, obo=()):
        return Envelope(
            sender=sender,
            recipient="tool-search" if healthy else "tool-exfil",
            intent="core",
            action="query" if healthy else "bulk_export",
            timestamp=float(t),
            signature_valid=healthy,
            credential_valid=healthy,
            audit_proof=f"merkle:{t}" if healthy else None,
            on_behalf_of=obo,
        )

    for i in range(120):
        engine.observe(env("boss", i, True))
        engine.observe(env("worker", i, True))

    fired = None
    for i in range(120, 300):
        engine.observe(env("boss", i, True))
        decision = engine.observe(env("worker", i, False, ("boss",)))
        if decision.action is Action.VERIFY:
            fired = decision
            break

    assert fired is not None
    assert fired.target == "worker"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"orchestrators": 0},
        {"workers_each": 0},
        {"steps": 0},
        {"attack_hazard": 0.0},
        {"attack_hazard": 1.0},
        {"episode_mean": 1.0},
    ],
)
def test_invalid_scenarios_are_rejected(kwargs):
    with pytest.raises(ValueError):
        DelegationScenario(**kwargs)


def test_outcome_summary_is_readable():
    outcome = run_scenario(SMALL, chain_aware=True, seed=0)
    text = outcome.summary()
    assert "exposure" in text and "wasted" in text
