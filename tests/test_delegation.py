import pytest

from attest import AttestEngine, Budget, Envelope, PolicyParams
from attest.delegation import (
    DelegationParams,
    backflow_weights,
    effective_trust,
)
from attest.policy import Action


# ------------------------------------------------------------- effective trust


def test_a_lone_agent_reduces_to_its_own_trust():
    chain = effective_trust([("a", 0.87)])
    assert chain.score == 0.87
    assert chain.target == "a"
    assert chain.depth == 0
    assert chain.limited_by_principal is False


def test_a_chain_is_as_strong_as_its_weakest_link():
    chain = effective_trust([("root", 0.20), ("mid", 0.95), ("worker", 0.98)])
    assert chain.score == pytest.approx(0.20)
    assert chain.target == "root"
    assert chain.depth == 2


def test_a_clean_worker_keeps_its_own_trust_intact():
    """The worker did nothing wrong; only the action it took is discounted."""
    chain = effective_trust([("root", 0.10), ("worker", 0.97)])
    assert chain.self_trust == 0.97
    assert chain.score == pytest.approx(0.10)


def test_verification_targets_the_principal_not_the_sender():
    """Challenging a spotless worker tells you nothing about its principal."""
    chain = effective_trust([("compromised", 0.05), ("worker", 0.99)])
    assert chain.target == "compromised"
    assert chain.limited_by_principal is True


def test_the_sender_is_the_target_when_the_sender_is_the_problem():
    chain = effective_trust([("root", 0.95), ("worker", 0.12)])
    assert chain.target == "worker"
    assert chain.limited_by_principal is False


def test_product_strategy_compounds_across_hops():
    chain = effective_trust(
        [("a", 0.9), ("b", 0.9), ("c", 0.9)],
        DelegationParams(strategy="product"),
    )
    assert chain.score == pytest.approx(0.729)
    # min would have given 0.9 - product charges for depth itself.
    assert chain.score < 0.9


def test_hop_damping_shrinks_distant_distrust():
    healthy = [("root", 0.0), ("mid", 1.0), ("worker", 1.0)]
    assert effective_trust(healthy).score == pytest.approx(0.0)

    # At damping 0.5 a root two hops up contributes a quarter of its distrust.
    damped = effective_trust(healthy, DelegationParams(hop_damping=0.5))
    assert damped.score == pytest.approx(0.75)


def test_damping_never_affects_the_acting_agent():
    chain = effective_trust(
        [("root", 1.0), ("worker", 0.3)], DelegationParams(hop_damping=0.1)
    )
    assert chain.score == pytest.approx(0.3)


def test_long_chains_are_truncated_from_the_actor_backwards():
    """Nearest principals matter most, and an unbounded walk is a DoS."""
    chain = [(f"a{i}", 0.99) for i in range(20)]
    chain[0] = ("ancient-root", 0.01)
    result = effective_trust(chain, DelegationParams(max_depth=3))
    assert result.depth == 2
    assert result.score == pytest.approx(0.99)
    assert result.target != "ancient-root"


def test_empty_chain_is_rejected():
    with pytest.raises(ValueError, match="at least the acting agent"):
        effective_trust([])


@pytest.mark.parametrize(
    "kwargs",
    [
        {"strategy": "average"},
        {"hop_damping": 0.0},
        {"hop_damping": 1.5},
        {"backflow": -0.1},
        {"backflow": 1.5},
        {"max_depth": 0},
    ],
)
def test_invalid_delegation_params_are_rejected(kwargs):
    with pytest.raises(ValueError):
        DelegationParams(**kwargs)


# ----------------------------------------------------------------- backflow


def test_backflow_decays_with_distance():
    weights = dict(backflow_weights(["root", "mid"], DelegationParams(backflow=0.5)))
    assert weights["mid"] == pytest.approx(0.5)
    assert weights["root"] == pytest.approx(0.25)


def test_backflow_can_be_disabled():
    assert backflow_weights(["root"], DelegationParams(backflow=0.0)) == []


def test_no_principals_means_no_backflow():
    assert backflow_weights([]) == []


# ------------------------------------------------------------------- engine


def _env(sender, t, *, healthy=True, on_behalf_of=()):
    return Envelope(
        sender=sender,
        recipient="tool-search" if healthy else "tool-exfil",
        intent="core",
        action="query" if healthy else "bulk_export",
        timestamp=float(t),
        signature_valid=healthy,
        credential_valid=healthy,
        audit_proof=f"merkle:{t}" if healthy else None,
        on_behalf_of=on_behalf_of,
    )


def test_undelegated_traffic_behaves_exactly_as_before():
    engine = AttestEngine()
    for i in range(80):
        decision = engine.observe(_env("solo", i))
    assert decision.effective_trust == pytest.approx(decision.trust)
    assert decision.target == "solo"
    assert decision.delegated is False


def test_a_compromised_principal_drags_down_its_delegate_s_actions():
    engine = AttestEngine()

    # Both agents build a clean history of their own.
    for i in range(120):
        engine.observe(_env("boss", i))
        engine.observe(_env("worker", i))
    assert engine.trust_of("worker") > 0.9

    # The principal is taken over. The worker carries on with its own clean
    # work throughout, so its score stays high on its own merits.
    for i in range(120, 220):
        engine.observe(_env("boss", i, healthy=False))
        engine.observe(_env("worker", i))
    assert engine.trust_of("worker") > 0.9

    # Work the worker does for the boss is another matter.
    decision = engine.observe(_env("worker", 220, on_behalf_of=("boss",)))
    assert decision.trust > 0.9
    assert decision.effective_trust < 0.2
    assert decision.target == "boss"


def test_the_delegate_s_own_trust_survives_its_principal_being_compromised():
    engine = AttestEngine()
    for i in range(120):
        engine.observe(_env("boss", i))
        engine.observe(_env("worker", i))
    for i in range(120, 220):
        engine.observe(_env("boss", i, healthy=False))
        engine.observe(_env("worker", i, on_behalf_of=("boss",)))

    # Guilt by association would be wrong: the worker never misbehaved.
    assert engine.trust_of("worker") > 0.85


def test_bad_evidence_flows_up_to_the_principal():
    """Otherwise a delegate is a way to launder a compromise."""

    def run(backflow):
        engine = AttestEngine(delegation=DelegationParams(backflow=backflow))
        for i in range(120):
            engine.observe(_env("boss", i))
            engine.observe(_env("worker", i))
        for i in range(120, 260):
            engine.observe(_env("worker", i, healthy=False, on_behalf_of=("boss",)))
        return engine.trust_of("boss")

    assert run(0.5) < run(0.0)


def test_good_evidence_does_not_flow_up():
    """A principal cannot rebuild its score by delegating innocuous work.

    A burned agent always drifts back toward the 0.5 prior as evidence ages -
    that is the intended idle behaviour. The claim here is narrower: clean work
    done by a delegate on its behalf must not lift it any *faster* than simply
    doing nothing would.
    """

    def boss_trust_after(delegate_clean_work: bool) -> float:
        engine = AttestEngine(delegation=DelegationParams(backflow=0.9))
        for i in range(120):
            engine.observe(_env("boss", i, healthy=False))
        for i in range(120, 400):
            if delegate_clean_work:
                engine.observe(_env("worker", i, on_behalf_of=("boss",)))
            else:
                engine.observe(_env("bystander", i))
        return engine.trust_of("boss", now=400.0)

    assert boss_trust_after(True) == pytest.approx(boss_trust_after(False), abs=1e-9)


def test_one_verification_of_the_principal_covers_every_delegate():
    """The budget saving: check the weak link once, not each worker in turn."""
    engine = AttestEngine(policy_params=PolicyParams(cooldown_seconds=0.0))
    workers = [f"w{i}" for i in range(6)]

    for i in range(120):
        engine.observe(_env("boss", i))
        for w in workers:
            engine.observe(_env(w, i))

    # Take the principal over, and let every worker keep acting on its behalf.
    verifications = []
    for i in range(120, 260):
        engine.observe(_env("boss", i, healthy=False))
        for w in workers:
            d = engine.observe(_env(w, i, on_behalf_of=("boss",)))
            if d.action is Action.VERIFY:
                verifications.append(d)

    # Every check aimed at the principal, and hysteresis kept it to one.
    assert all(v.target == "boss" for v in verifications)
    assert len(verifications) <= 1


def test_verifying_the_principal_resets_the_principal_not_the_sender():
    engine = AttestEngine(
        policy_params=PolicyParams(cooldown_seconds=0.0),
        budget=Budget(capacity=1, refill_per_second=0.0),
    )
    for i in range(120):
        engine.observe(_env("boss", i))
        engine.observe(_env("worker", i))

    # Drain the budget so the principal's own bad traffic cannot fire a check.
    # Budget exhaustion leaves the trigger armed, which is what lets the
    # delegate's next message be the thing that finally trips it.
    engine.budget.spend(0.0)
    for i in range(120, 240):
        engine.observe(_env("boss", i, healthy=False))
        engine.observe(_env("worker", i))
    assert engine.trust_of("boss") < 0.1

    engine.budget = Budget.unlimited()
    before = engine.trust_of("worker")

    fired = None
    for i in range(240, 320):
        d = engine.observe(_env("worker", i, on_behalf_of=("boss",)))
        if d.action is Action.VERIFY:
            fired = d
            break

    assert fired is not None and fired.target == "boss"
    assert engine.trust_of("boss") == pytest.approx(0.5)
    # The worker was never challenged, so its own score is untouched.
    assert engine.trust_of("worker") == pytest.approx(before, abs=0.05)


def test_backflow_tolerates_interleaved_timestamps():
    """A principal's own traffic and its delegates' arrive out of order."""
    engine = AttestEngine(delegation=DelegationParams(backflow=0.5))
    for i in range(50):
        engine.observe(_env("boss", i * 2 + 1))
        # Delegate evidence timestamped before the principal's last update.
        engine.observe(_env("worker", i * 2, healthy=False, on_behalf_of=("boss",)))
    assert 0.0 <= engine.trust_of("boss") <= 1.0


def test_chain_is_reported_on_the_decision():
    engine = AttestEngine()
    decision = engine.observe(
        _env("worker", 1, on_behalf_of=("root", "mid"))
    )
    assert decision.chain == ("root", "mid", "worker")
    assert decision.delegated is True
    assert decision.verification_target in decision.chain


def test_a_busy_orchestrator_is_not_penalised_for_being_busy():
    """Clean delegated work must not erode a principal simply by volume.

    Upward propagation is one-sided, so without a threshold the small residual
    risk on every ordinary message would accumulate against the principal with
    nothing to offset it.
    """
    workers = [f"w{i}" for i in range(8)]

    def boss_state(delegating: bool):
        engine = AttestEngine(delegation=DelegationParams(backflow=0.9))
        for i in range(60):
            engine.observe(_env("boss", i))
        for i in range(60, 400):
            for w in workers:
                engine.observe(
                    _env(w, i, on_behalf_of=("boss",) if delegating else ())
                )
        return engine.store.get("boss").trust

    # Identical to the case where the same work happened for someone else:
    # volume of clean delegated work costs the principal nothing at all.
    assert boss_state(True) == boss_state(False)


def test_the_backflow_threshold_gates_propagation():
    def boss_trust(threshold):
        engine = AttestEngine(
            delegation=DelegationParams(backflow=0.9, backflow_threshold=threshold)
        )
        for i in range(60):
            engine.observe(_env("boss", i))
        for i in range(60, 200):
            engine.observe(_env("worker", i, on_behalf_of=("boss",)))
        return engine.trust_of("boss", now=200.0)

    # Clean delegate traffic scores around 0.02, so a threshold above it gates
    # everything out and one below it lets the residue through.
    assert boss_trust(0.5) > boss_trust(0.0)


def test_penalize_adds_no_good_evidence():
    from attest import TrustParams, TrustState

    params = TrustParams()
    state = TrustState(r=5.0, s=1.0, updated_at=0.0)
    after = state.penalize(1.0, 1.0, params)

    assert after.s > state.s * params.gamma
    # r only decays; it never grows.
    assert after.r == pytest.approx(state.r * params.gamma)
    assert after.score < state.score
