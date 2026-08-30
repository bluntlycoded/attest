import pytest

from attest.engine import AttestEngine, Verification
from attest.evidence import Envelope, LogisticRiskScorer
from attest.metrics import evaluate
from attest.policy import Action, Budget, PolicyParams
from attest.store import InMemoryStore, JsonFileStore
from attest.trust import TrustParams


def _env(i, *, sender="agent-a", **kw):
    defaults = dict(
        sender=sender,
        recipient="tool-search",
        intent="core",
        action="query",
        timestamp=float(i),
        audit_proof=f"proof-{i}",
    )
    defaults.update(kw)
    return Envelope(**defaults)


class RecordingVerifier:
    def __init__(self):
        self.calls = []

    def __call__(self, agent_id, decision):
        self.calls.append((agent_id, decision.timestamp))
        return Verification(agent_id=agent_id, timestamp=decision.timestamp, compromised=True)


def test_ordinary_traffic_keeps_an_agent_trusted():
    engine = AttestEngine()
    for i in range(200):
        decision = engine.observe(_env(i))
    assert decision.action is Action.OBSERVE
    assert engine.trust_of("agent-a") > 0.9


def test_bad_signatures_drive_a_verification():
    engine = AttestEngine()
    for i in range(100):
        engine.observe(_env(i))
    assert engine.trust_of("agent-a") > 0.9

    actions = [
        engine.observe(_env(100 + i, signature_valid=False)).action for i in range(40)
    ]
    assert Action.VERIFY in actions


def test_shadow_mode_does_not_call_the_verifier():
    verifier = RecordingVerifier()
    engine = AttestEngine(verifier=verifier, shadow=True)
    for i in range(200):
        engine.observe(_env(i, signature_valid=False))
    assert verifier.calls == []


def test_enforcing_mode_calls_the_verifier():
    verifier = RecordingVerifier()
    engine = AttestEngine(verifier=verifier, shadow=False)
    for i in range(200):
        engine.observe(_env(i, signature_valid=False))
    assert verifier.calls


def test_enforcing_mode_requires_a_verifier():
    with pytest.raises(ValueError, match="requires a verifier"):
        AttestEngine(shadow=False)


def test_shadow_and_enforcing_produce_identical_decision_streams():
    """Shadow numbers are only useful if they predict enforcement."""

    def decisions(shadow):
        engine = AttestEngine(
            verifier=RecordingVerifier(),
            shadow=shadow,
            store=InMemoryStore(),
        )
        return [
            (d.action, round(d.trust, 9))
            for d in (engine.observe(_env(i, signature_valid=i % 3 == 0)) for i in range(300))
        ]

    assert decisions(True) == decisions(False)


def test_trust_resets_after_a_verification():
    engine = AttestEngine()
    fired_at = None
    for i in range(300):
        d = engine.observe(_env(i, signature_valid=False))
        if d.action is Action.VERIFY:
            fired_at = i
            break
    assert fired_at is not None
    # Reset returns to the prior, not to either extreme.
    assert engine.trust_of("agent-a") == pytest.approx(0.5)


def test_a_sustained_offender_is_verified_once_then_disarms():
    """Hysteresis, working as intended: no chattering on a stuck-bad agent."""
    engine = AttestEngine(policy_params=PolicyParams(cooldown_seconds=0.0))
    verifications = sum(
        1
        for i in range(2000)
        if engine.observe(_env(i, signature_valid=False)).action is Action.VERIFY
    )
    assert verifications == 1


def test_budget_is_shared_across_agents():
    """The budget is a fleet-wide constraint, not a per-agent one."""

    def fired(budget):
        engine = AttestEngine(
            budget=budget, policy_params=PolicyParams(cooldown_seconds=0.0)
        )
        return sum(
            1
            for agent in range(20)
            for i in range(300)
            if engine.observe(
                _env(i, sender=f"agent-{agent}", signature_valid=False)
            ).action
            is Action.VERIFY
        )

    assert fired(Budget.unlimited()) == 20
    assert fired(Budget(capacity=5, refill_per_second=0.0)) == 5


def test_agents_are_tracked_independently():
    engine = AttestEngine()
    for i in range(200):
        engine.observe(_env(i, sender="clean"))
        engine.observe(_env(i, sender="dirty", signature_valid=False))
    assert engine.trust_of("clean") > 0.9
    assert engine.trust_of("dirty") < engine.trust_of("clean")


def test_idle_agents_lose_their_standing():
    engine = AttestEngine()
    for i in range(200):
        engine.observe(_env(i))
    assert engine.trust_of("agent-a") > 0.9
    assert engine.trust_of("agent-a", now=1e7) == pytest.approx(0.5, abs=1e-6)


def test_subscribers_see_every_decision():
    engine = AttestEngine()
    seen = []
    engine.subscribe(seen.append)
    for i in range(50):
        engine.observe(_env(i))
    assert len(seen) == 50


def test_state_survives_a_restart(tmp_path):
    path = tmp_path / "state.json"

    engine = AttestEngine(store=JsonFileStore(path))
    for i in range(200):
        engine.observe(_env(i))
    before = engine.trust_of("agent-a")

    revived = AttestEngine(store=JsonFileStore(path))
    assert revived.trust_of("agent-a") == pytest.approx(before)


def test_warmup_damps_novelty_for_a_brand_new_agent():
    """A new agent sees everything for the first time; that is not evidence."""
    engine = AttestEngine(warmup_events=50)
    first = engine.observe(_env(0, recipient="tool-a", intent="i0", action="a0"))

    engine2 = AttestEngine(warmup_events=0)
    cold = engine2.observe(_env(0, recipient="tool-a", intent="i0", action="a0"))

    assert first.p < cold.p


def test_decisions_can_be_scored_with_the_metrics_module():
    engine = AttestEngine()
    records = []
    for i in range(400):
        compromised = i >= 200
        d = engine.observe(_env(i, signature_valid=not compromised))
        records.append(
            __import__("attest").StepRecord(
                session="s0",
                is_attack=compromised,
                episode="e0" if compromised else None,
                verified=d.action is Action.VERIFY,
            )
        )
    m = evaluate(records)
    assert m.episodes == 1
    assert m.containment == 1.0
    assert m.exposure < 1.0
