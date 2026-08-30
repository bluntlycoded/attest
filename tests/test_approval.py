import pytest

from attest import AttestEngine, Envelope, PolicyParams, TrustParams, Verification
from attest.approval import (
    AdaptiveThresholds,
    ApprovalPolicy,
    ApprovalRecord,
    Outcome,
    RubberStampDetector,
)
from attest.approval_sim import LoopScenario, run_loop
from attest.trust import TrustState


# ------------------------------------------------------------------ outcomes


def test_only_a_human_judgement_is_informative():
    assert Outcome.APPROVED.informative
    assert Outcome.REJECTED.informative
    assert not Outcome.TIMEOUT.informative
    assert not Outcome.FAILED.informative
    assert not Outcome.UNKNOWN.informative


def test_an_unset_outcome_is_inferred_from_the_compromise_flag():
    """Verifiers written before outcomes existed keep working."""
    clean = Verification(agent_id="a", timestamp=0.0, compromised=False)
    dirty = Verification(agent_id="a", timestamp=0.0, compromised=True)
    assert clean.resolved() is Outcome.APPROVED
    assert dirty.resolved() is Outcome.REJECTED


def test_an_explicit_outcome_wins_over_the_flag():
    v = Verification(
        agent_id="a", timestamp=0.0, compromised=False, outcome=Outcome.TIMEOUT
    )
    assert v.resolved() is Outcome.TIMEOUT


@pytest.mark.parametrize(
    "kwargs",
    [
        {"approval_vouch": -1.0},
        {"rejection_penalty": 1.5},
        {"threshold_step": -0.1},
        {"threshold_bound": 0.9},
        {"offset_half_life": 0.0},
    ],
)
def test_invalid_approval_policy_is_rejected(kwargs):
    with pytest.raises(ValueError):
        ApprovalPolicy(**kwargs)


# --------------------------------------------------------------------- vouch


def test_vouch_adds_good_evidence_only():
    params = TrustParams()
    state = TrustState(r=1.0, s=4.0, updated_at=0.0)
    after = state.vouch(3.0, 1.0, params)

    assert after.r > state.r
    assert after.s == pytest.approx(state.s * params.gamma)
    assert after.score > state.score


def test_vouch_from_the_prior_lands_above_it():
    """An approval should leave an agent better off than merely un-penalised."""
    after = TrustState().vouch(3.0, 0.0, TrustParams())
    assert after.score > 0.5


def test_vouch_rejects_negative_weight():
    with pytest.raises(ValueError, match="non-negative"):
        TrustState().vouch(-1.0, 0.0, TrustParams())


# -------------------------------------------------------- adaptive thresholds


def test_approval_widens_and_rejection_tightens():
    t = AdaptiveThresholds(ApprovalPolicy(threshold_step=0.05))
    t.record("a", Outcome.APPROVED)
    assert t.offset("a") == pytest.approx(-0.05)
    t.record("a", Outcome.REJECTED)
    assert t.offset("a") == pytest.approx(0.0)


def test_silence_is_not_consent():
    """A timeout must not quietly widen an agent's latitude."""
    t = AdaptiveThresholds()
    for _ in range(50):
        t.record("a", Outcome.TIMEOUT)
    assert t.offset("a") == 0.0


def test_timeouts_can_be_opted_into_as_approval():
    t = AdaptiveThresholds(ApprovalPolicy(timeout_is_approval=True))
    t.record("a", Outcome.TIMEOUT)
    assert t.offset("a") < 0.0


def test_the_bound_stops_latitude_running_away():
    """The safety property: approvals cannot buy unlimited freedom."""
    t = AdaptiveThresholds(ApprovalPolicy(threshold_bound=0.1))
    for _ in range(500):
        t.record("a", Outcome.APPROVED)
    assert t.offset("a") == pytest.approx(-0.1)


def test_the_bound_holds_in_the_tightening_direction_too():
    t = AdaptiveThresholds(ApprovalPolicy(threshold_bound=0.1))
    for _ in range(500):
        t.record("a", Outcome.REJECTED)
    assert t.offset("a") == pytest.approx(0.1)


def test_drift_decays_so_the_loop_is_not_a_ratchet():
    """One bad episode must not mark an agent as suspect forever."""
    t = AdaptiveThresholds(ApprovalPolicy(offset_half_life=100.0))
    for _ in range(20):
        t.record("a", Outcome.REJECTED, now=0.0)

    peak = t.offset("a", 0.0)
    assert t.offset("a", 100.0) == pytest.approx(peak / 2, abs=1e-6)
    assert t.offset("a", 1000.0) < 0.01


def test_threshold_reflects_the_drift():
    t = AdaptiveThresholds(ApprovalPolicy(threshold_step=0.1))
    t.record("a", Outcome.APPROVED)
    assert t.theta_low_for("a", 0.5) == pytest.approx(0.4)


def test_threshold_stays_in_range_even_at_the_extremes():
    t = AdaptiveThresholds(ApprovalPolicy(threshold_step=0.5, threshold_bound=0.5))
    t.record("a", Outcome.APPROVED)
    assert 0.0 <= t.theta_low_for("a", 0.1) <= 1.0
    t2 = AdaptiveThresholds(ApprovalPolicy(threshold_step=0.5, threshold_bound=0.5))
    t2.record("b", Outcome.REJECTED)
    assert 0.0 <= t2.theta_low_for("b", 0.9) <= 1.0


def test_reset_clears_earned_latitude():
    t = AdaptiveThresholds()
    t.record("a", Outcome.APPROVED, now=0.0)
    t.reset("a")
    assert t.offset("a", 0.0) == 0.0


# ------------------------------------------------------------- rubber stamps


def _records(n, approver, *, latency, rate=1.0, jitter=0.0):
    import random

    rng = random.Random(0)
    out = []
    for i in range(n):
        approved = rng.random() < rate
        out.append(
            ApprovalRecord(
                agent_id=f"a{i}",
                approver=approver,
                outcome=Outcome.APPROVED if approved else Outcome.REJECTED,
                requested_at=float(i),
                latency_seconds=latency + rng.uniform(-jitter, jitter),
            )
        )
    return out


def test_a_reviewer_who_is_reading_is_not_flagged():
    detector = RubberStampDetector()
    detector.extend(_records(60, "alice", latency=120.0, rate=0.8, jitter=100.0))
    assert detector.hollow_approvers() == []


def test_fast_uniform_blanket_approval_is_flagged():
    detector = RubberStampDetector()
    detector.extend(_records(60, "bob", latency=1.0, rate=1.0, jitter=0.2))
    flagged = detector.hollow_approvers()
    assert [s.approver for s in flagged] == ["bob"]
    assert "HOLLOW" in flagged[0].summary()


def test_speed_alone_does_not_convict():
    """Someone experienced answers quickly; that is not rubber-stamping."""
    detector = RubberStampDetector()
    detector.extend(_records(60, "carol", latency=2.0, rate=0.6, jitter=1.5))
    assert detector.hollow_approvers() == []


def test_approving_everything_slowly_does_not_convict():
    """A genuinely healthy fleet produces near-total approval."""
    detector = RubberStampDetector()
    detector.extend(_records(60, "dave", latency=300.0, rate=1.0, jitter=200.0))
    assert detector.hollow_approvers() == []


def test_too_few_decisions_yields_no_verdict():
    detector = RubberStampDetector(min_decisions=20)
    detector.extend(_records(5, "eve", latency=1.0, rate=1.0, jitter=0.1))
    assert detector.hollow_approvers() == []
    assert detector.stats()[0].hollow_score == 0.0


def test_stats_rank_the_most_suspicious_first():
    detector = RubberStampDetector()
    detector.extend(_records(60, "reader", latency=120.0, rate=0.7, jitter=90.0))
    detector.extend(_records(60, "clicker", latency=1.0, rate=1.0, jitter=0.2))
    assert detector.stats()[0].approver == "clicker"


# -------------------------------------------------------------------- engine


def _env(i, *, healthy=True):
    return Envelope(
        sender="agent-a",
        recipient="tool-search" if healthy else "tool-exfil",
        intent="core",
        action="query" if healthy else "bulk_export",
        timestamp=float(i),
        signature_valid=healthy,
        credential_valid=healthy,
        audit_proof=f"merkle:{i}" if healthy else None,
    )


def _engine_with(outcome, **kwargs):
    def verifier(agent_id, decision):
        return Verification(
            agent_id=agent_id,
            timestamp=decision.timestamp,
            compromised=outcome is Outcome.REJECTED,
            outcome=outcome,
            approver="alice",
            latency_seconds=45.0,
        )

    return AttestEngine(
        verifier=verifier,
        shadow=False,
        policy_params=PolicyParams(cooldown_seconds=0.0),
        **kwargs,
    )


def _drive(engine, steps=400):
    for i in range(120):
        engine.observe(_env(i))
    for i in range(120, steps):
        engine.observe(_env(i, healthy=False))
    return engine


def test_approval_leaves_the_agent_above_the_prior():
    engine = _drive(_engine_with(Outcome.APPROVED))
    assert engine.thresholds.offset("agent-a") < 0.0
    assert len(engine.rubber_stamp) > 0


def test_rejection_leaves_the_agent_below_the_prior():
    engine = _drive(_engine_with(Outcome.REJECTED))
    assert engine.thresholds.offset("agent-a") > 0.0


def test_a_timeout_moves_nothing():
    engine = _drive(_engine_with(Outcome.TIMEOUT))
    assert engine.thresholds.offset("agent-a") == 0.0


def test_approval_and_rejection_do_not_leave_the_same_state():
    """The flaw this phase exists to fix."""
    approved = _drive(_engine_with(Outcome.APPROVED))
    rejected = _drive(_engine_with(Outcome.REJECTED))
    assert approved.trust_of("agent-a") != rejected.trust_of("agent-a")


def test_a_verifier_returning_nothing_is_tolerated():
    engine = AttestEngine(
        verifier=lambda agent_id, decision: None,
        shadow=False,
        policy_params=PolicyParams(cooldown_seconds=0.0),
    )
    _drive(engine)
    assert engine.thresholds.offset("agent-a") == 0.0


# ---------------------------------------------------------------- loop safety


def test_the_loop_converges_rather_than_oscillating():
    for reviewer in ("attentive", "rubber-stamp", "absent"):
        outcome = run_loop(reviewer, LoopScenario(steps=2000), seed=0)
        assert outcome.offset_reversals == 0, reviewer


def test_latitude_never_escapes_the_bound():
    policy = ApprovalPolicy(threshold_bound=0.15)
    outcome = run_loop("rubber-stamp", LoopScenario(steps=4000), policy=policy, seed=0)
    assert all(abs(v) <= 0.15 + 1e-9 for v in outcome.offsets.values())


def test_rubber_stamping_is_caught_and_absence_is_not_mistaken_for_it():
    scenario = LoopScenario(steps=4000)
    assert run_loop("rubber-stamp", scenario, seed=0).hollow_flagged
    # An absent reviewer is a different failure - slow, not fast - and
    # conflating the two would send operators after the wrong problem.
    assert not run_loop("absent", scenario, seed=0).hollow_flagged
    assert not run_loop("attentive", scenario, seed=0).hollow_flagged


def test_the_loop_does_not_make_rubber_stamping_worse():
    """It must not actively harm in the case it cannot help."""
    scenario = LoopScenario(steps=4000)
    off = run_loop(
        "rubber-stamp", scenario, policy=ApprovalPolicy(threshold_step=0.0), seed=1
    )
    on = run_loop("rubber-stamp", scenario, policy=ApprovalPolicy(), seed=1)
    assert on.exposure <= off.exposure + 0.05


def test_an_attentive_reviewer_contains_most_episodes():
    outcome = run_loop("attentive", LoopScenario(steps=4000), seed=0)
    assert outcome.contained / outcome.episodes > 0.8
    assert outcome.exposure < 0.3
