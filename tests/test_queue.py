import pytest

from attest import Action, AttestEngine, Decision, Envelope
from attest.approval import Outcome
from attest.packet import PacketBuilder, Reversibility, Tier, ToolCatalog, ToolRisk
from attest.policy import Reason
from attest.queue import ApprovalQueue


def _builder():
    catalog = ToolCatalog().declare(
        "wire_transfer",
        ToolRisk(
            reversibility=Reversibility.IRREVERSIBLE,
            magnitude=1.0,
            sensitive=True,
            description="Moves money.",
        ),
    )
    return PacketBuilder(catalog=catalog, hold_seconds=300.0)


def _packet(builder, agent="agent-7", at=1000.0):
    decision = Decision(
        agent_id=agent,
        timestamp=at,
        p=0.9,
        trust=0.3,
        action=Action.VERIFY,
        reason=Reason.BELOW_THRESHOLD,
        effective_trust=0.3,
        target=agent,
        chain=(agent,),
    )
    return builder.build(decision, tool="wire_transfer", resource="acct-1")


def test_opening_a_request_makes_it_pending():
    queue = ApprovalQueue()
    request = queue.open(_packet(_builder()))

    assert request.request_id.startswith("apr-")
    assert not request.resolved
    assert queue.pending() == [request]
    assert len(queue) == 1


def test_deciding_records_the_answer_and_the_latency():
    queue = ApprovalQueue()
    request = queue.open(_packet(_builder()))

    record = queue.decide(request.request_id, "alice", Outcome.APPROVED, 1045.0)

    assert record.approver == "alice"
    assert record.outcome is Outcome.APPROVED
    assert record.latency_seconds == pytest.approx(45.0)
    assert queue.pending() == []


def test_a_request_cannot_be_answered_twice():
    """Approval records are audit evidence; overwritable evidence is not."""
    queue = ApprovalQueue()
    request = queue.open(_packet(_builder()))
    queue.decide(request.request_id, "alice", Outcome.APPROVED, 1010.0)

    with pytest.raises(ValueError, match="already approved by alice"):
        queue.decide(request.request_id, "bob", Outcome.REJECTED, 1020.0)


def test_an_expired_request_cannot_be_answered_late():
    queue = ApprovalQueue()
    request = queue.open(_packet(_builder()))
    with pytest.raises(ValueError, match="expired"):
        queue.decide(request.request_id, "alice", Outcome.APPROVED, 9999.0)


def test_expiry_produces_a_timeout_never_an_approval():
    """Silence is not consent."""
    queue = ApprovalQueue()
    queue.open(_packet(_builder()))

    timed_out = queue.expire(1301.0)

    assert len(timed_out) == 1
    assert timed_out[0].outcome is Outcome.TIMEOUT
    assert queue.pending() == []


def test_pending_hides_expired_requests_when_given_a_clock():
    queue = ApprovalQueue()
    queue.open(_packet(_builder()))
    assert queue.pending(now=1100.0)
    assert queue.pending(now=1400.0) == []


def test_a_reviewer_can_only_approve_or_reject():
    queue = ApprovalQueue()
    request = queue.open(_packet(_builder()))
    for outcome in (Outcome.TIMEOUT, Outcome.FAILED, Outcome.UNKNOWN):
        with pytest.raises(ValueError, match="can only approve or reject"):
            queue.decide(request.request_id, "alice", outcome, 1010.0)


def test_unknown_request_is_an_error():
    with pytest.raises(KeyError, match="unknown approval request"):
        ApprovalQueue().decide("apr-999999", "alice", Outcome.APPROVED, 0.0)


def test_requests_can_be_filtered_by_tier():
    queue = ApprovalQueue()
    queue.open(_packet(_builder()))
    assert queue.pending(tier=Tier.AUTHORITY)
    assert queue.pending(tier=Tier.OWNER) == []


def test_history_and_counts_track_the_queue():
    queue = ApprovalQueue()
    first = queue.open(_packet(_builder(), agent="a1"))
    queue.open(_packet(_builder(), agent="a2"))
    queue.decide(first.request_id, "alice", Outcome.APPROVED, 1010.0)
    queue.expire(1400.0)

    counts = queue.counts()
    assert counts["pending"] == 0
    assert counts["approved"] == 1
    assert counts["timeout"] == 1
    assert len(queue.history) == 2


def test_a_decided_request_is_still_retrievable():
    queue = ApprovalQueue()
    request = queue.open(_packet(_builder()))
    queue.decide(request.request_id, "alice", Outcome.APPROVED, 1010.0)
    assert queue.get(request.request_id).outcome is Outcome.APPROVED


# ---------------------------------------------------- end to end with the engine


def _env(i, *, healthy=True):
    return Envelope(
        sender="agent-7",
        recipient="tool-search" if healthy else "tool-exfil",
        intent="core",
        action="query" if healthy else "bulk_export",
        timestamp=float(i),
        signature_valid=healthy,
        credential_valid=healthy,
        audit_proof=f"merkle:{i}" if healthy else None,
    )


def test_an_answer_arriving_later_closes_the_loop():
    """The whole point of a decoupled flow: nobody blocks on a person."""
    engine = AttestEngine()
    queue = ApprovalQueue()
    builder = _builder()

    for i in range(150):
        engine.observe(_env(i))

    fired = None
    for i in range(150, 400):
        decision = engine.observe(_env(i, healthy=False))
        if decision.action is Action.VERIFY:
            fired = queue.open(
                builder.build(decision, tool="wire_transfer", resource="acct-1")
            )
            break

    assert fired is not None
    # The agent carried on while the request sat unanswered.
    record = queue.decide(fired.request_id, "alice", Outcome.REJECTED, fired.opened_at + 60)
    engine.resolve(
        record.agent_id,
        record.outcome,
        fired.opened_at + 60,
        approver=record.approver,
        latency_seconds=record.latency_seconds,
    )

    assert engine.thresholds.offset(record.agent_id, fired.opened_at + 60) > 0
    assert len(engine.rubber_stamp) == 1


def test_an_approval_arriving_later_leaves_the_agent_better_off():
    def run(outcome):
        engine = AttestEngine()
        for i in range(150):
            engine.observe(_env(i))
        engine.resolve("agent-7", outcome, 300.0, approver="alice", latency_seconds=30.0)
        return engine.trust_of("agent-7")

    idle = AttestEngine()
    for i in range(150):
        idle.observe(_env(i))

    assert run(Outcome.APPROVED) > idle.trust_of("agent-7", now=300.0)
    assert run(Outcome.REJECTED) < idle.trust_of("agent-7", now=300.0)


def test_a_timeout_resolved_out_of_band_changes_nothing():
    engine = AttestEngine()
    for i in range(150):
        engine.observe(_env(i))
    before = engine.trust_of("agent-7")
    engine.resolve("agent-7", Outcome.TIMEOUT, 300.0)
    assert engine.trust_of("agent-7") == pytest.approx(before)
    assert engine.thresholds.offset("agent-7", 300.0) == 0.0
