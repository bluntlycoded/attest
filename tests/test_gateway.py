import pytest

from attest import AttestEngine, PolicyParams
from attest.approval import Outcome
from attest.gateway import (
    AttestGateway,
    ToolCall,
    Verdict,
    from_mcp_request,
)
from attest.packet import PacketBuilder, Reversibility, Tier, ToolCatalog, ToolRisk


def _gateway(**kwargs):
    catalog = (
        ToolCatalog()
        .declare(
            "search",
            ToolRisk(
                reversibility=Reversibility.REVERSIBLE,
                magnitude=0.05,
                description="Read-only search.",
            ),
        )
        .declare(
            "wire_transfer",
            ToolRisk(
                reversibility=Reversibility.IRREVERSIBLE,
                magnitude=1.0,
                sensitive=True,
                description="Moves money.",
            ),
        )
    )
    engine = AttestEngine(policy_params=PolicyParams(cooldown_seconds=0.0))
    return AttestGateway(
        engine=engine, builder=PacketBuilder(catalog=catalog), **kwargs
    )


def _call(tool="search", at=0.0, agent="agent-7", **kwargs):
    return ToolCall(
        agent_id=agent, tool=tool, timestamp=at, resource="docs", **kwargs
    )


def _settle(gateway, n=60, agent="agent-7"):
    """Give an agent a clean, familiar history."""
    for i in range(n):
        gateway.evaluate(_call(at=float(i), agent=agent))


# ------------------------------------------------------------------- verdicts


def test_a_routine_call_from_a_trusted_agent_is_allowed():
    gateway = _gateway()
    _settle(gateway)
    decision = gateway.evaluate(_call(at=100.0))

    assert decision.verdict is Verdict.ALLOW
    assert decision.allowed
    assert decision.tier is Tier.AUTO
    assert "routine" in decision.explain


def test_a_consequential_novel_call_is_held_even_from_a_trusted_agent():
    """Trust is about the agent; this is about the action."""
    gateway = _gateway()
    _settle(gateway)
    decision = gateway.evaluate(_call(tool="wire_transfer", at=100.0))

    assert decision.verdict is Verdict.HOLD
    assert decision.tier is Tier.AUTHORITY
    assert decision.request_id is not None
    assert decision.packet is not None
    assert "cannot be undone" in decision.explain


def test_an_uncatalogued_tool_is_held_rather_than_waved_through():
    gateway = _gateway()
    _settle(gateway)
    assert gateway.evaluate(_call(tool="mystery", at=100.0)).verdict is Verdict.HOLD


def test_a_deeply_distrusted_agent_is_refused_without_asking():
    """Re-asking after a rejection is how a reviewer learns to stop reading."""
    gateway = _gateway(deny_below=0.4)
    _settle(gateway)
    for i in range(100, 300):
        decision = gateway.evaluate(
            _call(at=float(i), authenticated=False, credential_valid=False, logged=False)
        )
        if decision.verdict is Verdict.DENY:
            break

    assert decision.verdict is Verdict.DENY
    assert "floor" in decision.explain
    assert decision.request_id is None


def test_deny_below_is_validated():
    with pytest.raises(ValueError, match="deny_below"):
        _gateway(deny_below=1.5)


def test_a_scheduled_verification_holds_the_call_by_default():
    gateway = _gateway(deny_below=0.0)
    _settle(gateway)
    held = None
    for i in range(100, 400):
        decision = gateway.evaluate(
            _call(at=float(i), authenticated=False, credential_valid=False, logged=False)
        )
        if decision.verdict is Verdict.HOLD and "scheduled check" in decision.explain:
            held = decision
            break
    assert held is not None


def test_a_scheduled_verification_need_not_block_the_call():
    """Shadow rollouts want the check to happen without stopping work."""
    gateway = _gateway(deny_below=0.0, hold_on_verify=False)
    _settle(gateway)
    verdicts = {
        gateway.evaluate(
            _call(at=float(i), authenticated=False, credential_valid=False, logged=False)
        ).verdict
        for i in range(100, 300)
    }
    assert Verdict.HOLD not in verdicts


# ----------------------------------------------------------------- resolution


def test_approval_releases_a_held_call():
    gateway = _gateway()
    _settle(gateway)
    held = gateway.evaluate(_call(tool="wire_transfer", at=100.0))

    assert gateway.status(held.request_id) is Verdict.HOLD
    verdict = gateway.decide(held.request_id, "alice", Outcome.APPROVED, 130.0)
    assert verdict is Verdict.ALLOW
    assert gateway.status(held.request_id) is Verdict.ALLOW


def test_rejection_refuses_a_held_call_and_tightens_the_agent():
    gateway = _gateway()
    _settle(gateway)
    held = gateway.evaluate(_call(tool="wire_transfer", at=100.0))

    assert gateway.decide(held.request_id, "alice", Outcome.REJECTED, 130.0) is Verdict.DENY
    assert gateway.engine.thresholds.offset("agent-7", 130.0) > 0


def test_an_unanswered_hold_ends_as_a_denial():
    """Fail closed, or the gateway is most permissive when reviewers drown."""
    gateway = _gateway()
    _settle(gateway)
    held = gateway.evaluate(_call(tool="wire_transfer", at=100.0))

    expired = gateway.sweep(100.0 + 301.0)

    assert expired == [held.request_id]
    assert gateway.status(held.request_id) is Verdict.DENY


def test_a_timeout_does_not_widen_the_agent_s_latitude():
    gateway = _gateway()
    _settle(gateway)
    gateway.evaluate(_call(tool="wire_transfer", at=100.0))
    gateway.sweep(500.0)
    assert gateway.engine.thresholds.offset("agent-7", 500.0) == 0.0


def test_polling_an_unknown_request_is_an_error():
    with pytest.raises(KeyError, match="unknown approval request"):
        _gateway().status("apr-999999")


def test_approvals_feed_the_rubber_stamp_detector():
    gateway = _gateway()
    _settle(gateway)
    for i in range(30):
        held = gateway.evaluate(_call(tool="wire_transfer", at=100.0 + i * 10))
        if held.request_id:
            gateway.decide(held.request_id, "clicker", Outcome.APPROVED, 101.0 + i * 10)

    stats = gateway.engine.rubber_stamp.stats()
    assert stats and stats[0].approver == "clicker"


# ---------------------------------------------------------------- delegation


def test_a_held_call_names_the_chain_s_weak_link():
    gateway = _gateway()
    _settle(gateway, agent="boss")
    _settle(gateway, agent="worker")

    for i in range(200, 400):
        gateway.evaluate(
            _call(
                at=float(i),
                agent="boss",
                authenticated=False,
                credential_valid=False,
                logged=False,
            )
        )

    held = gateway.evaluate(
        _call(tool="wire_transfer", at=500.0, agent="worker", on_behalf_of=("boss",))
    )
    assert held.verdict in (Verdict.HOLD, Verdict.DENY)
    if held.packet:
        assert held.packet.target == "boss"


# ---------------------------------------------------------------------- MCP


def test_mcp_request_maps_to_a_tool_call():
    call = from_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "wire_transfer",
                "arguments": {"amount": 5000, "target": "acct-9"},
            },
        },
        agent_id="agent-7",
        timestamp=42.0,
    )

    assert call.agent_id == "agent-7"
    assert call.tool == "wire_transfer"
    assert call.resource == "acct-9"
    assert call.timestamp == 42.0


def test_identity_is_never_read_from_the_payload():
    """A request that could name its own caller lets any agent be any other."""
    call = from_mcp_request(
        {"params": {"name": "search", "arguments": {"agent_id": "admin"}}},
        agent_id="agent-7",
        timestamp=0.0,
    )
    assert call.agent_id == "agent-7"


def test_a_malformed_mcp_request_does_not_crash_the_gateway():
    call = from_mcp_request({}, agent_id="agent-7", timestamp=0.0)
    assert call.tool == "unknown"
    # An unknown tool fails closed, so this ends up in front of a person.
    gateway = _gateway()
    assert gateway.evaluate(call).verdict is Verdict.HOLD
