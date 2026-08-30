import pytest

from attest import Action, Decision
from attest.policy import Reason
from attest.packet import (
    PacketBuilder,
    Reversibility,
    Step,
    Tier,
    ToolCatalog,
    ToolRisk,
    digest,
)


def _catalog():
    return (
        ToolCatalog()
        .declare(
            "search",
            ToolRisk(
                reversibility=Reversibility.REVERSIBLE,
                magnitude=0.05,
                description="Read-only search over public documentation.",
            ),
        )
        .declare(
            "draft_email",
            ToolRisk(
                reversibility=Reversibility.RECOVERABLE,
                magnitude=0.3,
                description="Writes a draft. Not sent.",
            ),
        )
        .declare(
            "wire_transfer",
            ToolRisk(
                reversibility=Reversibility.IRREVERSIBLE,
                magnitude=1.0,
                sensitive=True,
                description="Moves money out of the operating account.",
            ),
        )
    )


def _decision(agent="agent-7", trust=0.9, effective=None, chain=()):
    return Decision(
        agent_id=agent,
        timestamp=1000.0,
        p=0.1,
        trust=trust,
        action=Action.VERIFY,
        reason=Reason.BELOW_THRESHOLD,
        effective_trust=effective if effective is not None else trust,
        target=chain[0] if chain else agent,
        chain=chain or (agent,),
    )


# ------------------------------------------------------------------ catalogue


def test_an_uncatalogued_tool_is_treated_as_dangerous():
    """Failing closed is what stops an agent reaching for something unlisted."""
    risk = ToolCatalog().risk_for("mystery_tool")
    assert risk.reversibility is Reversibility.UNKNOWN
    assert risk.magnitude == 1.0
    assert risk.sensitive


def test_catalogue_returns_declared_risk():
    catalog = _catalog()
    assert catalog.risk_for("search").magnitude == 0.05
    assert catalog.known("search")
    assert not catalog.known("nope")
    assert len(catalog) == 3


def test_magnitude_must_be_a_fraction():
    with pytest.raises(ValueError, match="magnitude"):
        ToolRisk(magnitude=2.0)


# ----------------------------------------------------------------- escalation


def test_a_routine_reversible_familiar_action_needs_nobody():
    builder = PacketBuilder(catalog=_catalog())
    for i in range(5):
        builder.observe("agent-7", "search", "docs", float(i), True)

    assert builder.assess("agent-7", "search", trust=0.9).tier is Tier.AUTO


def test_an_irreversible_novel_high_value_action_reaches_an_authority():
    builder = PacketBuilder(catalog=_catalog())
    for i in range(5):
        builder.observe("agent-7", "search", "docs", float(i), True)

    risk = builder.assess("agent-7", "wire_transfer", trust=0.9)
    assert risk.tier is Tier.AUTHORITY
    assert "cannot be undone (irreversible)" in risk.drivers
    assert "unlike anything this agent has done before" in risk.drivers


def test_no_single_axis_escalates_on_its_own():
    """Magnitude, novelty and irreversibility each alone are ordinary."""
    builder = PacketBuilder(catalog=_catalog())
    for i in range(5):
        builder.observe("agent-7", "wire_transfer", "acct", float(i), True)

    # Large and irreversible, but entirely routine for this agent.
    familiar = builder.assess("agent-7", "wire_transfer", trust=0.95)
    assert familiar.novelty == 0.0
    assert familiar.tier is Tier.AUTO

    # Novel, but trivial and reversible.
    novel_but_harmless = builder.assess("agent-7", "search", trust=0.95)
    assert novel_but_harmless.novelty == 1.0
    assert novel_but_harmless.tier is Tier.AUTO


def test_low_trust_raises_severity_but_cannot_invent_it():
    """A distrusted agent reading a public doc is still reading a public doc."""
    builder = PacketBuilder(catalog=_catalog())
    for i in range(5):
        builder.observe("agent-7", "search", "docs", float(i), True)

    trusted = builder.assess("agent-7", "search", trust=0.95)
    distrusted = builder.assess("agent-7", "search", trust=0.05)
    assert distrusted.score > trusted.score
    assert distrusted.tier is Tier.AUTO


def test_a_brand_new_agent_is_not_escalated_for_everything():
    """With no history, nothing can be unlike it."""
    builder = PacketBuilder(catalog=_catalog())
    assert builder.novelty("fresh", "search") == 0.5
    assert builder.assess("fresh", "search", trust=0.5).tier is Tier.AUTO


def test_thresholds_must_be_ordered():
    with pytest.raises(ValueError, match="owner_threshold"):
        PacketBuilder(owner_threshold=0.9, authority_threshold=0.2)


# -------------------------------------------------------------------- packets


def test_a_packet_carries_what_a_reviewer_needs():
    builder = PacketBuilder(catalog=_catalog())
    for i in range(5):
        builder.observe("agent-7", "search", "docs", float(i), True)

    packet = builder.build(
        _decision(),
        tool="wire_transfer",
        resource="acct-9912",
        arguments={"amount": 50000, "to": "vendor-3"},
        intent="pay_invoice",
    )

    text = packet.render()
    assert "wire_transfer" in text
    assert "acct-9912" in text
    assert "Moves money out of the operating account." in text
    assert "irreversible" in text
    assert "what led here" in text
    assert "abandoned, not allowed" in text


def test_arguments_are_digested_not_carried():
    """A payload routinely contains exactly what should not go in a chat."""
    builder = PacketBuilder(catalog=_catalog())
    packet = builder.build(
        _decision(),
        tool="wire_transfer",
        arguments={"iban": "GB29NWBK60161331926819", "amount": 50000},
    )
    assert "GB29NWBK" not in packet.render()
    assert "GB29NWBK" not in str(packet.to_dict())
    assert packet.argument_digest == digest(
        {"iban": "GB29NWBK60161331926819", "amount": 50000}
    )


def test_digest_is_stable_and_order_independent():
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})
    assert digest({"a": 1}) != digest({"a": 2})


def test_digest_survives_unserialisable_arguments():
    assert digest(object()) != ""


def test_a_delegated_packet_names_the_weak_link():
    builder = PacketBuilder(catalog=_catalog())
    packet = builder.build(
        _decision(agent="worker", trust=0.95, effective=0.1, chain=("boss", "worker")),
        tool="wire_transfer",
    )
    text = packet.render()
    assert packet.delegated
    assert "the weak link is boss, not the sender" in text
    assert "chain 0.100" in text


def test_the_trail_includes_allowed_actions_not_only_held_ones():
    """A reviewer shown only refusals sees an agent that only does bad things."""
    builder = PacketBuilder(catalog=_catalog(), history=4)
    builder.observe("agent-7", "search", "docs", 1.0, True)
    builder.observe("agent-7", "draft_email", "vendor", 2.0, True)
    builder.observe("agent-7", "wire_transfer", "acct", 3.0, False)

    packet = builder.build(_decision(), tool="wire_transfer")
    marks = [s.allowed for s in packet.recent]
    assert True in marks and False in marks


def test_the_trail_is_bounded():
    builder = PacketBuilder(catalog=_catalog(), history=3)
    for i in range(20):
        builder.observe("agent-7", "search", "docs", float(i), True)
    assert len(builder.build(_decision(), tool="search").recent) == 3


def test_a_packet_expires():
    builder = PacketBuilder(catalog=_catalog(), hold_seconds=120.0)
    packet = builder.build(_decision(), tool="search")
    assert packet.expires_at == pytest.approx(1000.0 + 120.0)
    assert packet.seconds_remaining == pytest.approx(120.0)


def test_packet_serialises_for_a_ui():
    builder = PacketBuilder(catalog=_catalog())
    body = builder.build(_decision(), tool="wire_transfer").to_dict()
    for key in ("tier", "risk_score", "reversibility", "drivers", "chain", "recent"):
        assert key in body


def test_step_renders_its_verdict():
    assert "held" in Step(at=0.0, tool="t", resource="r", allowed=False).render()
    assert "ok" in Step(at=0.0, tool="t", resource="r", allowed=True).render()
