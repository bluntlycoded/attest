import base64
import hashlib
import json
import time

import pytest

from attest.adapters.samacp import (
    SamacpAdapter,
    VerificationOutcome,
    canonicalize,
    merkle_verify,
)

nacl_signing = pytest.importorskip("nacl.signing", reason="needs the samacp extra")
pytest.importorskip("pyld", reason="needs the samacp extra")


class FakeAns:
    """Stands in for the Agent Name Service."""

    def __init__(self, *, key=None, issuer=None, revoked=None, reachable=True):
        self._key = key
        self._issuer = issuer
        self._revoked = revoked or set()
        self.reachable = reachable

    def public_key(self, agent_id, *, refresh=False):
        return self._key if self.reachable else None

    def issuer_pem(self):
        return self._issuer if self.reachable else None

    def credential_revoked(self, jti):
        if not self.reachable:
            return None
        return jti in self._revoked


def _envelope(**overrides):
    env = {
        "msg_id": "m-1",
        "timestamp": 1000.0,
        "from": "agent-sender",
        "to": "agent-receiver",
        "intent": "greet",
        "action": "say_hello",
        "payload": {"text": "hi"},
    }
    env.update(overrides)
    return env


def _signed(key, **overrides):
    env = _envelope(**overrides)
    env["signature"] = base64.b64encode(key.sign(canonicalize(env)).signature).decode()
    return env


# ------------------------------------------------------------------- merkle


def _h(a, b):
    return hashlib.sha256((a + b).encode()).hexdigest()


def test_merkle_verifies_a_valid_path():
    leaves = [hashlib.sha256(f"leaf{i}".encode()).hexdigest() for i in range(4)]
    root = _h(_h(leaves[0], leaves[1]), _h(leaves[2], leaves[3]))
    # Path for leaf index 2: sibling is leaf3 on the right, then the left subtree.
    proof = [
        {"sibling": leaves[3], "is_right_sibling": False},
        {"sibling": _h(leaves[0], leaves[1]), "is_right_sibling": True},
    ]
    assert merkle_verify(leaves[2], proof, root)


def test_merkle_rejects_a_tampered_leaf():
    leaves = [hashlib.sha256(f"leaf{i}".encode()).hexdigest() for i in range(2)]
    root = _h(leaves[0], leaves[1])
    proof = [{"sibling": leaves[1], "is_right_sibling": False}]
    assert merkle_verify(leaves[0], proof, root)
    assert not merkle_verify("deadbeef", proof, root)


def test_merkle_side_flag_matters():
    """is_right_sibling means the current node is the right child, not the sibling."""
    a = hashlib.sha256(b"a").hexdigest()
    b = hashlib.sha256(b"b").hexdigest()
    root = _h(a, b)
    assert merkle_verify(a, [{"sibling": b, "is_right_sibling": False}], root)
    assert not merkle_verify(a, [{"sibling": b, "is_right_sibling": True}], root)


# ---------------------------------------------------------------- signature


def test_valid_signature_verifies():
    key = nacl_signing.SigningKey.generate()
    ans = FakeAns(key=key.verify_key.encode().hex())
    adapter = SamacpAdapter(ans=ans)
    assert adapter.verify_signature(_signed(key)) is VerificationOutcome.VERIFIED


def test_tampered_envelope_fails_signature():
    key = nacl_signing.SigningKey.generate()
    ans = FakeAns(key=key.verify_key.encode().hex())
    adapter = SamacpAdapter(ans=ans)

    env = _signed(key)
    env["action"] = "drop_tables"
    assert adapter.verify_signature(env) is VerificationOutcome.FAILED


def test_signature_from_the_wrong_key_fails():
    key, other = nacl_signing.SigningKey.generate(), nacl_signing.SigningKey.generate()
    adapter = SamacpAdapter(ans=FakeAns(key=other.verify_key.encode().hex()))
    assert adapter.verify_signature(_signed(key)) is VerificationOutcome.FAILED


def test_unreachable_ans_is_unknown_not_failed():
    key = nacl_signing.SigningKey.generate()
    adapter = SamacpAdapter(ans=FakeAns(key=None, reachable=False))
    assert adapter.verify_signature(_signed(key)) is VerificationOutcome.UNKNOWN


def test_attaching_signature_does_not_change_the_signed_bytes():
    """The signature and audit proof are excluded from canonicalisation."""
    env = _envelope()
    before = canonicalize(env)
    env["signature"] = "irrelevant"
    env["audit_proof"] = {"index": 3}
    env["vc"] = "some.jwt.token"
    assert canonicalize(env) == before


# --------------------------------------------------------------- outcomes


def test_unknown_fails_open_by_default():
    assert VerificationOutcome.UNKNOWN.as_bool(unknown_is_invalid=False) is True
    assert VerificationOutcome.UNKNOWN.as_bool(unknown_is_invalid=True) is False


def test_verified_and_failed_ignore_the_unknown_policy():
    for policy in (True, False):
        assert VerificationOutcome.VERIFIED.as_bool(unknown_is_invalid=policy) is True
        assert VerificationOutcome.FAILED.as_bool(unknown_is_invalid=policy) is False


# --------------------------------------------------------------- credential


def test_missing_credential_counts_against_the_sender():
    """An absent VC is a real absence, not an infrastructure gap."""
    adapter = SamacpAdapter(ans=FakeAns())
    assert adapter.verify_credential(_envelope()) is VerificationOutcome.FAILED


def test_credential_without_an_issuer_key_is_unknown():
    adapter = SamacpAdapter(ans=FakeAns(issuer=None))
    env = _envelope(vc="header.body.sig")
    assert adapter.verify_credential(env) is VerificationOutcome.UNKNOWN


# -------------------------------------------------------------- conversion


def test_to_envelope_maps_fields_and_verifications():
    key = nacl_signing.SigningKey.generate()
    adapter = SamacpAdapter(ans=FakeAns(key=key.verify_key.encode().hex()))

    raw = _signed(key)
    leaf = hashlib.sha256(canonicalize(raw)).hexdigest()
    raw["audit_proof"] = {"index": 0, "proof": [], "root": leaf}

    envelope = adapter.to_envelope(raw)
    assert envelope.sender == "agent-sender"
    assert envelope.recipient == "agent-receiver"
    assert envelope.intent == "greet"
    assert envelope.action == "say_hello"
    assert envelope.timestamp == 1000.0
    assert envelope.signature_valid is True
    assert envelope.audit_proof == f"merkle:0:{leaf}"
    # No credential was attached, so that check failed.
    assert envelope.credential_valid is False


def test_bad_merkle_root_drops_the_audit_reference():
    key = nacl_signing.SigningKey.generate()
    adapter = SamacpAdapter(ans=FakeAns(key=key.verify_key.encode().hex()))
    raw = _signed(key)
    raw["audit_proof"] = {"index": 0, "proof": [], "root": "0" * 64}
    assert adapter.to_envelope(raw).audit_proof is None


def test_unknowns_are_counted_for_the_operator():
    key = nacl_signing.SigningKey.generate()
    adapter = SamacpAdapter(ans=FakeAns(reachable=False))
    adapter.to_envelope(_signed(key, vc="a.b.c"))
    assert adapter.unknowns["signature"] == 1
    assert adapter.unknowns["credential"] == 1


def test_envelope_without_a_sender_is_rejected():
    adapter = SamacpAdapter()
    with pytest.raises(ValueError, match="'from' and 'to'"):
        adapter.to_envelope({"to": "b"})


def test_to_envelope_json_accepts_wire_bytes():
    adapter = SamacpAdapter()
    envelope = adapter.to_envelope_json(json.dumps(_envelope()).encode())
    assert envelope.sender == "agent-sender"


def test_missing_timestamp_defaults_to_now():
    adapter = SamacpAdapter()
    raw = _envelope()
    del raw["timestamp"]
    assert adapter.to_envelope(raw).timestamp == pytest.approx(time.time(), abs=5)
