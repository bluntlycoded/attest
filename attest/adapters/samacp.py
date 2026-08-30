"""SAMACP envelope adapter.

Turns a signed SAMACP envelope into an :class:`attest.Envelope`, performing the
three checks the risk scorer weights most heavily and which nothing else in the
pipeline can establish:

signature
    URDNA2015-canonicalise the envelope minus its signature, audit proof and
    credential, then verify the Ed25519 signature against the sender's public
    key as registered with the Agent Name Service.
credential
    Decode the attached verifiable credential, check it has not expired, verify
    its RS256 signature against the ANS issuer key, and confirm the ANS has not
    revoked its ``jti``.
audit proof
    Recompute the Merkle path from the canonical leaf up to the claimed root.

Unverifiable is not the same as invalid
---------------------------------------
If the ANS is unreachable, we cannot resolve a sender's key - but an ANS outage
is not evidence that an agent has been compromised. Treating "unknown" as
"failed" would drive every agent's trust to zero simultaneously and spend the
entire verification budget on an infrastructure problem.

So the default is to fail open on *unknown* and fail closed on *failed*: a
signature that verifies incorrectly is bad evidence, a signature that cannot be
checked is not evidence at all. Every unknown is counted in
:attr:`SamacpAdapter.unknowns` so an operator can see when the engine is flying
blind. Set ``unknown_is_invalid=True`` to reverse this if your threat model
prefers it.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..evidence import Envelope

__all__ = ["VerificationOutcome", "AnsClient", "SamacpAdapter", "merkle_verify"]

# Mirrors prot/spec/core-context.jsonld. Inlined rather than read from disk so
# the adapter works without a checkout of the protocol repo beside it.
CORE_CONTEXT: dict[str, str] = {
    "msg_id": "http://samacp.org/msg_id",
    "from": "http://samacp.org/from",
    "to": "http://samacp.org/to",
    "intent": "http://samacp.org/intent",
    "action": "http://samacp.org/action",
    "payload": "http://samacp.org/payload",
    "timestamp": "http://samacp.org/timestamp",
    "signature": "http://samacp.org/signature",
    "audit_proof": "http://samacp.org/audit_proof",
}

# Fields excluded from the signed form, matching the sender's canonicalisation.
_UNSIGNED_FIELDS = ("signature", "audit_proof", "vc")


class VerificationOutcome(str, Enum):
    """Result of one check."""

    VERIFIED = "verified"
    FAILED = "failed"
    UNKNOWN = "unknown"

    def as_bool(self, *, unknown_is_invalid: bool) -> bool:
        """Collapse to the boolean the risk scorer consumes."""
        if self is VerificationOutcome.VERIFIED:
            return True
        if self is VerificationOutcome.FAILED:
            return False
        return not unknown_is_invalid


def _require(module: str, extra: str = "samacp"):
    """Import a lazily-required dependency with an actionable error."""
    try:
        return __import__(module, fromlist=["*"])
    except ImportError as exc:  # pragma: no cover - exercised only when unset up
        raise ImportError(
            f"the SAMACP adapter needs {module!r}; "
            f'install it with: pip install -e ".[{extra}]"'
        ) from exc


def canonicalize(envelope: dict[str, Any]) -> bytes:
    """Produce the exact byte string the sender signed.

    Drops the signature, audit proof and credential, injects the core JSON-LD
    context, and normalises with URDNA2015 to N-Quads. Any deviation here makes
    every signature appear invalid, so this must track the sender exactly.
    """
    jsonld = _require("pyld.jsonld")
    env = {k: v for k, v in envelope.items() if k not in _UNSIGNED_FIELDS}
    env["@context"] = CORE_CONTEXT
    normalized = jsonld.normalize(
        env, {"algorithm": "URDNA2015", "format": "application/n-quads"}
    )
    return normalized.encode()


def merkle_verify(leaf_hex: str, proof: list[dict[str, Any]], root_hex: str) -> bool:
    """Recompute a Merkle path from ``leaf_hex`` and compare against ``root_hex``.

    Note the flag name in the wire format is misleading: ``is_right_sibling`` is
    set when the *current node* is the right child, so the sibling goes on the
    left. Reading it the other way round silently fails every proof.
    """
    cur = leaf_hex
    for step in proof:
        sibling = step["sibling"]
        if step.get("is_right_sibling"):
            cur = hashlib.sha256((sibling + cur).encode()).hexdigest()
        else:
            cur = hashlib.sha256((cur + sibling).encode()).hexdigest()
    return cur == root_hex


@dataclass
class AnsClient:
    """Read-only client for the Agent Name Service.

    Public keys are cached because they change only on a committed key
    rollover, which is rare and explicit. Revocation status is deliberately not
    cached - a revoked credential has to take effect immediately.

    Args:
        base_url: Root URL of the ANS.
        timeout: Per-request timeout in seconds.
    """

    base_url: str = "http://localhost:5000"
    timeout: float = 2.0
    _keys: dict[str, str | None] = field(default_factory=dict, init=False)
    _issuer_pem: bytes | None = field(default=None, init=False)

    def _get(self, path: str) -> Any:
        requests = _require("requests")
        try:
            response = requests.get(
                f"{self.base_url.rstrip('/')}{path}", timeout=self.timeout
            )
        except Exception:
            return None
        if response.status_code != 200:
            return None
        try:
            return response.json()
        except ValueError:
            return response.text

    def public_key(self, agent_id: str, *, refresh: bool = False) -> str | None:
        """Ed25519 signing key for ``agent_id``, hex encoded, or None if unknown."""
        if not refresh and agent_id in self._keys:
            return self._keys[agent_id]
        agent = self._get(f"/agent/{agent_id}")
        key = agent.get("pubkey_hex") if isinstance(agent, dict) else None
        self._keys[agent_id] = key
        return key

    def issuer_pem(self) -> bytes | None:
        """PEM-encoded RSA public key the ANS signs credentials with."""
        if self._issuer_pem is None:
            pem = self._get("/issuer_pub")
            if isinstance(pem, str):
                self._issuer_pem = pem.encode()
        return self._issuer_pem

    def credential_revoked(self, jti: str) -> bool | None:
        """Whether ``jti`` is revoked, or None if the ANS could not be reached."""
        status = self._get(f"/vc_status/{jti}")
        if not isinstance(status, dict):
            return None
        return bool(status.get("revoked"))


@dataclass
class SamacpAdapter:
    """Maps SAMACP envelopes to scored :class:`attest.Envelope` values.

    Args:
        ans: ANS client used to resolve keys and revocation. None disables both
            signature and credential verification, which leaves every check
            UNKNOWN.
        unknown_is_invalid: Whether checks that could not be performed count as
            failures. Defaults to False - see the module docstring.
        clock_skew: Seconds of tolerance allowed on credential expiry.
    """

    ans: AnsClient | None = None
    unknown_is_invalid: bool = False
    clock_skew: float = 30.0
    unknowns: dict[str, int] = field(
        default_factory=lambda: {"signature": 0, "credential": 0, "audit": 0},
        init=False,
    )

    def verify_signature(self, raw: dict[str, Any]) -> VerificationOutcome:
        """Check the envelope's Ed25519 signature against its registered key."""
        signature = raw.get("signature")
        sender = raw.get("from")
        if not signature or not sender or self.ans is None:
            return VerificationOutcome.UNKNOWN

        key_hex = self.ans.public_key(str(sender))
        if not key_hex:
            return VerificationOutcome.UNKNOWN

        import base64

        nacl_signing = _require("nacl.signing")
        nacl_exceptions = _require("nacl.exceptions")
        try:
            canon = canonicalize(raw)
        except Exception:
            # A malformed envelope cannot be canonicalised, and that is a
            # property of the message rather than of our infrastructure.
            return VerificationOutcome.FAILED

        try:
            verify_key = nacl_signing.VerifyKey(bytes.fromhex(key_hex))
            verify_key.verify(canon, base64.b64decode(signature))
        except (nacl_exceptions.BadSignatureError, ValueError, TypeError):
            return VerificationOutcome.FAILED
        return VerificationOutcome.VERIFIED

    def verify_credential(self, raw: dict[str, Any]) -> VerificationOutcome:
        """Check the attached verifiable credential's signature, expiry and revocation."""
        token = raw.get("vc")
        if not token:
            # No credential attached at all. That is a real absence, not an
            # infrastructure gap, so it counts against the sender.
            return VerificationOutcome.FAILED
        if self.ans is None:
            return VerificationOutcome.UNKNOWN

        jwt = _require("jwt")
        issuer_pem = self.ans.issuer_pem()
        if issuer_pem is None:
            return VerificationOutcome.UNKNOWN

        try:
            claims = jwt.decode(
                token,
                issuer_pem,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
        except jwt.ExpiredSignatureError:
            return VerificationOutcome.FAILED
        except jwt.InvalidTokenError:
            return VerificationOutcome.FAILED

        expiry = claims.get("exp")
        if expiry is not None and time.time() > float(expiry) + self.clock_skew:
            return VerificationOutcome.FAILED

        jti = claims.get("jti")
        if not jti:
            return VerificationOutcome.FAILED
        revoked = self.ans.credential_revoked(str(jti))
        if revoked is None:
            return VerificationOutcome.UNKNOWN
        return (
            VerificationOutcome.FAILED if revoked else VerificationOutcome.VERIFIED
        )

    def verify_audit(self, raw: dict[str, Any]) -> tuple[VerificationOutcome, str | None]:
        """Check the envelope's Merkle inclusion proof.

        Returns:
            The outcome and, when it verifies, a stable reference of the form
            ``merkle:<index>:<leaf>`` for the decision log.
        """
        proof_block = raw.get("audit_proof")
        if not isinstance(proof_block, dict):
            return VerificationOutcome.FAILED, None

        proof = proof_block.get("proof")
        root = proof_block.get("root")
        if proof is None or not root:
            return VerificationOutcome.FAILED, None

        try:
            leaf = hashlib.sha256(canonicalize(raw)).hexdigest()
        except Exception:
            return VerificationOutcome.FAILED, None

        if not merkle_verify(leaf, list(proof), str(root)):
            return VerificationOutcome.FAILED, None
        return VerificationOutcome.VERIFIED, f"merkle:{proof_block.get('index')}:{leaf}"

    def to_envelope(self, raw: dict[str, Any]) -> Envelope:
        """Convert and verify one SAMACP envelope.

        Raises:
            ValueError: If the envelope lacks the fields needed to attribute it
                to a sender at all.
        """
        sender = raw.get("from")
        recipient = raw.get("to")
        if not sender or not recipient:
            raise ValueError("SAMACP envelope must carry both 'from' and 'to'")

        signature = self.verify_signature(raw)
        credential = self.verify_credential(raw)
        audit, audit_ref = self.verify_audit(raw)

        for name, outcome in (
            ("signature", signature),
            ("credential", credential),
            ("audit", audit),
        ):
            if outcome is VerificationOutcome.UNKNOWN:
                self.unknowns[name] += 1

        return Envelope(
            sender=str(sender),
            recipient=str(recipient),
            intent=str(raw.get("intent") or "unknown"),
            action=str(raw.get("action") or "unknown"),
            timestamp=float(raw.get("timestamp") or time.time()),
            signature_valid=signature.as_bool(
                unknown_is_invalid=self.unknown_is_invalid
            ),
            credential_valid=credential.as_bool(
                unknown_is_invalid=self.unknown_is_invalid
            ),
            audit_proof=audit_ref,
        )

    def to_envelope_json(self, payload: str | bytes) -> Envelope:
        """Convert a raw JSON envelope, as received off the wire."""
        return self.to_envelope(json.loads(payload))
