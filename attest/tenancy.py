"""API keys, roles and tenant isolation.

A service that decides which agents to interrupt has to know who is asking.
Three separations matter, and they are not the same separation:

Tenants must not see each other
    Trust state, approvals and the tool catalogue are all per tenant. This is
    enforced by giving each tenant its own engine over a scoped store rather
    than by remembering to add a ``WHERE tenant_id = ?`` to every query.
    Filters get forgotten; a scoped store has nothing else to return.

Roles are not seniority, they are blast radius
    The gateway posting tool calls needs no ability to approve them, and the
    person approving needs no ability to rewrite the thresholds that decide
    what reaches them. An ingest credential sitting on every gateway node is
    the one most likely to leak, so it is also the one that can do least.

Keys are secrets and are stored as hashes
    Only a digest is written down. A stolen database yields nothing usable,
    and the plaintext is shown exactly once at issue.

Auth is required by default
    An unauthenticated deployment of a security control is worse than none,
    because it is trusted. ``ATTEST_BOOTSTRAP_KEY`` supplies the first
    credential from the environment - the usual way to hand a service its
    initial secret without writing one into a database that ships open.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import Enum

__all__ = ["Role", "Principal", "IssuedKey", "KeyStore", "hash_token"]

DEFAULT_TENANT = "default"
_PREFIX = "attest"


class Role(str, Enum):
    """What a credential is allowed to do."""

    INGEST = "ingest"
    """Submit traffic and tool calls. Cannot approve, read the fleet, or
    change settings. This is what sits on gateway nodes, so it is deliberately
    the least capable."""

    APPROVER = "approver"
    """Everything ingest can do, plus answering approval requests and reading
    the fleet. Cannot change thresholds - a reviewer who could widen the
    thresholds that decide what reaches them could quietly stop being asked."""

    ADMIN = "admin"
    """Everything, including configuration, the tool catalogue and key
    management."""

    @property
    def rank(self) -> int:
        return {Role.INGEST: 0, Role.APPROVER: 1, Role.ADMIN: 2}[self]

    def allows(self, required: "Role") -> bool:
        """Whether this role satisfies ``required``."""
        return self.rank >= required.rank


@dataclass(frozen=True)
class Principal:
    """Who is making a request."""

    key_id: str
    tenant_id: str
    role: Role
    label: str = ""

    def require(self, role: Role) -> None:
        """Raise if this principal is not permitted to act as ``role``."""
        if not self.role.allows(role):
            raise PermissionError(
                f"{self.role.value} credential cannot act as {role.value}"
            )


@dataclass(frozen=True)
class IssuedKey:
    """A freshly minted key. The token is returned once and never stored."""

    key_id: str
    token: str
    tenant_id: str
    role: Role
    label: str


def hash_token(token: str) -> str:
    """Digest a token for storage.

    A plain SHA-256 rather than a slow KDF: these are 256-bit random secrets,
    not human-chosen passwords, so there is no dictionary to make expensive.
    """
    return hashlib.sha256(token.encode()).hexdigest()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    key_id     TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    role       TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    last_used  REAL,
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys (tenant_id);
"""


class KeyStore:
    """Issues, verifies and revokes API keys.

    Args:
        connection: An open SQLite connection, shared with the rest of the
            service so keys live in the same file as everything else.
        bootstrap_token: Initial admin credential, from the environment. It is
            never written to the database, so rotating it means restarting
            with a different value rather than editing rows.
        bootstrap_tenant: Tenant the bootstrap credential administers.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        bootstrap_token: str | None = None,
        bootstrap_tenant: str = DEFAULT_TENANT,
    ) -> None:
        self._conn = connection
        self._lock = threading.Lock()
        self._bootstrap = bootstrap_token or None
        self._bootstrap_tenant = bootstrap_tenant
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def issue(
        self,
        tenant_id: str,
        role: Role,
        *,
        label: str = "",
        now: float | None = None,
    ) -> IssuedKey:
        """Mint a key. The token is returned here and cannot be recovered later."""
        if not tenant_id:
            raise ValueError("a key must belong to a tenant")
        key_id = secrets.token_hex(8)
        secret = secrets.token_urlsafe(32)
        token = f"{_PREFIX}_{key_id}_{secret}"

        with self._lock:
            self._conn.execute(
                "INSERT INTO api_keys (key_id, tenant_id, role, token_hash, "
                "label, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    key_id,
                    tenant_id,
                    role.value,
                    hash_token(token),
                    label,
                    now if now is not None else time.time(),
                ),
            )
            self._conn.commit()

        return IssuedKey(
            key_id=key_id, token=token, tenant_id=tenant_id, role=role, label=label
        )

    def authenticate(self, token: str | None) -> Principal | None:
        """Resolve a bearer token, or None if it is not valid."""
        if not token:
            return None

        if self._bootstrap and hmac.compare_digest(token, self._bootstrap):
            return Principal(
                key_id="bootstrap",
                tenant_id=self._bootstrap_tenant,
                role=Role.ADMIN,
                label="bootstrap credential",
            )

        parts = token.split("_", 2)
        if len(parts) != 3 or parts[0] != _PREFIX:
            return None
        key_id = parts[1]

        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM api_keys WHERE key_id = ?", (key_id,)
            ).fetchone()

        if row is None or row["revoked"]:
            return None
        # Constant time, so a caller cannot learn a valid digest by measuring
        # how long a rejection takes.
        if not hmac.compare_digest(row["token_hash"], hash_token(token)):
            return None

        with self._lock:
            self._conn.execute(
                "UPDATE api_keys SET last_used = ? WHERE key_id = ?",
                (time.time(), key_id),
            )
            self._conn.commit()

        return Principal(
            key_id=key_id,
            tenant_id=row["tenant_id"],
            role=Role(row["role"]),
            label=row["label"],
        )

    def revoke(self, key_id: str, tenant_id: str) -> bool:
        """Revoke a key. Scoped to a tenant so nobody can revoke another's."""
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE api_keys SET revoked = 1 WHERE key_id = ? AND tenant_id = ?",
                (key_id, tenant_id),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def list_keys(self, tenant_id: str) -> list[dict]:
        """Key metadata for one tenant. Never includes a token or a hash."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT key_id, tenant_id, role, label, created_at, last_used, "
                "revoked FROM api_keys WHERE tenant_id = ? ORDER BY created_at",
                (tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def tenants(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT tenant_id FROM api_keys ORDER BY tenant_id"
            ).fetchall()
        found = [row["tenant_id"] for row in rows]
        if self._bootstrap and self._bootstrap_tenant not in found:
            found.insert(0, self._bootstrap_tenant)
        return found
