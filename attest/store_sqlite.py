"""SQLite-backed state and decision log.

:class:`~attest.store.JsonFileStore` rewrites its whole file on every decision,
which is fine for a test and hopeless under real traffic. This module is the
version meant to run: one file, no server, a row per agent and a row per
decision.

Behavioural profiles stay in memory. They rebuild from traffic within the
warm-up window, and persisting an unbounded set of peers and intents per agent
would cost far more than it saves.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from typing import Iterator

from .engine import Decision
from .policy import PolicyState
from .store import AgentRecord
from .trust import TrustState

__all__ = ["SqliteStore", "SqliteDecisionLog", "AgentSummary"]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id       TEXT PRIMARY KEY,
    r              REAL NOT NULL DEFAULT 0,
    s              REAL NOT NULL DEFAULT 0,
    updated_at     REAL,
    armed          INTEGER NOT NULL DEFAULT 1,
    cooldown_until REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS decisions (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id  TEXT NOT NULL,
    timestamp REAL NOT NULL,
    p         REAL NOT NULL,
    trust     REAL NOT NULL,
    action    TEXT NOT NULL,
    reason    TEXT NOT NULL,
    enforced  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS decisions_agent_idx ON decisions (agent_id, id DESC);
CREATE INDEX IF NOT EXISTS decisions_action_idx ON decisions (action, id DESC);
"""


@dataclass(frozen=True)
class AgentSummary:
    """Fleet-view row for one agent."""

    agent_id: str
    trust: float
    updated_at: float | None
    armed: bool
    cooldown_until: float
    decisions: int
    verifications: int


def _connect(path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    # WAL lets the console read while the ingest path writes.
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.executescript(_SCHEMA)
    connection.commit()
    return connection


class SqliteStore:
    """Durable :class:`~attest.store.StateStore` backed by SQLite.

    Args:
        path: Database file. Use ``":memory:"`` for tests.
    """

    def __init__(self, path: str = "attest.db") -> None:
        self.path = path
        self._lock = threading.Lock()
        self._conn = _connect(path)
        # Profiles are per-process and never persisted; see the module docstring.
        self._profiles: dict[str, AgentRecord] = {}

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def get(self, agent_id: str) -> AgentRecord:
        cached = self._profiles.get(agent_id)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()

        if row is None:
            record = cached or AgentRecord(agent_id=agent_id)
        else:
            record = AgentRecord(
                agent_id=agent_id,
                trust=TrustState(
                    r=row["r"], s=row["s"], updated_at=row["updated_at"]
                ),
                policy=PolicyState(
                    armed=bool(row["armed"]), cooldown_until=row["cooldown_until"]
                ),
                # Carry the in-memory profile across, so a restart loses the
                # behavioural baseline but never the trust state.
                profile=cached.profile if cached else None,
            )
        self._profiles[agent_id] = record
        return record

    def put(self, record: AgentRecord) -> None:
        self._profiles[record.agent_id] = record
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO agents (agent_id, r, s, updated_at, armed, cooldown_until)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    r = excluded.r,
                    s = excluded.s,
                    updated_at = excluded.updated_at,
                    armed = excluded.armed,
                    cooldown_until = excluded.cooldown_until
                """,
                (
                    record.agent_id,
                    record.trust.r,
                    record.trust.s,
                    record.trust.updated_at,
                    int(record.policy.armed),
                    record.policy.cooldown_until,
                ),
            )
            self._conn.commit()

    def agents(self) -> Iterator[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT agent_id FROM agents ORDER BY agent_id"
            ).fetchall()
        return iter([row["agent_id"] for row in rows])

    def summaries(self, limit: int = 500, offset: int = 0) -> list[AgentSummary]:
        """Fleet view, least-trusted first - the order an operator cares about."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT a.*,
                       COALESCE(d.total, 0)    AS decisions,
                       COALESCE(d.verified, 0) AS verifications
                FROM agents a
                LEFT JOIN (
                    SELECT agent_id,
                           COUNT(*) AS total,
                           SUM(CASE WHEN action = 'verify' THEN 1 ELSE 0 END) AS verified
                    FROM decisions GROUP BY agent_id
                ) d ON d.agent_id = a.agent_id
                ORDER BY (a.r + 1.0) / (a.r + a.s + 2.0) ASC, a.agent_id
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()

        return [
            AgentSummary(
                agent_id=row["agent_id"],
                trust=(row["r"] + 1.0) / (row["r"] + row["s"] + 2.0),
                updated_at=row["updated_at"],
                armed=bool(row["armed"]),
                cooldown_until=row["cooldown_until"],
                decisions=row["decisions"],
                verifications=row["verifications"],
            )
            for row in rows
        ]

    def count(self) -> int:
        with self._lock:
            return int(
                self._conn.execute("SELECT COUNT(*) AS n FROM agents").fetchone()["n"]
            )


class SqliteDecisionLog:
    """Append-only log of engine decisions.

    Shares its connection with a :class:`SqliteStore` so both live in one file
    and one transaction scope.
    """

    def __init__(self, store: SqliteStore) -> None:
        self._store = store
        self._conn = store._conn
        self._lock = store._lock

    def append(self, decision: Decision) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO decisions
                    (agent_id, timestamp, p, trust, action, reason, enforced)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.agent_id,
                    decision.timestamp,
                    decision.p,
                    decision.trust,
                    decision.action.value,
                    decision.reason.value,
                    int(decision.enforced),
                ),
            )
            self._conn.commit()

    def recent(
        self,
        *,
        limit: int = 100,
        agent_id: str | None = None,
        action: str | None = None,
    ) -> list[dict]:
        """Most recent decisions first."""
        clauses, params = [], []
        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if action:
            clauses.append("action = ?")
            params.append(action)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM decisions {where} ORDER BY id DESC LIMIT ?", params
            ).fetchall()
        return [dict(row) for row in rows]

    def trajectory(self, agent_id: str, *, limit: int = 500) -> list[dict]:
        """Trust over time for one agent, oldest first, ready to plot."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT timestamp, p, trust, action, reason FROM decisions
                WHERE agent_id = ? ORDER BY id DESC LIMIT ?
                """,
                (agent_id, limit),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def counters(self) -> dict[str, float]:
        """Operational counters.

        Deliberately excludes exposure, onset delay and containment: those need
        ground truth about whether an agent was actually compromised, which a
        production deployment does not have. Use the benchmark for those.
        """
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS steps,
                       SUM(CASE WHEN action = 'verify' THEN 1 ELSE 0 END) AS verifications,
                       SUM(CASE WHEN enforced = 1 THEN 1 ELSE 0 END) AS enforced,
                       AVG(trust) AS mean_trust,
                       MIN(timestamp) AS first_seen,
                       MAX(timestamp) AS last_seen
                FROM decisions
                """
            ).fetchone()

        steps = row["steps"] or 0
        verifications = row["verifications"] or 0
        return {
            "steps": steps,
            "verifications": verifications,
            "enforced": row["enforced"] or 0,
            "budget_per_1k_steps": (1000.0 * verifications / steps) if steps else 0.0,
            "mean_trust": row["mean_trust"] if row["mean_trust"] is not None else 0.5,
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "agents": self._store.count(),
        }

    def reason_breakdown(self) -> dict[str, int]:
        """How often each decision reason fired. Shows where the policy is binding."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT reason, COUNT(*) AS n FROM decisions GROUP BY reason"
            ).fetchall()
        return {row["reason"]: row["n"] for row in rows}

    def clear(self) -> None:
        """Drop all decisions and agent state. Used when resetting a demo."""
        with self._lock:
            self._conn.execute("DELETE FROM decisions")
            self._conn.execute("DELETE FROM agents")
            self._conn.commit()
        self._store._profiles.clear()
