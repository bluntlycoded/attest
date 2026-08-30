"""Persistence for per-agent trust state.

The state that has to survive a restart is small - two counters, a timestamp,
an armed flag and a cooldown - which is a deliberate property of the design
rather than an accident. It means the engine can be restarted, sharded or run
as a sidecar without a migration story.

Behavioural profiles are held in memory only. They rebuild from traffic, and
persisting them would mean persisting an unbounded set of peers and intents per
agent for very little benefit.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Iterator, Protocol

from .evidence import AgentProfile
from .policy import PolicyState
from .trust import TrustState

__all__ = ["AgentRecord", "StateStore", "InMemoryStore", "JsonFileStore"]


@dataclass
class AgentRecord:
    """Everything the engine tracks for one agent."""

    agent_id: str
    trust: TrustState = field(default_factory=TrustState)
    policy: PolicyState = field(default_factory=PolicyState)
    profile: AgentProfile | None = None

    def ensure_profile(self, warmup_events: int) -> AgentProfile:
        """Return the behavioural profile, creating it on first use."""
        if self.profile is None:
            self.profile = AgentProfile(
                agent_id=self.agent_id, warmup_events=warmup_events
            )
        return self.profile


class StateStore(Protocol):
    """Storage interface for agent records."""

    def get(self, agent_id: str) -> AgentRecord:
        """Return the record for ``agent_id``, creating an empty one if absent."""
        ...

    def put(self, record: AgentRecord) -> None:
        """Persist ``record``."""
        ...

    def agents(self) -> Iterator[str]:
        """Iterate over known agent identifiers."""
        ...


class InMemoryStore:
    """Non-durable store. The default, and what the simulator uses."""

    def __init__(self) -> None:
        self._records: dict[str, AgentRecord] = {}

    def get(self, agent_id: str) -> AgentRecord:
        record = self._records.get(agent_id)
        if record is None:
            record = AgentRecord(agent_id=agent_id)
            self._records[agent_id] = record
        return record

    def put(self, record: AgentRecord) -> None:
        self._records[record.agent_id] = record

    def agents(self) -> Iterator[str]:
        return iter(tuple(self._records))

    def __len__(self) -> int:
        return len(self._records)


class JsonFileStore(InMemoryStore):
    """In-memory store with a JSON file behind it.

    Writes the whole file on every ``put``, which is fine at the scale this is
    meant for - a single process watching some thousands of agents - and keeps
    the durability story to one readable artefact. Swap in a real database
    before running this across processes.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        super().__init__()
        self.path = os.fspath(path)
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        for agent_id, blob in raw.items():
            self._records[agent_id] = AgentRecord(
                agent_id=agent_id,
                trust=TrustState(
                    r=blob["r"], s=blob["s"], updated_at=blob["updated_at"]
                ),
                policy=PolicyState(
                    armed=blob["armed"], cooldown_until=blob["cooldown_until"]
                ),
            )

    def put(self, record: AgentRecord) -> None:
        super().put(record)
        self._flush()

    def _flush(self) -> None:
        payload = {
            agent_id: {
                "r": rec.trust.r,
                "s": rec.trust.s,
                "updated_at": rec.trust.updated_at,
                "armed": rec.policy.armed,
                "cooldown_until": rec.policy.cooldown_until,
            }
            for agent_id, rec in self._records.items()
        }
        # Write to a temporary file in the same directory, then rename, so a
        # crash mid-write cannot leave a truncated state file behind.
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
