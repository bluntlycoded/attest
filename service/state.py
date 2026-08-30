"""Service-wide state: the engine, its store, and the live decision fan-out.

Held as a single object rather than module globals so tests can build an
isolated instance against an in-memory database.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from attest import AttestEngine, Budget, Decision, PolicyParams, TrustParams
from attest.adapters import AnsClient, SamacpAdapter
from attest.store_sqlite import SqliteDecisionLog, SqliteStore

__all__ = ["ServiceState", "Verifiers"]

# Bound on the per-subscriber queue. A console that stops reading is dropped
# from rather than allowed to grow without limit.
_STREAM_QUEUE_SIZE = 512


class Verifiers:
    """The actions a verification can take.

    ``log`` is the default and does nothing but record. The others are what
    "verify" means once the engine is enforcing: revoke the agent's credential
    so it must re-attest, or escalate to a human.
    """

    @staticmethod
    def log(agent_id: str, decision: Decision):
        from attest import Verification

        return Verification(
            agent_id=agent_id,
            timestamp=decision.timestamp,
            compromised=False,
            detail="recorded only; no action taken",
        )

    @staticmethod
    def revoke_credential(ans_url: str):
        """Revoke the agent's credential via the ANS, forcing re-attestation."""

        def verify(agent_id: str, decision: Decision):
            import requests

            from attest import Verification

            try:
                response = requests.post(
                    f"{ans_url.rstrip('/')}/revoke_vc",
                    json={"jti": agent_id},
                    timeout=3,
                )
                ok = response.status_code == 200
            except Exception as exc:
                return Verification(
                    agent_id=agent_id,
                    timestamp=decision.timestamp,
                    compromised=False,
                    detail=f"revocation failed: {exc}",
                )
            return Verification(
                agent_id=agent_id,
                timestamp=decision.timestamp,
                compromised=ok,
                detail="credential revoked" if ok else "revocation rejected",
            )

        return verify


@dataclass
class _Settings:
    """Mutable copy of the engine configuration, so it can be reported back."""

    gamma: float = 0.94
    w: float = 2.0
    recovery_seconds: float = 33.0
    theta_low: float = 0.5
    theta_high: float = 0.65
    cooldown_seconds: float = 8.0
    budget_per_1k_steps: float | None = None
    shadow: bool = True
    warmup_events: int = 50


class ServiceState:
    """Everything the API handlers need.

    Args:
        db_path: SQLite file, or ``":memory:"`` for tests.
        ans_url: Agent Name Service base URL used by the SAMACP adapter.
    """

    def __init__(
        self, db_path: str = "attest.db", ans_url: str = "http://localhost:5000"
    ) -> None:
        self.store = SqliteStore(db_path)
        self.log = SqliteDecisionLog(self.store)
        self.settings = _Settings()
        self.adapter = SamacpAdapter(ans=AnsClient(base_url=ans_url))
        self.ans_url = ans_url
        self._subscribers: set[asyncio.Queue] = set()
        self.feed = None  # set by service.feed.SimulatedFeed
        self.engine = self._build_engine()

    def _build_engine(self) -> AttestEngine:
        s = self.settings
        budget = (
            Budget.unlimited()
            if s.budget_per_1k_steps is None
            else Budget.per_thousand_steps(
                s.budget_per_1k_steps, self.trust_params.step_seconds
            )
        )
        engine = AttestEngine(
            trust_params=self.trust_params,
            policy_params=PolicyParams(
                theta_low=s.theta_low,
                theta_high=s.theta_high,
                cooldown_seconds=s.cooldown_seconds,
            ),
            budget=budget,
            store=self.store,
            verifier=Verifiers.revoke_credential(self.ans_url)
            if not s.shadow
            else Verifiers.log,
            shadow=s.shadow,
            warmup_events=s.warmup_events,
        )
        engine.subscribe(self._on_decision)
        return engine

    @property
    def trust_params(self) -> TrustParams:
        s = self.settings
        return TrustParams.from_recovery_time(
            s.recovery_seconds, gamma=s.gamma, w=s.w
        )

    def reconfigure(self, **changes) -> None:
        """Apply setting changes and rebuild the engine.

        Trust state survives, because it lives in the store rather than the
        engine. Changing gamma mid-flight does re-interpret the accumulated
        counters, which is worth being aware of but is not a reason to discard
        them - the alternative is resetting the whole fleet to neutral.
        """
        for key, value in changes.items():
            if value is not None and hasattr(self.settings, key):
                setattr(self.settings, key, value)
        self.engine = self._build_engine()

    def _on_decision(self, decision: Decision) -> None:
        self.log.append(decision)
        dead = []
        for queue in self._subscribers:
            try:
                queue.put_nowait(decision)
            except asyncio.QueueFull:
                dead.append(queue)
        for queue in dead:
            self._subscribers.discard(queue)

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=_STREAM_QUEUE_SIZE)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    @property
    def subscribers(self) -> int:
        return len(self._subscribers)

    def close(self) -> None:
        self.store.close()
