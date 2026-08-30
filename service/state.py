"""Service state: one context per tenant, over one database.

Isolation is structural rather than procedural. Each tenant gets its own
engine, gateway, approval queue and tool catalogue, over a store scoped to that
tenant. Nothing filters by tenant at the call site, because a filter can be
forgotten and a scoped store has nothing else it could return.

Behavioural profiles, threshold drift and rubber-stamp statistics all live on
the engine, so they are per tenant for free. That matters more than it looks:
approval latencies are the raw material of the rubber-stamp detector, and
pooling them across tenants would let one customer's reviewers mask another's.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from attest import AttestEngine, Budget, Decision, PolicyParams, TrustParams
from attest.adapters import AnsClient, SamacpAdapter
from attest.gateway import AttestGateway
from attest.packet import PacketBuilder, Reversibility, ToolCatalog, ToolRisk
from attest.queue import ApprovalQueue
from attest.store_sqlite import SqliteDecisionLog, SqliteStore
from attest.tenancy import KeyStore

__all__ = ["ServiceState", "TenantContext", "Verifiers"]

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
    """Mutable copy of one tenant's engine configuration."""

    gamma: float = 0.94
    w: float = 2.0
    recovery_seconds: float = 33.0
    theta_low: float = 0.5
    theta_high: float = 0.65
    cooldown_seconds: float = 8.0
    budget_per_1k_steps: float | None = None
    shadow: bool = True
    warmup_events: int = 50


class TenantContext:
    """Everything one tenant owns.

    Deliberately exposes the same surface the single-tenant service used, so
    the handlers did not have to learn about tenancy - they receive a context
    that can only see one tenant's data.
    """

    def __init__(self, tenant_id: str, store: SqliteStore, ans_url: str) -> None:
        self.tenant_id = tenant_id
        self.store = store
        self.log = SqliteDecisionLog(store)
        self.settings = _Settings()
        self.adapter = SamacpAdapter(ans=AnsClient(base_url=ans_url))
        self.ans_url = ans_url
        self._subscribers: set[asyncio.Queue] = set()
        self.feed = None  # set by service.feed.SimulatedFeed
        self.engine = self._build_engine()

        self.catalog = starter_catalog()
        self.builder = PacketBuilder(catalog=self.catalog)
        self.approvals = ApprovalQueue()
        self.gateway = AttestGateway(
            engine=self.engine, builder=self.builder, queue=self.approvals
        )

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
        """Apply setting changes and rebuild this tenant's engine.

        Trust state survives, because it lives in the store rather than the
        engine. Changing gamma mid-flight does re-interpret the accumulated
        counters, which is worth being aware of but is not a reason to discard
        them - the alternative is resetting the whole fleet to neutral.
        """
        for key, value in changes.items():
            if value is not None and hasattr(self.settings, key):
                setattr(self.settings, key, value)
        self.engine = self._build_engine()
        # Re-point the gateway, or it keeps deciding against the engine that
        # was just replaced - approvals would resolve into state nothing reads.
        if getattr(self, "gateway", None) is not None:
            self.gateway.engine = self.engine

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


class ServiceState:
    """Global state: the database, the key store, and every tenant context.

    Args:
        db_path: SQLite file, or ``":memory:"`` for tests.
        ans_url: Agent Name Service base URL used by the SAMACP adapter.
        bootstrap_token: Initial admin credential, from the environment.
    """

    def __init__(
        self,
        db_path: str = "attest.db",
        ans_url: str = "http://localhost:5000",
        bootstrap_token: str | None = None,
    ) -> None:
        self._base = SqliteStore(db_path)
        self.ans_url = ans_url
        self.keys = KeyStore(self._base._conn, bootstrap_token=bootstrap_token)
        self._tenants: dict[str, TenantContext] = {}

    def tenant(self, tenant_id: str) -> TenantContext:
        """Context for ``tenant_id``, created on first use."""
        context = self._tenants.get(tenant_id)
        if context is None:
            context = TenantContext(
                tenant_id, self._base.for_tenant(tenant_id), self.ans_url
            )
            self._tenants[tenant_id] = context
        return context

    @property
    def tenants(self) -> list[str]:
        return sorted(self._tenants)

    async def shutdown(self) -> None:
        for context in self._tenants.values():
            if context.feed is not None:
                await context.feed.stop()

    def close(self) -> None:
        self._base.close()


def starter_catalog() -> ToolCatalog:
    """A few tools declared so a fresh install does nothing surprising.

    Everything not listed is treated as irreversible and sensitive, which is
    the safe default but also means an unconfigured gateway holds every call.
    These entries exist so the demo is usable; a real deployment replaces them.
    """
    return (
        ToolCatalog()
        .declare(
            "search",
            ToolRisk(
                reversibility=Reversibility.REVERSIBLE,
                magnitude=0.05,
                description="Read-only search over documentation.",
            ),
        )
        .declare(
            "read_file",
            ToolRisk(
                reversibility=Reversibility.REVERSIBLE,
                magnitude=0.1,
                description="Reads a file the agent already has access to.",
            ),
        )
        .declare(
            "draft_message",
            ToolRisk(
                reversibility=Reversibility.RECOVERABLE,
                magnitude=0.25,
                description="Writes a draft. Nothing is sent.",
            ),
        )
        .declare(
            "send_message",
            ToolRisk(
                reversibility=Reversibility.IRREVERSIBLE,
                magnitude=0.6,
                description="Sends a message to an external recipient.",
            ),
        )
        .declare(
            "bulk_export",
            ToolRisk(
                reversibility=Reversibility.IRREVERSIBLE,
                magnitude=0.9,
                sensitive=True,
                description="Exports records to an external destination.",
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
