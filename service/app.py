"""Attest HTTP service.

Wraps the engine in an API the console can drive, plus a benchmark endpoint
that runs the offline evaluation where ground truth exists.

Run with::

    uvicorn service.app:app --reload
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from attest.tenancy import Principal, Role

from attest.metrics import bootstrap_ci, evaluate
from attest.policy import Budget, PolicyParams
from attest.simulate import (
    BetaTrustPolicy,
    EwmaThresholdPolicy,
    GeneratorConfig,
    PeriodicPolicy,
    RawThresholdPolicy,
    generate_sessions,
    run_policy,
)

from .feed import FeedConfig, SimulatedFeed
from .schemas import (
    AgentOut,
    ApprovalOut,
    ApproverOut,
    CatalogOut,
    DecideIn,
    ToolCallIn,
    ToolRiskIn,
    VerdictOut,
    IssueKeyIn,
    IssuedKeyOut,
    KeyOut,
    WhoAmIOut,
    BenchmarkIn,
    BenchmarkOut,
    ConfigIn,
    ConfigOut,
    DecisionOut,
    EnvelopeIn,
    FeedIn,
    FeedOut,
    FrontierOut,
    FrontierPoint,
    MetricsOut,
    PolicyResult,
    TrajectoryPoint,
)
from .state import ServiceState, TenantContext

DB_PATH = os.environ.get("ATTEST_DB", "attest.db")
ANS_URL = os.environ.get("ATTEST_ANS_URL", "http://localhost:5000")
# The console's dev origin. Override for a deployed front end.
CORS_ORIGINS = os.environ.get(
    "ATTEST_CORS_ORIGINS", "http://localhost:3317,http://127.0.0.1:3317"
).split(",")

BOOTSTRAP_TOKEN = os.environ.get("ATTEST_BOOTSTRAP_KEY") or None

_state: ServiceState | None = None
_bearer = HTTPBearer(auto_error=False)


def _global_state() -> ServiceState:
    if _state is None:  # pragma: no cover - only before startup
        raise RuntimeError("service state not initialised")
    return _state


def principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    state: ServiceState = Depends(_global_state),
) -> Principal:
    """Resolve the caller, or refuse.

    There is no anonymous path. A security control that answers to whoever
    asks is worse than no control, because it is trusted. The first credential
    comes from ATTEST_BOOTSTRAP_KEY rather than from a row, so an unconfigured
    database is unusable rather than open.
    """
    token = credentials.credentials if credentials else None
    if token is None:
        # EventSource cannot set headers, so the SSE stream is the one place a
        # token may arrive as a query parameter. That puts a credential in
        # access logs, so it is allowed for that path alone rather than
        # everywhere.
        if request.url.path == "/decisions/stream":
            token = request.query_params.get("token")
    who = state.keys.authenticate(token)
    if who is None:
        raise HTTPException(
            401,
            "a valid bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return who


def _at_least(role: Role):
    """Dependency factory enforcing a minimum role."""

    def guard(who: Principal = Depends(principal)) -> Principal:
        try:
            who.require(role)
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        return who

    return guard


require_ingest = _at_least(Role.INGEST)
require_approver = _at_least(Role.APPROVER)
require_admin = _at_least(Role.ADMIN)


def get_state(
    who: Principal = Depends(require_ingest),
    state: ServiceState = Depends(_global_state),
) -> TenantContext:
    """The caller's tenant context - the only data they can reach."""
    return state.tenant(who.tenant_id)


def get_reader(
    who: Principal = Depends(require_approver),
    state: ServiceState = Depends(_global_state),
) -> TenantContext:
    return state.tenant(who.tenant_id)


def get_admin(
    who: Principal = Depends(require_admin),
    state: ServiceState = Depends(_global_state),
) -> TenantContext:
    return state.tenant(who.tenant_id)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _state
    _state = ServiceState(
        db_path=DB_PATH, ans_url=ANS_URL, bootstrap_token=BOOTSTRAP_TOKEN
    )
    try:
        yield
    finally:
        if _state is not None:
            await _state.shutdown()
            _state.close()
        _state = None


app = FastAPI(
    title="Attest",
    version="0.1.0",
    description="Budgeted re-verification scheduling for AI agent identity.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in CORS_ORIGINS if o.strip()],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------- health & config


@app.get("/health")
async def health(state: TenantContext = Depends(get_state)) -> dict:
    return {
        "status": "ok",
        "agents": state.store.count(),
        "shadow": state.settings.shadow,
        "feed_running": bool(state.feed and state.feed.running),
        "stream_subscribers": state.subscribers,
    }


def _config_out(state: TenantContext) -> ConfigOut:
    params = state.trust_params
    s = state.settings
    return ConfigOut(
        gamma=params.gamma,
        w=params.w,
        step_seconds=params.step_seconds,
        recovery_seconds=params.recovery_seconds,
        half_life_seconds=params.half_life_seconds,
        theta_low=s.theta_low,
        theta_high=s.theta_high,
        cooldown_seconds=s.cooldown_seconds,
        budget_per_1k_steps=s.budget_per_1k_steps,
        shadow=s.shadow,
        warmup_events=s.warmup_events,
    )


@app.get("/config", response_model=ConfigOut)
async def get_config(state: TenantContext = Depends(get_reader)) -> ConfigOut:
    return _config_out(state)


@app.put("/config", response_model=ConfigOut)
async def put_config(
    body: ConfigIn, state: TenantContext = Depends(get_admin)
) -> ConfigOut:
    changes = body.model_dump(exclude_unset=True)
    # `unlimited_budget` is a separate flag because None already means
    # "leave unchanged" everywhere else in this payload.
    if changes.pop("unlimited_budget", False):
        changes["budget_per_1k_steps"] = None
        state.settings.budget_per_1k_steps = None

    theta_low = changes.get("theta_low", state.settings.theta_low)
    theta_high = changes.get("theta_high", state.settings.theta_high)
    if theta_high < theta_low:
        raise HTTPException(
            422, f"theta_high ({theta_high}) must be at least theta_low ({theta_low})"
        )

    state.reconfigure(**changes)
    return _config_out(state)


# ---------------------------------------------------------------------- ingest


def _to_out(decision) -> DecisionOut:
    return DecisionOut(
        agent_id=decision.agent_id,
        timestamp=decision.timestamp,
        p=decision.p,
        trust=decision.trust,
        action=decision.action.value,
        reason=decision.reason.value,
        enforced=decision.enforced,
        effective_trust=decision.effective_trust,
        target=decision.target,
        chain=list(decision.chain),
    )


@app.post("/observe", response_model=DecisionOut)
async def observe(
    body: EnvelopeIn, state: TenantContext = Depends(get_state)
) -> DecisionOut:
    """Score one already-verified message."""
    from attest import Envelope

    envelope = Envelope(
        sender=body.sender,
        recipient=body.recipient,
        intent=body.intent,
        action=body.action,
        timestamp=body.at(),
        signature_valid=body.signature_valid,
        credential_valid=body.credential_valid,
        audit_proof=body.audit_proof,
        on_behalf_of=tuple(body.on_behalf_of),
    )
    try:
        return _to_out(state.engine.observe(envelope))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/ingest/samacp", response_model=DecisionOut)
async def ingest_samacp(
    request: Request, state: TenantContext = Depends(get_state)
) -> DecisionOut:
    """Score one raw SAMACP envelope, verifying it first.

    The adapter checks the Ed25519 signature against the sender's ANS-registered
    key, the credential's expiry and revocation, and the Merkle inclusion proof.
    Checks that cannot be performed - an unreachable ANS, say - are counted as
    unknown rather than failed, and surface in ``/metrics``.
    """
    raw = await request.json()
    if not isinstance(raw, dict):
        raise HTTPException(422, "expected a JSON object")
    try:
        envelope = state.adapter.to_envelope(raw)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except ImportError as exc:
        raise HTTPException(503, str(exc)) from exc
    return _to_out(state.engine.observe(envelope))


# ---------------------------------------------------------------------- reads


@app.get("/agents", response_model=list[AgentOut])
async def list_agents(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    state: TenantContext = Depends(get_reader),
) -> list[AgentOut]:
    """Fleet view, least-trusted first."""
    return [AgentOut(**vars(s)) for s in state.store.summaries(limit, offset)]


@app.get("/agents/{agent_id}", response_model=AgentOut)
async def get_agent(
    agent_id: str, state: TenantContext = Depends(get_reader)
) -> AgentOut:
    for summary in state.store.summaries(limit=1000):
        if summary.agent_id == agent_id:
            return AgentOut(**vars(summary))
    raise HTTPException(404, f"unknown agent {agent_id!r}")


@app.get("/agents/{agent_id}/trajectory", response_model=list[TrajectoryPoint])
async def trajectory(
    agent_id: str,
    limit: int = Query(300, ge=1, le=5000),
    state: TenantContext = Depends(get_reader),
) -> list[TrajectoryPoint]:
    return [
        TrajectoryPoint(**point) for point in state.log.trajectory(agent_id, limit=limit)
    ]


@app.get("/decisions", response_model=list[DecisionOut])
async def decisions(
    limit: int = Query(100, ge=1, le=1000),
    agent_id: str | None = None,
    action: str | None = Query(None, pattern="^(observe|verify)$"),
    reason: str | None = Query(
        None, description="Comma-separated decision reasons to include"
    ),
    state: TenantContext = Depends(get_reader),
) -> list[DecisionOut]:
    reasons = [r.strip() for r in reason.split(",") if r.strip()] if reason else None
    rows = state.log.recent(
        limit=limit, agent_id=agent_id, action=action, reasons=reasons
    )
    return [
        DecisionOut(
            agent_id=r["agent_id"],
            timestamp=r["timestamp"],
            p=r["p"],
            trust=r["trust"],
            action=r["action"],
            reason=r["reason"],
            enforced=bool(r["enforced"]),
            effective_trust=r["effective_trust"],
            target=r["target"],
            chain=r["chain"].split(">") if r["chain"] else [],
        )
        for r in rows
    ]


@app.get("/decisions/stream")
async def stream(state: TenantContext = Depends(get_reader)) -> StreamingResponse:
    """Server-sent events, one per decision."""
    queue = state.subscribe()

    async def events():
        try:
            while True:
                try:
                    decision = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    # Keep-alive comment so proxies do not drop an idle stream.
                    yield ": keepalive\n\n"
                    continue
                payload = _to_out(decision).model_dump()
                yield f"data: {json.dumps(payload)}\n\n"
        finally:
            state.unsubscribe(queue)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/metrics", response_model=MetricsOut)
async def metrics(state: TenantContext = Depends(get_reader)) -> MetricsOut:
    counters = state.log.counters()
    return MetricsOut(
        **counters,
        reasons=state.log.reason_breakdown(),
        adapter_unknowns=dict(state.adapter.unknowns),
    )


# ------------------------------------------------------------------ benchmark


def _budget_factory(rate: float | None, step_seconds: float, session_length: int):
    if rate is None:
        return None
    capacity = max(1.0, rate * session_length / 1000.0)
    return lambda: Budget.per_thousand_steps(rate, step_seconds, capacity=capacity)


@app.post("/benchmark", response_model=BenchmarkOut)
async def benchmark(body: BenchmarkIn) -> BenchmarkOut:
    """Compare trigger policies on generated sessions.

    This is the only endpoint that can report exposure, containment and onset
    delay, because it is the only place ground truth exists.
    """
    config = GeneratorConfig(detector_quality=body.detector_quality)
    sessions = generate_sessions(body.sessions, config, seed=body.seed)
    budget = _budget_factory(
        body.budget_per_1k_steps, config.step_seconds, config.session_length
    )

    policies = [
        BetaTrustPolicy(),
        RawThresholdPolicy(theta=0.995),
        EwmaThresholdPolicy(),
        PeriodicPolicy(k=16),
    ]

    results = []
    for policy in policies:
        records = run_policy(
            sessions,
            policy,
            cooldown_seconds=body.cooldown_seconds,
            budget=budget,
        )
        m = evaluate(records)
        ci = None
        if body.resamples:
            ci = bootstrap_ci(records, resamples=body.resamples, seed=body.seed)
        results.append(
            PolicyResult(
                policy=policy.name,
                exposure=m.exposure,
                exposure_ci=ci,
                containment=m.containment,
                median_onset_delay=m.median_onset_delay,
                budget_per_1k_steps=m.budget_per_1k_steps,
                false_verifications_per_1k_benign=m.false_verifications_per_1k_benign,
                episodes=m.episodes,
                steps=m.steps,
            )
        )

    return BenchmarkOut(config=body.model_dump(), results=results)


@app.post("/frontier", response_model=FrontierOut)
async def frontier(body: BenchmarkIn) -> FrontierOut:
    """Sweep budget against attacker exposure for adaptive and periodic policies."""
    config = GeneratorConfig(detector_quality=body.detector_quality)
    sessions = generate_sessions(body.sessions, config, seed=body.seed)
    points: list[FrontierPoint] = []

    for theta_low in (0.30, 0.40, 0.50, 0.60, 0.70):
        policy = BetaTrustPolicy(
            policy_params=PolicyParams(
                theta_low=theta_low, theta_high=min(1.0, theta_low + 0.15)
            )
        )
        m = evaluate(run_policy(sessions, policy, cooldown_seconds=body.cooldown_seconds))
        points.append(
            FrontierPoint(
                policy="adaptive",
                setting=f"theta={theta_low:.2f}",
                budget_per_1k_steps=m.budget_per_1k_steps,
                exposure=m.exposure,
                false_verifications_per_1k_benign=m.false_verifications_per_1k_benign,
            )
        )

    for k in (128, 64, 32, 16, 8):
        m = evaluate(
            run_policy(sessions, PeriodicPolicy(k=k), cooldown_seconds=body.cooldown_seconds)
        )
        points.append(
            FrontierPoint(
                policy="periodic",
                setting=f"k={k}",
                budget_per_1k_steps=m.budget_per_1k_steps,
                exposure=m.exposure,
                false_verifications_per_1k_benign=m.false_verifications_per_1k_benign,
            )
        )

    return FrontierOut(config=body.model_dump(), points=points)


# ----------------------------------------------------------------------- feed


def _feed_out(state: TenantContext) -> FeedOut:
    feed = state.feed
    if feed is None:
        return FeedOut(
            running=False, agents=0, steps_per_second=0.0, emitted=0, compromised_now=[]
        )
    return FeedOut(
        running=feed.running,
        agents=feed.config.agents,
        steps_per_second=feed.config.steps_per_second,
        emitted=feed.emitted,
        compromised_now=feed.compromised_now,
    )


@app.get("/feed", response_model=FeedOut)
async def get_feed(state: TenantContext = Depends(get_reader)) -> FeedOut:
    return _feed_out(state)


@app.post("/feed/start", response_model=FeedOut)
async def start_feed(
    body: FeedIn, state: TenantContext = Depends(get_admin)
) -> FeedOut:
    """Start synthetic traffic so the console has something to show."""
    if state.feed is not None and state.feed.running:
        await state.feed.stop()

    if body.auto_tune:
        # Each agent emits every `agents / steps_per_second` seconds. The trust
        # step has to match that, or evidence accumulates so far past what an
        # episode can overcome that the trigger never fires. See
        # TrustParams.from_event_interval.
        from attest.trust import STEPS_TO_RECOVER

        interval = body.agents / body.steps_per_second
        state.reconfigure(
            recovery_seconds=STEPS_TO_RECOVER * interval,
            # The reference cooldown is 8 steps, so express it in seconds at
            # this rate rather than leaving it at a wall-clock default that
            # would span hundreds of steps.
            cooldown_seconds=8 * interval,
        )
    state.feed = SimulatedFeed(
        state,
        FeedConfig(
            agents=body.agents,
            steps_per_second=body.steps_per_second,
            detector_quality=body.detector_quality,
            seed=body.seed,
            attack_hazard=body.attack_hazard,
            episode_mean=body.episode_mean,
        ),
    )
    state.feed.start()
    return _feed_out(state)


@app.post("/feed/stop", response_model=FeedOut)
async def stop_feed(state: TenantContext = Depends(get_admin)) -> FeedOut:
    if state.feed is not None:
        await state.feed.stop()
    return _feed_out(state)


@app.post("/reset")
async def reset(state: TenantContext = Depends(get_admin)) -> dict:
    """Clear all agent state and decisions. Intended for demos."""
    if state.feed is not None:
        await state.feed.stop()
        state.feed = None
    state.log.clear()
    return {"status": "cleared"}


# -------------------------------------------------------------------- gateway


def _verdict_out(result) -> VerdictOut:
    trust = (
        result.decision.effective_trust
        if result.decision.effective_trust is not None
        else result.decision.trust
    )
    return VerdictOut(
        verdict=result.verdict.value,
        explain=result.explain,
        tier=result.tier.value,
        request_id=result.request_id,
        trust=result.decision.trust,
        effective_trust=trust,
        target=result.decision.verification_target,
        packet=result.packet.to_dict() if result.packet else None,
    )


@app.get("/catalog", response_model=CatalogOut)
async def get_catalog(state: TenantContext = Depends(get_reader)) -> CatalogOut:
    """What each tool is declared to do. The operator owns this, not the agent."""
    return CatalogOut(
        tools={
            name: ToolRiskIn(
                reversibility=risk.reversibility.value,
                magnitude=risk.magnitude,
                sensitive=risk.sensitive,
                description=risk.description,
            )
            for name, risk in state.catalog.tools.items()
        }
    )


@app.put("/catalog/{tool}", response_model=CatalogOut)
async def declare_tool(
    tool: str, body: ToolRiskIn, state: TenantContext = Depends(get_admin)
) -> CatalogOut:
    """Declare a tool's risk properties."""
    from attest.packet import Reversibility, ToolRisk

    state.catalog.declare(
        tool,
        ToolRisk(
            reversibility=Reversibility(body.reversibility),
            magnitude=body.magnitude,
            sensitive=body.sensitive,
            description=body.description,
        ),
    )
    return await get_catalog(state)


@app.post("/gateway/evaluate", response_model=VerdictOut)
async def evaluate_call(
    body: ToolCallIn, state: TenantContext = Depends(get_state)
) -> VerdictOut:
    """Judge one intercepted tool call: allow, hold for a person, or deny."""
    from attest.gateway import ToolCall

    call = ToolCall(
        agent_id=body.agent_id,
        tool=body.tool,
        arguments=body.arguments,
        resource=body.resource,
        intent=body.intent,
        timestamp=body.at(),
        authenticated=body.authenticated,
        credential_valid=body.credential_valid,
        logged=body.logged,
        on_behalf_of=tuple(body.on_behalf_of),
    )
    try:
        return _verdict_out(state.gateway.evaluate(call))
    except ValueError as exc:
        # An out-of-order timestamp is the caller's clock going backwards, not
        # a server fault. Evidence has to arrive in order or the recurrence is
        # meaningless, so say so plainly rather than returning a 500.
        raise HTTPException(422, str(exc)) from exc


@app.post("/gateway/mcp", response_model=VerdictOut)
async def evaluate_mcp(
    request: Request,
    agent_id: str = Query(..., min_length=1),
    state: TenantContext = Depends(get_state),
) -> VerdictOut:
    """Judge a raw MCP ``tools/call`` request.

    ``agent_id`` is a query parameter rather than a payload field on purpose:
    identity must come from whatever the gateway authenticated. A request that
    could name its own caller would let any agent act as any other.
    """
    from attest.gateway import from_mcp_request

    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(422, "expected a JSON-RPC object")
    call = from_mcp_request(payload, agent_id=agent_id, timestamp=time.time())
    try:
        return _verdict_out(state.gateway.evaluate(call))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


def _approval_out(request) -> ApprovalOut:
    return ApprovalOut(
        request_id=request.request_id,
        agent_id=request.packet.agent_id,
        target=request.packet.target,
        tier=request.tier.value,
        tool=request.packet.tool,
        resource=request.packet.resource,
        opened_at=request.opened_at,
        expires_at=request.expires_at,
        outcome=request.outcome.value if request.outcome else None,
        approver=request.approver,
        rendered=request.packet.render(),
        packet=request.packet.to_dict(),
    )


@app.get("/approvals", response_model=list[ApprovalOut])
async def list_approvals(
    tier: str | None = Query(None, pattern="^(owner|authority)$"),
    state: TenantContext = Depends(get_reader),
) -> list[ApprovalOut]:
    """Requests waiting on a person, oldest first.

    Expiry is not applied here. A request past its deadline is still pending
    until something retires it, and hiding it implicitly would mean the queue
    looked empty while held calls sat unresolved. ``POST /approvals/sweep``
    is what turns those into denials; ``expires_at`` lets a caller show which
    are overdue.
    """
    from attest.packet import Tier

    wanted = Tier(tier) if tier else None
    return [_approval_out(r) for r in state.approvals.pending(tier=wanted)]


@app.get("/approvals/{request_id}", response_model=ApprovalOut)
async def get_approval(
    request_id: str, state: TenantContext = Depends(get_reader)
) -> ApprovalOut:
    request = state.approvals.get(request_id)
    if request is None:
        raise HTTPException(404, f"unknown approval request {request_id!r}")
    return _approval_out(request)


@app.post("/approvals/{request_id}/decide", response_model=ApprovalOut)
async def decide_approval(
    request_id: str, body: DecideIn, state: TenantContext = Depends(get_reader)
) -> ApprovalOut:
    """Record a reviewer's answer and release or refuse the held call."""
    from attest.approval import Outcome

    at = body.at if body.at is not None else time.time()
    try:
        state.gateway.decide(request_id, body.approver, Outcome(body.outcome), at)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return _approval_out(state.approvals.get(request_id))


@app.post("/approvals/sweep")
async def sweep_approvals(state: TenantContext = Depends(get_reader)) -> dict:
    """Age out unanswered holds. Every one becomes a denial, never a release."""
    expired = state.gateway.sweep(time.time())
    return {"expired": expired, "counts": state.approvals.counts()}


@app.get("/approvers", response_model=list[ApproverOut])
async def approvers(state: TenantContext = Depends(get_reader)) -> list[ApproverOut]:
    """Whether each reviewer still appears to be reading.

    A hollow gate looks identical to a healthy one from the outside - the
    approvals still arrive and the audit log still fills. This is the only
    place that difference shows up.
    """
    return [ApproverOut(**vars(s)) for s in state.engine.rubber_stamp.stats()]


# ----------------------------------------------------------------------- keys


@app.post("/keys", response_model=IssuedKeyOut, status_code=201)
async def issue_key(
    body: IssueKeyIn,
    who: Principal = Depends(require_admin),
    state: ServiceState = Depends(_global_state),
) -> IssuedKeyOut:
    """Mint a credential for the caller's own tenant.

    The token is returned here and nowhere else - only a digest is stored, so
    a stolen database yields nothing usable and a lost token has to be
    replaced rather than recovered. The tenant is taken from the caller, not
    from the body: an admin cannot mint credentials into someone else's.
    """
    issued = state.keys.issue(who.tenant_id, Role(body.role), label=body.label)
    return IssuedKeyOut(
        key_id=issued.key_id,
        token=issued.token,
        tenant_id=issued.tenant_id,
        role=issued.role.value,
        label=issued.label,
        warning="This token is shown once. Store it now; it cannot be recovered.",
    )


@app.get("/keys", response_model=list[KeyOut])
async def list_keys(
    who: Principal = Depends(require_admin),
    state: ServiceState = Depends(_global_state),
) -> list[KeyOut]:
    """Key metadata for the caller's tenant. Never a token or a digest."""
    return [KeyOut(**row) for row in state.keys.list_keys(who.tenant_id)]


@app.delete("/keys/{key_id}")
async def revoke_key(
    key_id: str,
    who: Principal = Depends(require_admin),
    state: ServiceState = Depends(_global_state),
) -> dict:
    """Revoke a key belonging to the caller's tenant."""
    if not state.keys.revoke(key_id, who.tenant_id):
        raise HTTPException(404, f"unknown key {key_id!r} in this tenant")
    return {"revoked": key_id}


@app.get("/whoami", response_model=WhoAmIOut)
async def whoami(who: Principal = Depends(principal)) -> WhoAmIOut:
    """What this credential is, for a client checking its own reach."""
    return WhoAmIOut(
        key_id=who.key_id,
        tenant_id=who.tenant_id,
        role=who.role.value,
        label=who.label,
    )
