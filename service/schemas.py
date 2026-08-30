"""Request and response models for the Attest service."""

from __future__ import annotations

import time
from typing import Any, Literal

from pydantic import BaseModel, Field

__all__ = [
    "EnvelopeIn",
    "DecisionOut",
    "AgentOut",
    "TrajectoryPoint",
    "ConfigIn",
    "ConfigOut",
    "MetricsOut",
    "BenchmarkIn",
    "PolicyResult",
    "BenchmarkOut",
    "FrontierPoint",
    "FrontierOut",
    "FeedIn",
    "FeedOut",
]


class EnvelopeIn(BaseModel):
    """A pre-verified agent message.

    Use this when something upstream has already checked the signature. For raw
    SAMACP traffic post to ``/ingest/samacp`` instead and let the adapter do the
    cryptography.
    """

    sender: str = Field(..., min_length=1)
    recipient: str = Field(..., min_length=1)
    intent: str = "unknown"
    action: str = "unknown"
    timestamp: float | None = None
    signature_valid: bool = True
    credential_valid: bool = True
    audit_proof: str | None = None
    on_behalf_of: list[str] = Field(
        default_factory=list,
        description="Delegation chain above the sender, root principal first",
    )

    def at(self) -> float:
        return self.timestamp if self.timestamp is not None else time.time()


class DecisionOut(BaseModel):
    agent_id: str
    timestamp: float
    p: float
    trust: float
    action: Literal["observe", "verify"]
    reason: str
    enforced: bool
    #: Trust of the whole delegation chain. Equal to ``trust`` for an agent
    #: acting only for itself.
    effective_trust: float | None = None
    #: Who a verification is aimed at - the chain's weakest link, which is not
    #: always the sender.
    target: str | None = None
    #: Delegation chain, root principal first, sender last.
    chain: list[str] = Field(default_factory=list)


class AgentOut(BaseModel):
    agent_id: str
    trust: float
    updated_at: float | None
    armed: bool
    cooldown_until: float
    decisions: int
    verifications: int


class TrajectoryPoint(BaseModel):
    timestamp: float
    p: float
    trust: float
    action: str
    reason: str


class ConfigIn(BaseModel):
    """Engine settings. Every field is optional; omitted fields are left alone."""

    gamma: float | None = Field(None, gt=0, lt=1)
    w: float | None = Field(None, gt=0)
    recovery_seconds: float | None = Field(
        None, gt=0, description="Time a distrusted agent takes to earn trust back"
    )
    theta_low: float | None = Field(None, ge=0, le=1)
    theta_high: float | None = Field(None, ge=0, le=1)
    cooldown_seconds: float | None = Field(None, ge=0)
    budget_per_1k_steps: float | None = Field(
        None, gt=0, description="Verification budget; omit for unlimited"
    )
    unlimited_budget: bool | None = None
    shadow: bool | None = None
    warmup_events: int | None = Field(None, ge=0)


class ConfigOut(BaseModel):
    gamma: float
    w: float
    step_seconds: float
    recovery_seconds: float
    half_life_seconds: float
    theta_low: float
    theta_high: float
    cooldown_seconds: float
    budget_per_1k_steps: float | None
    shadow: bool
    warmup_events: int


class MetricsOut(BaseModel):
    """Operational counters from live traffic.

    Exposure, onset delay and containment are absent on purpose: they need
    ground truth about whether an agent was actually compromised, which no
    production deployment has. Run ``/benchmark`` for those.
    """

    steps: int
    verifications: int
    enforced: int
    budget_per_1k_steps: float
    mean_trust: float
    agents: int
    first_seen: float | None
    last_seen: float | None
    reasons: dict[str, int]
    adapter_unknowns: dict[str, int]


class BenchmarkIn(BaseModel):
    sessions: int = Field(300, ge=1, le=5000)
    seed: int = 0
    detector_quality: float = Field(9.0, gt=0)
    cooldown_seconds: float = Field(8.0, ge=0)
    budget_per_1k_steps: float | None = Field(None, gt=0)
    resamples: int = Field(0, ge=0, le=2000, description="0 skips bootstrap CIs")


class PolicyResult(BaseModel):
    policy: str
    exposure: float
    exposure_ci: tuple[float, float] | None = None
    containment: float
    median_onset_delay: float | None
    budget_per_1k_steps: float
    false_verifications_per_1k_benign: float
    episodes: int
    steps: int


class BenchmarkOut(BaseModel):
    config: dict[str, Any]
    results: list[PolicyResult]


class FrontierPoint(BaseModel):
    policy: Literal["adaptive", "periodic"]
    setting: str
    budget_per_1k_steps: float
    exposure: float
    false_verifications_per_1k_benign: float


class FrontierOut(BaseModel):
    config: dict[str, Any]
    points: list[FrontierPoint]


class FeedIn(BaseModel):
    """Start a synthetic traffic feed so the console has something to show."""

    agents: int = Field(12, ge=1, le=200)
    steps_per_second: float = Field(20.0, gt=0, le=1000)
    detector_quality: float = Field(9.0, gt=0)
    seed: int = 0
    attack_hazard: float = Field(
        0.01,
        gt=0,
        lt=1,
        description=(
            "Per-step chance an agent is taken over. Far higher than anything "
            "realistic, so a demo shows compromises within seconds rather than hours."
        ),
    )
    episode_mean: float = Field(60.0, gt=1, description="Mean episode length in steps")
    auto_tune: bool = Field(
        True,
        description=(
            "Set the trust step interval from the feed rate. Without this, "
            "step_seconds is unrelated to how fast agents actually emit and the "
            "trigger will never fire."
        ),
    )


class FeedOut(BaseModel):
    running: bool
    agents: int
    steps_per_second: float
    emitted: int
    compromised_now: list[str]


# ------------------------------------------------------------------- gateway


class ToolRiskIn(BaseModel):
    """Operator declaration of what a tool can do."""

    reversibility: Literal[
        "reversible", "recoverable", "irreversible", "unknown"
    ] = "unknown"
    magnitude: float = Field(1.0, ge=0.0, le=1.0)
    sensitive: bool = False
    description: str = ""


class CatalogOut(BaseModel):
    tools: dict[str, ToolRiskIn]


class ToolCallIn(BaseModel):
    """An intercepted tool call.

    ``agent_id`` is whoever the gateway authenticated. It is never read from a
    request payload, because a call that could name its own caller would let
    any agent act as any other.
    """

    agent_id: str = Field(..., min_length=1)
    tool: str = Field(..., min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    resource: str = ""
    intent: str = ""
    timestamp: float | None = None
    authenticated: bool = True
    credential_valid: bool = True
    logged: bool = True
    on_behalf_of: list[str] = Field(default_factory=list)

    def at(self) -> float:
        return self.timestamp if self.timestamp is not None else time.time()


class VerdictOut(BaseModel):
    verdict: Literal["allow", "hold", "deny"]
    explain: str
    tier: Literal["auto", "owner", "authority"]
    request_id: str | None = None
    trust: float
    effective_trust: float
    target: str
    packet: dict[str, Any] | None = None


class ApprovalOut(BaseModel):
    request_id: str
    agent_id: str
    target: str
    tier: Literal["auto", "owner", "authority"]
    tool: str
    resource: str
    opened_at: float
    expires_at: float
    outcome: str | None = None
    approver: str | None = None
    rendered: str
    packet: dict[str, Any]


class DecideIn(BaseModel):
    approver: str = Field(..., min_length=1)
    outcome: Literal["approved", "rejected"]
    at: float | None = None


class ApproverOut(BaseModel):
    """Whether one reviewer still appears to be reading."""

    approver: str
    decisions: int
    approval_rate: float
    median_latency: float
    latency_cv: float
    hollow_score: float
    hollow: bool


# ---------------------------------------------------------------------- keys


class IssueKeyIn(BaseModel):
    role: Literal["ingest", "approver", "admin"]
    label: str = ""


class IssuedKeyOut(BaseModel):
    """The one and only time a token is returned."""

    key_id: str
    token: str
    tenant_id: str
    role: str
    label: str
    warning: str


class KeyOut(BaseModel):
    key_id: str
    tenant_id: str
    role: str
    label: str
    created_at: float
    last_used: float | None
    revoked: int


class WhoAmIOut(BaseModel):
    key_id: str
    tenant_id: str
    role: str
    label: str
