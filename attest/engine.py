"""The engine: perception, trust and trigger policy wired together.

One call per envelope. The engine scores it, folds the score into the agent's
trust, asks the policy whether to verify, and - outside shadow mode - hands the
decision to a verifier.

Shadow mode suppresses only the external side effect. Trust still resets, the
trigger still disarms, and budget is still spent, so the decision stream a
shadow deployment produces is the one enforcement would have produced. A shadow
run that skipped those updates would report a verification rate several times
too high, because a distrusted agent would re-fire on every subsequent envelope.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from .evidence import Envelope, LogisticRiskScorer
from .policy import Action, Budget, PolicyParams, Reason, decide
from .store import InMemoryStore, StateStore
from .trust import TrustParams

__all__ = ["Decision", "Verification", "Verifier", "AttestEngine"]


@dataclass(frozen=True)
class Decision:
    """The engine's output for one envelope.

    Attributes:
        agent_id: Agent the envelope came from.
        timestamp: Unix timestamp of the envelope.
        p: Calibrated compromise probability the scorer emitted.
        trust: Trust score after folding in ``p``.
        action: What the policy chose.
        reason: Why it chose that.
        enforced: Whether a verifier was actually invoked. False in shadow mode
            and whenever the action was to observe.
    """

    agent_id: str
    timestamp: float
    p: float
    trust: float
    action: Action
    reason: Reason
    enforced: bool = False


@dataclass(frozen=True)
class Verification:
    """Outcome of an attempted verification."""

    agent_id: str
    timestamp: float
    compromised: bool
    detail: str = ""


class Verifier(Protocol):
    """Performs the expensive check the scheduler decides to spend.

    Implementations revoke the agent's credential and require re-attestation,
    escalate to a human for approval, or force a full re-issuance - whatever
    "verify" means in the deployment.
    """

    def __call__(self, agent_id: str, decision: Decision) -> Verification:
        ...


class AttestEngine:
    """Decides which agents to re-verify, under a fixed budget.

    Args:
        trust_params: Trust recurrence parameters.
        policy_params: Trigger policy parameters.
        budget: Verification budget. Defaults to unlimited, which is only
            appropriate for measuring an unconstrained baseline.
        scorer: Maps envelopes to calibrated compromise probabilities.
        store: Where per-agent state lives.
        verifier: Invoked when the policy fires and the engine is enforcing.
        shadow: When True, decisions are recorded but no verifier runs.
        warmup_events: Envelopes before an agent's novelty signals count fully.
    """

    def __init__(
        self,
        *,
        trust_params: TrustParams | None = None,
        policy_params: PolicyParams | None = None,
        budget: Budget | None = None,
        scorer: LogisticRiskScorer | None = None,
        store: StateStore | None = None,
        verifier: Verifier | None = None,
        shadow: bool = True,
        warmup_events: int = 50,
    ) -> None:
        # Explicit None checks rather than `or`: an empty store is falsy, so
        # `store or InMemoryStore()` silently discards a freshly-loaded one.
        self.trust_params = trust_params if trust_params is not None else TrustParams()
        self.policy_params = (
            policy_params if policy_params is not None else PolicyParams()
        )
        self.budget = budget if budget is not None else Budget.unlimited()
        self.scorer = scorer if scorer is not None else LogisticRiskScorer()
        self.store = store if store is not None else InMemoryStore()
        self.verifier = verifier
        self.shadow = shadow
        self.warmup_events = warmup_events
        self._listeners: list[Callable[[Decision], None]] = []

        if not shadow and verifier is None:
            raise ValueError("enforcing mode requires a verifier")

    def subscribe(self, listener: Callable[[Decision], None]) -> None:
        """Register a callback invoked with every decision, in order."""
        self._listeners.append(listener)

    def trust_of(self, agent_id: str, now: float | None = None) -> float:
        """Current trust for ``agent_id``.

        Args:
            now: When supplied, ages the score to this timestamp without
                recording evidence. This is what makes idle agents decay toward
                the neutral prior rather than holding a stale high score.
        """
        record = self.store.get(agent_id)
        if now is None:
            return record.trust.score
        return record.trust.decayed(now, self.trust_params).score

    def observe(self, env: Envelope) -> Decision:
        """Process one envelope and return the resulting decision."""
        record = self.store.get(env.sender)
        profile = record.ensure_profile(self.warmup_events)

        p = self.scorer.score(env, profile)
        profile.update(env)

        trust_state = record.trust.observe(p, env.timestamp, self.trust_params)
        action, policy_state, reason = decide(
            record.policy,
            trust_state.score,
            env.timestamp,
            self.policy_params,
            budget=self.budget,
        )

        decision = Decision(
            agent_id=env.sender,
            timestamp=env.timestamp,
            p=p,
            trust=trust_state.score,
            action=action,
            reason=reason,
        )

        if action is Action.VERIFY:
            # Commit the budget here rather than inside decide(), so that the
            # policy stays a pure function of its inputs.
            self.budget.spend(env.timestamp)
            # Both a clean result and a remediation restart the relationship,
            # so trust returns to the prior either way.
            trust_state = trust_state.reset(env.timestamp)
            if not self.shadow and self.verifier is not None:
                self.verifier(env.sender, decision)
                decision = Decision(
                    agent_id=decision.agent_id,
                    timestamp=decision.timestamp,
                    p=decision.p,
                    trust=decision.trust,
                    action=decision.action,
                    reason=decision.reason,
                    enforced=True,
                )

        record.trust = trust_state
        record.policy = policy_state
        self.store.put(record)

        for listener in self._listeners:
            listener(decision)
        return decision
