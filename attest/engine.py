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

from dataclasses import dataclass, replace
from typing import Callable, Protocol

from .delegation import DelegationParams, backflow_weights, effective_trust
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
        trust: The sending agent's own trust after folding in ``p``.
        action: What the policy chose.
        reason: Why it chose that.
        enforced: Whether a verifier was actually invoked. False in shadow mode
            and whenever the action was to observe.
        effective_trust: Trust of the whole delegation chain. Equal to
            ``trust`` when the agent acts only for itself; lower when it is
            working on behalf of a less-trusted principal.
        target: Agent a verification is aimed at. This is the chain's weakest
            link, which is not always the sender - challenging a spotless
            worker tells you nothing about the compromised principal directing
            it.
        chain: Full delegation chain, root first, sender last.
    """

    agent_id: str
    timestamp: float
    p: float
    trust: float
    action: Action
    reason: Reason
    enforced: bool = False
    effective_trust: float | None = None
    target: str | None = None
    chain: tuple[str, ...] = ()

    @property
    def verification_target(self) -> str:
        """Who to challenge. Falls back to the sender for un-delegated traffic."""
        return self.target or self.agent_id

    @property
    def delegated(self) -> bool:
        """Whether this action was taken on someone else's behalf."""
        return len(self.chain) > 1


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
        delegation: DelegationParams | None = None,
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
        self.delegation = (
            delegation if delegation is not None else DelegationParams()
        )
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
        # Clamp rather than raise. Traffic from an agent and from its delegates
        # interleaves, so a caller can legitimately ask for the score "as of"
        # a moment already behind this agent's last update. Evidence cannot be
        # un-applied, so the answer is simply the current score.
        at = max(now, record.trust.updated_at or now)
        return record.trust.decayed(at, self.trust_params).score

    def _charge_principals(self, env: Envelope, p: float) -> None:
        """Charge a share of a delegate's bad evidence to its principals.

        Only bad evidence travels upward. Letting good evidence flow up would
        hand a compromised principal an easy way to rebuild its own score:
        delegate a great deal of innocuous work and collect the credit.
        """
        # Below the threshold nothing is charged at all. Because propagation is
        # one-sided, a per-message residue would accumulate against a principal
        # with no counterweight, and a busy orchestrator with flawless workers
        # would sink purely for delegating a lot.
        if p <= self.delegation.backflow_threshold:
            return
        for agent_id, weight in backflow_weights(env.on_behalf_of, self.delegation):
            principal = self.store.get(agent_id)
            # A principal receives evidence from its own traffic as well as
            # from delegates, and the two streams interleave, so a backflow
            # event can arrive behind the principal's own last update. Clamp
            # rather than reject: the alternative is dropping real evidence
            # purely because of interleaving.
            at = max(env.timestamp, principal.trust.updated_at or env.timestamp)
            principal.trust = principal.trust.penalize(
                weight * p, at, self.trust_params
            )
            self.store.put(principal)

    def observe(self, env: Envelope) -> Decision:
        """Process one envelope and return the resulting decision.

        The policy is evaluated against the *chain's* effective trust, and any
        verification is aimed at the chain's weakest link. For undelegated
        traffic both collapse to the sending agent and the behaviour is
        identical to per-agent scoring.
        """
        record = self.store.get(env.sender)
        profile = record.ensure_profile(self.warmup_events)

        p = self.scorer.score(env, profile)
        profile.update(env)

        trust_state = record.trust.observe(p, env.timestamp, self.trust_params)
        self._charge_principals(env, p)

        chain_ids = (*env.on_behalf_of, env.sender)
        chain = effective_trust(
            [
                (agent_id, self.trust_of(agent_id, env.timestamp))
                if agent_id != env.sender
                else (agent_id, trust_state.score)
                for agent_id in chain_ids
            ],
            self.delegation,
        )

        # Policy state belongs to whoever would be challenged, not to whoever
        # happened to send this message. Otherwise a chain could re-fire on the
        # same principal once per delegate.
        target_record = (
            record if chain.target == env.sender else self.store.get(chain.target)
        )
        action, policy_state, reason = decide(
            target_record.policy,
            chain.score,
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
            effective_trust=chain.score,
            target=chain.target,
            chain=chain_ids,
        )

        if action is Action.VERIFY:
            # Commit the budget here rather than inside decide(), so that the
            # policy stays a pure function of its inputs.
            self.budget.spend(env.timestamp)
            # Both a clean result and a remediation restart the relationship,
            # so trust returns to the prior either way. Reset the agent that
            # was actually checked - resetting anyone else would clear a score
            # nobody verified.
            if chain.target == env.sender:
                trust_state = trust_state.reset(env.timestamp)
            else:
                target_record.trust = target_record.trust.reset(env.timestamp)

            if not self.shadow and self.verifier is not None:
                self.verifier(chain.target, decision)
                decision = replace(decision, enforced=True)

        record.trust = trust_state
        target_record.policy = policy_state
        self.store.put(record)
        if target_record is not record:
            self.store.put(target_record)

        for listener in self._listeners:
            listener(decision)
        return decision
