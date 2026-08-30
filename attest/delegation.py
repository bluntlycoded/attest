"""Trust across a delegation chain.

The thing that distinguishes an agent identity from both a human user and a
service account is the delegation chain - this agent is acting on behalf of
that one, which is acting on behalf of a user, within some scope. Scoring each
agent in isolation misses the failure that matters most: a compromised
orchestrator that never touches a sensitive resource itself, and instead has
five perfectly healthy workers do it.

Two mechanisms, and they are deliberately asymmetric.

Effective trust flows *down*
    An action is worth no more than the weakest link in the chain that
    authorised it. A spotless worker executing instructions from a
    compromised principal is doing attacker-chosen work, and its own clean
    history says nothing about that. So the policy is evaluated against the
    effective trust of the chain rather than the acting agent's self trust.

    Crucially this does not damage the worker's own score. Self trust and
    effective trust are separate: the worker did nothing wrong, and once the
    principal is resolved the worker is immediately trustworthy again.

Bad evidence flows *up*
    If a delegate misbehaves while acting for a principal, some of that
    counts against the principal - otherwise using a delegate as a proxy is a
    way to launder a compromise. Good evidence does not flow up, for the same
    reason: a compromised principal could otherwise rebuild its own score by
    having a healthy delegate do a great deal of innocuous work.

The scheduling consequence is the interesting one. When a chain's effective
trust falls, the verification is aimed at the *weakest link*, not at the agent
that happened to send the message. Challenging the worker would tell you
nothing, because the worker is fine. One verification of the principal resolves
every delegate acting on its behalf at once, which is where the budget saving
comes from.

The discounting idea is Jøsang and Ismail's, from the same work the trust
recurrence comes from; what is applied here is a simplified, readable form of
it rather than the full operator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Sequence

__all__ = ["DelegationParams", "ChainTrust", "effective_trust", "backflow_weights"]

Strategy = Literal["min", "product"]


@dataclass(frozen=True)
class DelegationParams:
    """How trust moves along a chain.

    Args:
        strategy: How chain trust is combined. ``min`` treats a chain as being
            exactly as strong as its weakest link - readable, and it does not
            punish a legitimately deep chain. ``product`` compounds, so every
            additional hop costs something even when all links are healthy;
            defensible, since each hop is more surface, but it makes long
            workflows look untrustworthy quickly.
        hop_damping: How much of a distant principal's *distrust* still counts,
            per hop. At 1.0 a compromised root implicates the whole subtree
            equally. At 0.5 a principal two hops up contributes a quarter of
            its distrust. Damping below 1.0 buys resilience against one bad
            root freezing an entire fleet, at the cost of letting a distant
            attacker hide behind depth.
        backflow: Fraction of a delegate's *bad* evidence that is charged to
            its immediate principal, decaying by the same factor per further
            hop. Zero disables upward propagation entirely.

            The default is not arbitrary. Below about 0.25 a compromised
            principal never sinks past the delegate doing its dirty work, so
            every check lands on the delegate, comes back clean, and contains
            nothing. At 0.5 the principal becomes the weakest link quickly
            enough that the first check is aimed correctly - which in the
            scenario in :mod:`attest.delegation_sim` takes wasted checks from
            84% to zero and total spend to roughly a quarter. Higher values
            keep working but implicate principals on thinner evidence.
        backflow_threshold: A delegate's evidence is only charged upward when
            it exceeds this. Without a threshold every ordinary message would
            contribute its small residual risk, and because upward propagation
            is deliberately one-sided - bad evidence only, never good - that
            residue accumulates with nothing to offset it. A busy orchestrator
            delegating to flawless workers would drift steadily downward purely
            for being busy. The default of 0.5 is the neutral prior: a
            principal is charged only for delegate behaviour that is more
            likely compromised than not.
        max_depth: Chains longer than this are truncated from the acting agent
            backwards. A chain that long is usually a loop or a bug, and
            walking it unbounded would let a caller drive unbounded work.
    """

    strategy: Strategy = "min"
    hop_damping: float = 1.0
    backflow: float = 0.5
    backflow_threshold: float = 0.5
    max_depth: int = 8

    def __post_init__(self) -> None:
        if self.strategy not in ("min", "product"):
            raise ValueError(f"unknown strategy {self.strategy!r}")
        if not 0.0 < self.hop_damping <= 1.0:
            raise ValueError(
                f"hop_damping must lie in (0, 1], got {self.hop_damping}"
            )
        if not 0.0 <= self.backflow <= 1.0:
            raise ValueError(f"backflow must lie in [0, 1], got {self.backflow}")
        if not 0.0 <= self.backflow_threshold <= 1.0:
            raise ValueError(
                f"backflow_threshold must lie in [0, 1], got {self.backflow_threshold}"
            )
        if self.max_depth < 1:
            raise ValueError(f"max_depth must be at least 1, got {self.max_depth}")


@dataclass(frozen=True)
class ChainTrust:
    """Result of evaluating a delegation chain.

    Attributes:
        score: Effective trust of an action taken by this chain.
        target: Agent a verification should be aimed at - the weakest link,
            which is the only member whose resolution actually changes the
            picture.
        self_trust: The acting agent's own trust, unaffected by the chain.
        depth: Number of principals above the acting agent, after truncation.
        limited_by_principal: True when a principal, rather than the acting
            agent itself, is what dragged the effective trust down. This is
            the case where verifying the sender would be a wasted check.
    """

    score: float
    target: str
    self_trust: float
    depth: int
    limited_by_principal: bool


def _discount(trust: float, distance: int, damping: float) -> float:
    """Shrink a principal's distrust with distance from the acting agent.

    Distrust, not trust, is what decays: at ``damping ** distance`` of zero the
    principal is simply ignored, which means a score of 1.0, not 0.0.
    """
    if distance <= 0 or damping >= 1.0:
        return trust
    return 1.0 - (1.0 - trust) * (damping**distance)


def effective_trust(
    chain: Sequence[tuple[str, float]],
    params: DelegationParams | None = None,
) -> ChainTrust:
    """Combine a delegation chain into one trust score and a verification target.

    Args:
        chain: ``(agent_id, self_trust)`` pairs ordered root principal first,
            acting agent last. A single-element chain is an agent acting only
            for itself and reduces exactly to its own trust.
        params: Combination rules. Defaults to weakest-link with no distance
            damping.

    Returns:
        The chain's effective trust, and which member to verify.

    Raises:
        ValueError: If the chain is empty.
    """
    if not chain:
        raise ValueError("a delegation chain needs at least the acting agent")

    p = params or DelegationParams()
    # Truncate from the acting agent backwards: the nearest principals are the
    # ones with the most bearing on this action.
    walked = list(chain)[-p.max_depth :]
    actor_id, actor_trust = walked[-1]

    # distance 0 is the acting agent, 1 its immediate principal, and so on.
    discounted = [
        (agent_id, _discount(trust, len(walked) - 1 - i, p.hop_damping))
        for i, (agent_id, trust) in enumerate(walked)
    ]

    weakest_id, weakest = min(discounted, key=lambda pair: pair[1])
    if p.strategy == "min":
        score = weakest
    else:
        score = 1.0
        for _, trust in discounted:
            score *= trust

    return ChainTrust(
        score=score,
        # Aim the check at the weakest link. Verifying anyone else leaves the
        # thing that actually lowered the score untouched.
        target=weakest_id,
        self_trust=actor_trust,
        depth=len(walked) - 1,
        limited_by_principal=weakest_id != actor_id,
    )


def backflow_weights(
    principals: Sequence[str], params: DelegationParams | None = None
) -> list[tuple[str, float]]:
    """Fraction of a delegate's bad evidence charged to each principal.

    Args:
        principals: Principal ids, root first, immediate delegator last.
        params: Propagation rules.

    Returns:
        ``(agent_id, weight)`` pairs, weights in [0, 1], decaying by
        ``backflow`` per hop away from the acting agent. Empty when there are
        no principals or propagation is disabled.
    """
    p = params or DelegationParams()
    if not principals or p.backflow <= 0.0:
        return []

    walked = list(principals)[-p.max_depth :]
    weights = []
    # The immediate principal is at the end of the list and carries the most.
    for distance, agent_id in enumerate(reversed(walked), start=1):
        weight = p.backflow**distance
        if weight <= 0.0:
            break
        weights.append((agent_id, weight))
    return list(reversed(weights))
