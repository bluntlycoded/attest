"""Evaluating chain-aware scheduling against chain-blind scheduling.

The scenario is the one delegation awareness exists for, and it is chosen
deliberately rather than as a representative sample of compromises: an
orchestrator is taken over, its own messages continue to look entirely
ordinary because all it does is issue instructions, and the visibly hostile
traffic comes from workers that are themselves perfectly healthy.

Two configurations of the *same* engine are compared. The chain-blind arm is
not a strawman - it is this engine with the delegation field withheld, which is
what every agent-identity system in the field does today, because none of them
carry the chain into the scheduling decision.

Verification semantics matter here and are modelled explicitly. Checking an
agent reveals whether *that agent* is compromised. Challenging a spotless
worker therefore returns clean and contains nothing, while the orchestrator
directing it keeps going. That is the whole cost being measured: not just how
many verifications get spent, but how many of them could never have helped.

What this does not show
-----------------------
Compromises where the acting agent is itself the compromised party. There the
two arms are identical by construction, because the chain's weakest link is
the sender either way. Delegation awareness is not a general improvement; it
closes one specific hole.
"""

from __future__ import annotations

import random
import statistics
from dataclasses import dataclass, field

from .engine import AttestEngine
from .evidence import Envelope
from .policy import Action, Budget, PolicyParams
from .trust import TrustParams

__all__ = ["DelegationScenario", "DelegationOutcome", "run_scenario", "compare"]

_BENIGN_PEERS = ("tool-search", "tool-docs", "tool-calendar")
_BENIGN_ACTIONS = ("query", "summarise", "lookup")
_HOSTILE_PEERS = ("tool-exfil", "host-external", "tool-shell")
_HOSTILE_ACTIONS = ("bulk_export", "escalate", "disable_audit")


@dataclass(frozen=True)
class DelegationScenario:
    """Fleet shape and compromise dynamics.

    Args:
        orchestrators: Number of principals, each with its own worker pool.
        workers_each: Workers per orchestrator.
        steps: Simulation steps. Every orchestrator and every worker emits one
            envelope per step.
        attack_hazard: Per-step probability an idle orchestrator is taken over.
        episode_mean: Mean length of a takeover, in steps.
        guard_steps: Forced benign period after an episode ends.
        detector_quality: Probability that a step of attacker-directed work
            actually looks wrong on the wire.
        step_seconds: Wall-clock spacing between steps.
    """

    orchestrators: int = 4
    workers_each: int = 5
    steps: int = 1500
    attack_hazard: float = 0.004
    episode_mean: float = 80.0
    guard_steps: int = 40
    detector_quality: float = 9.0
    step_seconds: float = 1.0

    def __post_init__(self) -> None:
        if self.orchestrators < 1 or self.workers_each < 1:
            raise ValueError("need at least one orchestrator and one worker")
        if self.steps < 1:
            raise ValueError("steps must be at least 1")
        if not 0.0 < self.attack_hazard < 1.0:
            raise ValueError("attack_hazard must lie in (0, 1)")
        if self.episode_mean <= 1.0:
            raise ValueError("episode_mean must exceed 1")


@dataclass(frozen=True)
class DelegationOutcome:
    """What a scheduling arm achieved.

    Attributes:
        verifications: Total checks spent.
        useful: Checks aimed at an agent that really was compromised.
        wasted: Checks aimed at an agent that was clean. Pure cost - the
            episode continued regardless.
        episodes: Compromise episodes that occurred.
        contained: Episodes ended by a verification.
        exposure: Fraction of compromised steps during which the orchestrator
            was still running.
        median_delay: Steps from takeover to containment, over contained
            episodes.
        steps: Envelopes processed.
    """

    verifications: int
    useful: int
    wasted: int
    episodes: int
    contained: int
    exposure: float
    median_delay: float | None
    steps: int

    @property
    def budget_per_1k_steps(self) -> float:
        return 1000.0 * self.verifications / self.steps if self.steps else 0.0

    @property
    def wasted_fraction(self) -> float:
        return self.wasted / self.verifications if self.verifications else 0.0

    def summary(self) -> str:
        delay = "n/a" if self.median_delay is None else f"{self.median_delay:.1f}"
        return (
            f"exposure {self.exposure:.3f} | "
            f"contained {self.contained}/{self.episodes} | "
            f"delay {delay} | "
            f"budget {self.budget_per_1k_steps:.2f}/1k | "
            f"wasted {self.wasted}/{self.verifications}"
        )


@dataclass
class _Orchestrator:
    """One principal and its worker pool."""

    agent_id: str
    workers: list[str]
    remaining: int = 0
    guard: int = 0
    onset_step: int = 0
    episode_open: bool = False
    exposed_steps: int = 0

    @property
    def compromised(self) -> bool:
        return self.remaining > 0


def _envelope(
    rng: random.Random, sender: str, t: float, *, hostile: bool, on_behalf_of=()
) -> Envelope:
    if hostile:
        return Envelope(
            sender=sender,
            recipient=rng.choice(_HOSTILE_PEERS),
            intent="core",
            action=rng.choice(_HOSTILE_ACTIONS),
            timestamp=t,
            signature_valid=False,
            credential_valid=False,
            audit_proof=None,
            on_behalf_of=on_behalf_of,
        )
    return Envelope(
        sender=sender,
        recipient=rng.choice(_BENIGN_PEERS),
        intent="core",
        action=rng.choice(_BENIGN_ACTIONS),
        timestamp=t,
        signature_valid=True,
        credential_valid=True,
        audit_proof=f"merkle:{t}",
        on_behalf_of=on_behalf_of,
    )


def run_scenario(
    scenario: DelegationScenario | None = None,
    *,
    chain_aware: bool,
    seed: int = 0,
    budget: Budget | None = None,
    policy_params: PolicyParams | None = None,
) -> DelegationOutcome:
    """Run one scheduling arm over the scenario.

    Args:
        scenario: Fleet and compromise settings.
        chain_aware: When False, the delegation field is withheld from every
            envelope, so the engine scores each agent in isolation. Everything
            else is identical.
        seed: Reproducibility seed.
        budget: Verification budget. Defaults to unlimited, which is the
            comparison that isolates *how many* checks each arm needs.
        policy_params: Trigger settings.
    """
    cfg = scenario or DelegationScenario()
    rng = random.Random(seed)

    engine = AttestEngine(
        trust_params=TrustParams.from_event_interval(cfg.step_seconds),
        policy_params=policy_params
        or PolicyParams(cooldown_seconds=8 * cfg.step_seconds),
        budget=budget if budget is not None else Budget.unlimited(),
    )

    fleet = [
        _Orchestrator(
            agent_id=f"orch-{i}",
            workers=[f"orch-{i}-w{j}" for j in range(cfg.workers_each)],
        )
        for i in range(cfg.orchestrators)
    ]
    compromised_now: set[str] = set()

    verifications = useful = wasted = 0
    episodes = contained = 0
    delays: list[int] = []
    steps = 0
    # Containment truncates an episode, so elapsed compromised steps are not a
    # denominator - they already reflect the intervention. Exposure is measured
    # against how long each takeover would have run unchecked, recorded at onset.
    intended_steps = 0
    exposed_steps = 0
    visibility = cfg.detector_quality / (cfg.detector_quality + 1.0)

    def handle(decision, step: int) -> None:
        """Apply verification semantics: a check reveals only its own target."""
        nonlocal verifications, useful, wasted, contained
        if decision.action is not Action.VERIFY:
            return
        verifications += 1
        target = decision.verification_target
        if target not in compromised_now:
            # Clean agent, clean result, nothing changes. Whoever is actually
            # directing the traffic carries on untouched.
            wasted += 1
            return

        useful += 1
        contained += 1
        for orch in fleet:
            if orch.agent_id == target and orch.episode_open:
                delays.append(step - orch.onset_step)
                orch.remaining = 0
                orch.guard = cfg.guard_steps
                orch.episode_open = False
                compromised_now.discard(target)

    for step in range(cfg.steps):
        t = step * cfg.step_seconds

        for orch in fleet:
            if orch.remaining > 0:
                orch.remaining -= 1
                if orch.remaining == 0:
                    orch.guard = cfg.guard_steps
                    orch.episode_open = False
                    compromised_now.discard(orch.agent_id)
            elif orch.guard > 0:
                orch.guard -= 1
            elif rng.random() < cfg.attack_hazard:
                length = max(5, int(rng.expovariate(1.0 / cfg.episode_mean)))
                orch.remaining = length
                orch.onset_step = step
                orch.episode_open = True
                compromised_now.add(orch.agent_id)
                episodes += 1
                intended_steps += length

            if orch.compromised:
                exposed_steps += 1

            # The orchestrator's own traffic stays unremarkable: a compromised
            # principal that only issues instructions has nothing visibly wrong
            # about the instructions themselves. This is precisely the case
            # per-agent scoring cannot see.
            handle(
                engine.observe(_envelope(rng, orch.agent_id, t, hostile=False)), step
            )
            steps += 1

            for worker in orch.workers:
                hostile = orch.compromised and rng.random() < visibility
                chain = (orch.agent_id,) if chain_aware else ()
                handle(
                    engine.observe(
                        _envelope(
                            rng, worker, t, hostile=hostile, on_behalf_of=chain
                        )
                    ),
                    step,
                )
                steps += 1

    return DelegationOutcome(
        verifications=verifications,
        useful=useful,
        wasted=wasted,
        episodes=episodes,
        contained=contained,
        exposure=exposed_steps / intended_steps if intended_steps else 0.0,
        median_delay=statistics.median(delays) if delays else None,
        steps=steps,
    )


def compare(
    scenario: DelegationScenario | None = None, *, seed: int = 0
) -> dict[str, DelegationOutcome]:
    """Run both arms over the same scenario."""
    return {
        "chain-aware": run_scenario(scenario, chain_aware=True, seed=seed),
        "chain-blind": run_scenario(scenario, chain_aware=False, seed=seed),
    }
