"""Synthetic traffic feed.

Drives a fleet of simulated agents through the engine so the console has
something live to render without requiring the SAMACP stack to be running.

The dynamics mirror :mod:`attest.simulate`: each agent runs a two-state process
with a per-step hazard of being taken over, a geometric episode length, and a
benign guard interval afterwards. What differs is that a compromise here shows
up as *observable envelope properties* - a bad signature, an expired credential,
an unlogged message, a peer the agent has never spoken to - rather than as a
pre-baked probability. That means the risk scorer is genuinely in the loop,
which is the point of using this to exercise the console.

This is a demonstration and development aid. Numbers it produces describe the
simulator, not any real deployment.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field

from attest import Envelope

__all__ = ["SimulatedFeed", "FeedConfig"]

_BENIGN_PEERS = ("tool-search", "tool-docs", "tool-calendar", "agent-planner")
_BENIGN_ACTIONS = ("query", "summarise", "lookup", "schedule")
_HOSTILE_PEERS = ("tool-exfil", "agent-unknown", "tool-shell", "host-external")
_HOSTILE_ACTIONS = ("bulk_export", "escalate", "spawn", "disable_audit")


@dataclass
class FeedConfig:
    agents: int = 12
    steps_per_second: float = 20.0
    detector_quality: float = 9.0
    seed: int = 0
    attack_hazard: float = 0.01
    episode_mean: float = 60.0
    guard_steps: int = 30


@dataclass
class _AgentSim:
    """Per-agent simulation state."""

    agent_id: str
    remaining: int = 0
    guard: int = 0
    peers: tuple[str, ...] = field(default=_BENIGN_PEERS)

    @property
    def compromised(self) -> bool:
        return self.remaining > 0


class SimulatedFeed:
    """Background task pushing generated envelopes into the engine.

    Args:
        state: The service state whose engine receives the traffic.
        config: Fleet size, rate and generator settings.
    """

    def __init__(self, state, config: FeedConfig) -> None:
        self.state = state
        self.config = config
        self.emitted = 0
        self._rng = random.Random(config.seed)
        self._task: asyncio.Task | None = None
        self._stopping = False
        self._agents = [
            _AgentSim(agent_id=f"agent-{i:02d}") for i in range(config.agents)
        ]
        # Probability that a compromised step actually looks wrong on the wire.
        k = config.detector_quality
        self._visibility = k / (k + 1.0)

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def compromised_now(self) -> list[str]:
        """Ground truth, which only the simulator has."""
        return [a.agent_id for a in self._agents if a.compromised]

    def start(self) -> None:
        if self.running:
            return
        self._stopping = False
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stopping = True
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=2.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None

    def _advance(self, sim: _AgentSim) -> None:
        """Move one agent's two-state process forward one step."""
        if sim.remaining > 0:
            sim.remaining -= 1
            if sim.remaining == 0:
                sim.guard = self.config.guard_steps
            return
        if sim.guard > 0:
            sim.guard -= 1
            return
        if self._rng.random() < self.config.attack_hazard:
            # Geometric episode length, same shape as the offline generator.
            mean = self.config.episode_mean
            sim.remaining = max(
                5, int(self._rng.expovariate(1.0 / mean)) if mean > 0 else 5
            )

    def _envelope(self, sim: _AgentSim, now: float) -> Envelope:
        """Build one envelope reflecting the agent's current true state."""
        if sim.compromised and self._rng.random() < self._visibility:
            # A visible compromise: something about the message is wrong.
            flavour = self._rng.random()
            return Envelope(
                sender=sim.agent_id,
                recipient=self._rng.choice(_HOSTILE_PEERS),
                intent="core",
                action=self._rng.choice(_HOSTILE_ACTIONS),
                timestamp=now,
                signature_valid=flavour > 0.35,
                credential_valid=flavour > 0.65 or flavour < 0.35,
                audit_proof=None if flavour > 0.5 else f"merkle:{self.emitted}",
            )

        return Envelope(
            sender=sim.agent_id,
            recipient=self._rng.choice(_BENIGN_PEERS),
            intent="core",
            action=self._rng.choice(_BENIGN_ACTIONS),
            timestamp=now,
            signature_valid=True,
            credential_valid=True,
            audit_proof=f"merkle:{self.emitted}",
        )

    async def _run(self) -> None:
        interval = 1.0 / self.config.steps_per_second
        now = 0.0
        # Give every agent a clean history first, so novelty signals mean
        # something and the fleet does not start out uniformly suspicious.
        loop = asyncio.get_running_loop()
        start_wall = loop.time()

        while not self._stopping:
            sim = self._agents[self.emitted % len(self._agents)]
            self._advance(sim)
            now = start_wall + self.emitted * interval

            try:
                self.state.engine.observe(self._envelope(sim, now))
            except Exception:
                # A feed must never take the service down. Drop the step.
                pass
            self.emitted += 1

            await asyncio.sleep(interval)
