"""Pending approvals, answered out of band.

A verifier cannot block waiting for a person. Most of what agents do happens
without anyone watching, and a synchronous consent model only works if the user
happens to be at their desk at that moment - which quietly pushes teams back to
broad standing approvals, the thing the whole design exists to avoid.

So an approval is opened, the request is held, and the answer arrives later
through whatever channel the reviewer actually uses. This is the same shape as
CIBA's decoupled authentication flow: the thing needing authorisation and the
person granting it are not in the same session.

Two rules the queue enforces rather than leaves to callers:

An expired request is a timeout, never an approval
    A held action that nobody answered is abandoned. Silence is not consent,
    and a queue that quietly let requests age into approval would approve most
    reliably at exactly the moments reviewers were most overloaded.

An answer is recorded once
    Deciding a request twice, or deciding one that already expired, is
    rejected rather than silently applied. Approval records are audit
    evidence, and evidence that can be overwritten is not evidence.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from .approval import ApprovalRecord, Outcome
from .packet import DecisionPacket, Tier

__all__ = ["PendingApproval", "ApprovalQueue"]


@dataclass
class PendingApproval:
    """One request awaiting an answer."""

    request_id: str
    packet: DecisionPacket
    tier: Tier
    opened_at: float
    expires_at: float
    outcome: Outcome | None = None
    approver: str | None = None
    decided_at: float | None = None

    @property
    def resolved(self) -> bool:
        return self.outcome is not None

    def expired(self, now: float) -> bool:
        return not self.resolved and now >= self.expires_at

    @property
    def latency_seconds(self) -> float | None:
        if self.decided_at is None:
            return None
        return max(0.0, self.decided_at - self.opened_at)


class ApprovalQueue:
    """Holds requests until a person answers, or until they age out."""

    def __init__(self) -> None:
        self._pending: dict[str, PendingApproval] = {}
        self._history: list[PendingApproval] = []
        self._ids = itertools.count(1)

    def open(self, packet: DecisionPacket) -> PendingApproval:
        """Raise an approval request for ``packet``."""
        request = PendingApproval(
            request_id=f"apr-{next(self._ids):06d}",
            packet=packet,
            tier=packet.risk.tier,
            opened_at=packet.requested_at,
            expires_at=packet.expires_at,
        )
        self._pending[request.request_id] = request
        return request

    def get(self, request_id: str) -> PendingApproval | None:
        return self._pending.get(request_id) or next(
            (r for r in self._history if r.request_id == request_id), None
        )

    def pending(self, now: float | None = None, tier: Tier | None = None):
        """Requests still awaiting an answer, oldest first."""
        out = [
            r
            for r in self._pending.values()
            if (now is None or not r.expired(now))
            and (tier is None or r.tier is tier)
        ]
        return sorted(out, key=lambda r: r.opened_at)

    def decide(
        self,
        request_id: str,
        approver: str,
        outcome: Outcome,
        at: float,
    ) -> ApprovalRecord:
        """Record a person's answer.

        Raises:
            KeyError: If the request is unknown.
            ValueError: If it was already answered, has expired, or the
                outcome is not a judgement a person can make.
        """
        # Look through settled requests too. A second answer to an already
        # decided request is a different problem from an answer to one that
        # never existed, and reporting the second as the first sends whoever
        # is investigating a duplicate approval down the wrong path.
        request = self.get(request_id)
        if request is None:
            raise KeyError(f"unknown approval request {request_id!r}")
        if request.resolved:
            raise ValueError(
                f"{request_id} was already {request.outcome.value} by "
                f"{request.approver}"
            )
        if at >= request.expires_at:
            raise ValueError(
                f"{request_id} expired at {request.expires_at}; reopen rather "
                "than answering late"
            )
        if outcome not in (Outcome.APPROVED, Outcome.REJECTED):
            raise ValueError(
                f"a reviewer can only approve or reject, not {outcome.value}"
            )

        request.outcome = outcome
        request.approver = approver
        request.decided_at = at
        self._retire(request)

        return ApprovalRecord(
            agent_id=request.packet.target,
            approver=approver,
            outcome=outcome,
            requested_at=request.opened_at,
            latency_seconds=request.latency_seconds or 0.0,
        )

    def expire(self, now: float) -> list[PendingApproval]:
        """Age out unanswered requests. Returns the ones that timed out."""
        timed_out = [r for r in self._pending.values() if r.expired(now)]
        for request in timed_out:
            request.outcome = Outcome.TIMEOUT
            request.decided_at = now
            self._retire(request)
        return timed_out

    def _retire(self, request: PendingApproval) -> None:
        self._pending.pop(request.request_id, None)
        self._history.append(request)

    @property
    def history(self) -> list[PendingApproval]:
        return list(self._history)

    def counts(self) -> dict[str, int]:
        """Queue health, for the metrics endpoint."""
        tally = {"pending": len(self._pending)}
        for request in self._history:
            key = request.outcome.value if request.outcome else "unknown"
            tally[key] = tally.get(key, 0) + 1
        return tally

    def __len__(self) -> int:
        return len(self._pending)
