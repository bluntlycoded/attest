"""Attest - decide when to re-verify an agent's identity, under a budget.

Zero trust says an agent verified an hour ago is not necessarily trustworthy
now. Acting on that costs something: a re-attestation handshake, a rotated
credential, an interrupted human. A monitor cannot spend that on every agent at
every step, so it has to choose. This library is the chooser.

Three stages, of which only the first would ever be learned:

perception (:mod:`attest.evidence`)
    Maps an agent's signed message stream to a calibrated probability that it
    is currently compromised.
trust (:mod:`attest.trust`)
    An exponentially-forgetting Beta-reputation update folds that probability
    stream into a bounded score. Two counters, nothing learned.
policy (:mod:`attest.policy`)
    A two-threshold hysteresis rule with a cooldown turns the score into an
    observe-or-verify decision under an explicit budget.

Everything downstream of the probability is arithmetic an operator can read,
which is deliberate: the part of the system that acts on production traffic
should not be something anyone has to take on faith.
"""

from .approval import (
    AdaptiveThresholds,
    ApprovalPolicy,
    ApprovalRecord,
    Outcome,
    RubberStampDetector,
)
from .delegation import ChainTrust, DelegationParams, effective_trust
from .engine import AttestEngine, Decision, Verification, Verifier
from .evidence import AgentProfile, Calibrator, Envelope, LogisticRiskScorer
from .metrics import Metrics, StepRecord, bootstrap_ci, evaluate
from .policy import Action, Budget, PolicyParams, PolicyState, decide
from .store import AgentRecord, InMemoryStore, JsonFileStore, StateStore
from .trust import TrustParams, TrustState

__version__ = "0.1.0"

__all__ = [
    "AgentProfile",
    "RubberStampDetector",
    "Outcome",
    "ApprovalRecord",
    "ApprovalPolicy",
    "AdaptiveThresholds",
    "AgentRecord",
    "Action",
    "AttestEngine",
    "Budget",
    "ChainTrust",
    "Calibrator",
    "Decision",
    "DelegationParams",
    "Envelope",
    "InMemoryStore",
    "JsonFileStore",
    "LogisticRiskScorer",
    "Metrics",
    "PolicyParams",
    "PolicyState",
    "StateStore",
    "StepRecord",
    "TrustParams",
    "TrustState",
    "Verification",
    "Verifier",
    "bootstrap_ci",
    "decide",
    "effective_trust",
    "evaluate",
    "__version__",
]
