# Attest

**A trust layer for AI agents that decides *when* to re-verify an agent's identity, under a fixed budget of disruptive verifications.**

Zero trust says an agent verified an hour ago is not necessarily trustworthy now. Acting on that costs something — a re-attestation handshake, a rotated credential, an interrupted human. A monitor cannot spend that on every agent at every step, so it has to choose.

Most of the agent-identity field verifies an agent once at discovery and then stops. The runtime-governance field proposes trust engines and publishes no accuracy numbers. The step-up standards (RFC 9470, CIBA) specify *how* to verify and are silent on *when*. Nobody publishes a verification budget.

This library is the missing scheduler.

## Install

```bash
pip install -e .
```

No runtime dependencies. Python 3.10+.

## The pipeline

Three stages, of which only the first would ever be learned:

| Stage | Module | What it does | Learned? |
|---|---|---|---|
| Perception | `attest.evidence` | Agent's signed message stream → calibrated compromise probability | Eventually |
| Trust | `attest.trust` | Probability stream → bounded trust score, fast to burn, slow to rebuild | No — two counters |
| Policy | `attest.policy` | Trust score → observe-or-verify, under a budget | No — three thresholds |

Everything downstream of the probability is arithmetic an operator can read. That is deliberate: the part of the system that acts on production traffic should not be something anyone has to take on faith.

## Use

```python
from attest import AttestEngine, Envelope, Budget, TrustParams

engine = AttestEngine(
    trust_params=TrustParams.from_recovery_time(24 * 3600),  # a day to earn trust back
    budget=Budget.per_thousand_steps(rate=8.5, step_seconds=1.0),
    shadow=True,  # decide, record, do not act
)

decision = engine.observe(Envelope(
    sender="agent-7",
    recipient="tool-search",
    intent="core",
    action="query",
    timestamp=time.time(),
    signature_valid=True,
    credential_valid=True,
    audit_proof="merkle:0x9f...",
))

print(decision.action, decision.trust)
```

Shadow mode suppresses only the external side effect. Trust still resets, the trigger still disarms, budget is still spent — so a shadow run reports the numbers enforcement would have produced. Swap in a `verifier` and set `shadow=False` to act.

Three properties worth knowing:

- **Idle agents lose standing.** With no traffic both counters decay and trust returns to the 0.5 prior. A stale verification stops conferring trust, which is the whole zero-trust premise.
- **Forgetting is wall-clock, not per-event.** Fifty envelopes in a second do not age the score like fifty envelopes across an hour.
- **Trust burns faster than it recovers.** `w = 2` weights bad evidence over good.

## Results

```bash
attest frontier --sessions 400
attest bench --sessions 400 --ci
```

On 400 generated sessions (102,400 steps, 1,212 attack episodes), 95% CIs from a session-grouped bootstrap:

| Policy | Budget /1k | Exposure | False verifications /1k benign | Contained |
|---|---|---|---|---|
| **Beta-trust, θ=0.5** | **9.12** | **0.375** | **0.108** | 0.764 |
| Periodic, k=16 | 62.50 | 0.325 | 61.83 | 0.792 |
| Periodic, k=128 | 7.81 | 0.905 | 7.88 | 0.179 |
| Raw threshold, θ=0.995 | 9.67 | 0.519 | 0.000 | 0.527 |

Two readings, both fair:

- **Against periodic verification** — which is what fixed session expiry and calendar credential rotation actually are — the adaptive policy reaches comparable exposure at **about a seventh of the budget** and **roughly 570× fewer false verifications**. A clock fires regardless of what the agent is doing; a trust score does not.
- **Against thresholding the same probabilities** at matched budget, integrating evidence over time contains 76% of episodes where instantaneous thresholding contains 53%. Held to the same spend, a raw threshold has to sit so close to certainty that it discards all sub-certain evidence.

### What these numbers are not

The sessions are synthetic and the detector is modelled — a pair of Beta distributions whose separation stands in for detector quality. There is no public corpus of compromised AI agents, so this measures **the scheduler, holding perception fixed**. It is not evidence about how well any risk model detects real compromise.

Two honest caveats the benchmark surfaces:

- Under a hard token-bucket budget cap (`--budget`), rather than a tuned threshold, raw thresholding does *better* than the trust layer on this generator. The simulated detector is close to an oracle, and when scores are that clean there is little sub-certain evidence left for the trust layer to integrate. The advantage above is real but it lives in the threshold-tuning framing, not every framing.
- **The trust calculus requires calibrated probabilities.** The recurrence treats `p` as an expected count of bad evidence. If a benign agent's scores average far above zero, `w` scales that into a steady-state trust below `θ_low`, and the policy fires on well-behaved agents and then disarms. `attest bench --detector-quality 1.5` shows this failure outright: containment collapses to 0.017. This is pinned by a test so it cannot quietly disappear.

## Where the risk score comes from

`LogisticRiskScorer` ships **stated prior weights, not fitted ones** — cryptographic failures (bad signature, expired credential, unlogged envelope) weighted heavily, behavioural novelty (new peer, new intent, burst rate) weighted lightly. Every weight is a guess. The interface is the one a trained model will have, and `Calibrator` exists from the start so calibration is not retrofitted later.

The intended path: run in shadow mode, collect outcomes, fit the calibrator on real labels, then replace the scorer.

## Design

Derived from the re-verification pipeline in *An Interpretable Sequence Model for Adaptive Re-Verification in Zero-Trust Intrusion Detection*, with the perception stage re-targeted from IoT network flows to agent message streams and forgetting re-parameterised from discrete steps to wall-clock time.

Reference parameters (`γ = 0.94`, `w = 2`, `θ_low = 0.5`, `θ_high = 0.65`, cooldown 8) come from that work. Configure `TrustParams.from_recovery_time()` from a stated policy requirement rather than picking a decay constant off a validation curve.

## Status

Early. The engine, metrics and benchmark are real and tested (87 tests). Not yet built: a SAMACP transport adapter, a real verifier implementation, and any evaluation against non-synthetic data. Those are the next three things.

## Licence

MIT
