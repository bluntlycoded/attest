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

## Real-corpus evaluation

Everything above is measured on sessions this project generated, which is the
single biggest weakness in the whole argument. `attest evaluate` runs the same
four policies and four metrics against a corpus somebody else collected and
labelled:

```bash
attest evaluate --auth auth.txt.gz --redteam redteam.txt.gz
```

The target is LANL's *Comprehensive, Multi-Source Cyber-Security Events* (Kent, 2015) — 58 days of Windows authentication from a real enterprise network, 1.6 billion events across 12,425 accounts, with published red team ground truth. It is the closest public analogue: a real entity stream, real behaviour, labels assigned by someone with no stake in this result.

The pipeline is built and tested end to end:

- `datasets/lanl.py` streams `auth.txt.gz` (7.2 GB) and filters in one pass, never decompressing to disk
- `learn.py` fits the perception stage — logistic regression, minibatch SGD, prior correction, temperature calibration, no dependencies
- Splits are **entity-grouped and stratified**; coefficients, temperature and evaluation each see a disjoint set of accounts
- Detection quality (ROC-AUC, PR-AUC, ECE) is reported next to the scheduling result, because a scheduler on a weak risk model looks bad for reasons that have nothing to do with scheduling

**The number does not exist yet.** LANL moved the corpus behind a request to `cyberdata@lanl.gov`, so it has not been run on real data. What has been run is a fixture in exact LANL wire format, which proves the plumbing and nothing else — the model promptly found the fixture's tell (a giveaway `auth_type`, coefficient +9.4) and scored ROC-AUC 0.999, which is what a fixture does, not what a corpus does.

A labelling decision worth knowing before reading any eventual result: the red team file marks *individual* events, but compromise is a state. An episode is taken as the interval from an account's first red team event to its last, with every event in between labelled compromised. That inflates the positive class relative to the raw file, and results move if you change it. `--strict-labels` marks only the literal events, for comparison.

## Delegation chains

Scoring each agent alone misses the failure that matters most: a compromised orchestrator that never touches anything sensitive itself, and instead has five perfectly healthy workers do it. Its own messages look ordinary, because all it sends is instructions.

Two mechanisms, deliberately asymmetric:

- **Effective trust flows down.** An action is worth no more than the weakest link in the chain that authorised it. The policy runs against the chain's effective trust, not the sender's own — and the worker's own score is left untouched, because the worker did nothing wrong.
- **Bad evidence flows up.** A delegate's misbehaviour is charged, in part, to its principal. Good evidence does not flow up: otherwise a compromised principal could rebuild its score by having a healthy delegate do a lot of innocuous work.

The scheduling consequence is the point. A verification is aimed at the **weakest link**, not the sender. Challenging a spotless worker returns clean and contains nothing, while the principal directing it carries on.

```bash
attest delegation
```

```
arm                contained    exposure   budget/1k      wasted       delay
chain-aware            17/17       0.050        0.47        0/17         3.0
chain-blind             0/16       0.945        2.56       92/92         n/a
```

Both arms are the same engine; the blind one simply never sees the chain, which is what every agent-identity system does today. It contains nothing and every one of its 92 checks is wasted on an agent that really was clean.

**This is one specific hole, not a general improvement.** Where the acting agent is itself the compromised party, the two arms are identical by construction — the weakest link is the sender either way. The scenario is constructed to expose the gap.

The `backflow` default of 0.5 came out of the ablation rather than taste. Below ~0.25 the principal never sinks past the delegate doing its dirty work, so every check lands on the delegate and containment collapses to zero:

| backflow | contained | exposure | budget/1k | wasted |
|---|---|---|---|---|
| 0.00 | 0/70 | 0.923 | 2.48 | 100% |
| 0.25 | 71/83 | 0.147 | 3.04 | 84% |
| **0.50** | **82/82** | **0.064** | **0.57** | **0%** |
| 1.00 | 93/93 | 0.029 | 0.65 | 0% |

## Where the risk score comes from

`LogisticRiskScorer` ships **stated prior weights, not fitted ones** — cryptographic failures (bad signature, expired credential, unlogged envelope) weighted heavily, behavioural novelty (new peer, new intent, burst rate) weighted lightly. Every weight is a guess. The interface is the one a trained model will have, and `Calibrator` exists from the start so calibration is not retrofitted later.

The intended path: run in shadow mode, collect outcomes, fit the calibrator on real labels, then replace the scorer.

## Design

Derived from the re-verification pipeline in *An Interpretable Sequence Model for Adaptive Re-Verification in Zero-Trust Intrusion Detection*, with the perception stage re-targeted from IoT network flows to agent message streams and forgetting re-parameterised from discrete steps to wall-clock time.

Reference parameters (`γ = 0.94`, `w = 2`, `θ_low = 0.5`, `θ_high = 0.65`, cooldown 8) come from that work. Configure `TrustParams.from_recovery_time()` from a stated policy requirement rather than picking a decay constant off a validation curve.

## Running the service and console

```bash
pip install -e ".[dev]"
uvicorn service.app:app --port 8317
```

```bash
cd console && npm install && npm run dev
```

The console is at `http://localhost:3317`. Press **Start simulated feed** on the Fleet page — nothing else is needed, and in particular the SAMACP stack does not have to be running.

Five pages: **Fleet** (every agent, least trusted first), **Agent detail** (trust trajectory with verification markers and the hysteresis band), **Decisions** (live SSE stream with a reason breakdown), **Frontier** (the budget–exposure sweep), and **Settings** (parameters set from a stated recovery requirement, not a raw decay constant).

`/metrics` reports only operational counters. Exposure, containment and onset delay need ground truth no live deployment has, so they appear on the Frontier page — computed on generated sessions — and nowhere else.

## Feeding it real traffic

```bash
pip install -e ".[samacp]"
curl -X POST localhost:8317/ingest/samacp -d @envelope.json -H 'Content-Type: application/json'
```

The adapter verifies the Ed25519 signature against the sender's ANS-registered key, the credential's expiry and revocation, and the Merkle inclusion proof.

**Unverifiable is not invalid.** If the ANS is unreachable we cannot resolve keys — but an ANS outage is not evidence any agent is compromised, and treating unknown as failed would drive the whole fleet's trust to zero at once and spend the entire budget on an infrastructure problem. Unknowns fail open and are counted in `/metrics`. Set `unknown_is_invalid=True` to reverse it.

## One thing that will bite you

`step_seconds` must track how often an agent actually emits. Steady-state evidence accumulates to roughly `1 / (1 - γ^(interval / step_seconds))`. Leave it at a wall-clock default while agents emit every 30 ms and that figure reaches several hundred — at which point no realistic compromise episode can bank enough bad evidence to overcome it, and **the trigger silently never fires**. There is no error; trust simply sits high forever.

Use `TrustParams.from_event_interval(seconds)`, or let `/feed/start` tune it.

## Status

Early. The engine, metrics, benchmark, delegation-chain trust, SAMACP adapter, real-corpus harness, service and console are built and tested (213 tests). Not yet built: a real verifier beyond credential revocation, and any evaluation against non-synthetic data. The second of those is the one that decides whether the thesis holds.

## Licence

MIT
