# Attest

**A trust layer for AI agents that decides *when* to re-verify an agent's identity, and what to put in front of the person who has to answer — under a fixed budget of interruptions.**

Zero trust says an agent verified an hour ago is not necessarily trustworthy now. Acting on that costs something: a re-attestation handshake, a rotated credential, an interrupted human. A monitor cannot spend that on every agent at every step, so it has to choose.

Most of the agent-identity field verifies an agent once at discovery and then stops. The runtime-governance field proposes trust engines and publishes no accuracy numbers. The step-up standards (RFC 9470, CIBA) specify *how* to verify and are silent on *when*. Gateways enforce spend caps and rate limits and have no opinion about when a person should look.

Nobody publishes a verification budget. That is the gap this fills.

---

## The loop

```
tool call ──▶ gateway ──▶ allow          (routine, and it stays routine)
                     ├──▶ hold  ──▶ decision packet ──▶ a person
                     └──▶ deny          (already judged; do not ask again)
                                              │
                          answer ─────────────┘
                                              ▼
                       trust adjusts · threshold adapts · was anyone reading?
```

The last line is the part that does not exist elsewhere. An approval is evidence, so it feeds back. Thresholds move so an agent that keeps passing is interrupted less. And the system measures whether its own reviewers are still reading, because a gate that has decayed into a rubber stamp looks identical to a healthy one from every other angle — the approvals still arrive, the audit log still fills.

## Quick start

```bash
make install                                   # library, service, console
make test                                      # 366 tests
make delegation                                # the headline result, in ten seconds
```

To see it running:

```bash
export ATTEST_BOOTSTRAP_KEY="$(openssl rand -base64 32)"
make api          # terminal 1  -> :8317
make console      # terminal 2  -> :3317
make demo         # terminal 3  -> live traffic and two actions held for a person
```

Then open <http://localhost:3317/approvals>.

The core library has **no runtime dependencies** — CI installs it bare and asserts it still works. Python 3.10+. The SAMACP adapter and the HTTP service pull their own extras. Copy `.env.example` for the full set of settings.

To put it on the internet instead, see [DEPLOY.md](DEPLOY.md) — including why the console's token is public by construction and what that means for which key you give it.

## The pipeline

Three stages, of which only the first would ever be learned:

| Stage | Module | What it does | Learned? |
|---|---|---|---|
| Perception | `attest.evidence`, `attest.learn` | Message stream → calibrated compromise probability | Eventually |
| Trust | `attest.trust` | Probability stream → bounded score, fast to burn, slow to rebuild | No — two counters |
| Policy | `attest.policy` | Score → observe-or-verify, under a budget | No — three thresholds |

Everything downstream of the probability is arithmetic an operator can read. That is deliberate: the part of the system that acts on production traffic should not be something anyone has to take on faith.

```python
from attest import AttestEngine, Budget, Envelope, TrustParams

engine = AttestEngine(
    trust_params=TrustParams.from_recovery_time(24 * 3600),  # a day to earn trust back
    budget=Budget.per_thousand_steps(rate=8.5, step_seconds=1.0),
    shadow=True,  # decide, record, do not act
)

decision = engine.observe(Envelope(
    sender="agent-7", recipient="tool-search", intent="core", action="query",
    timestamp=time.time(), signature_valid=True, credential_valid=True,
    audit_proof="merkle:0x9f...",
))
```

Three properties worth knowing:

- **Idle agents lose standing.** With no traffic both counters decay and trust returns to the 0.5 prior. A stale verification stops conferring trust, which is the whole zero-trust premise.
- **Forgetting is wall-clock, not per-event.** Fifty messages in a second do not age the score like fifty across an hour.
- **Trust burns faster than it recovers.** `w = 2` weights bad evidence over good.

Shadow mode suppresses only the external side effect. Trust still resets, the trigger still disarms, budget is still spent. It predicts enforcement **up to the first informative outcome** — a shadow deployment never learns what a reviewer would have said, so it cannot reproduce the state an approval or rejection leaves behind.

## What the reviewer sees

Timing the question well and then asking it badly produces a rubber stamp on a schedule. `attest.packet` assembles enough to answer without guessing:

```
agent-07 wants to run: bulk_export
  Exports customer records to an external destination.
  on: customers (41,220 rows)

  reversibility : irreversible
  escalated because: cannot be undone; high-consequence tool;
                     unlike anything this agent has done before; touches sensitive data
  trust         : 0.940 (chain 0.210 via orch-planner)
  note          : the weak link is orch-planner, not the sender
  arguments     : sha256 7fc58b52526f53fe

  what led here:
    [ok ] search -> docs/pricing
    [ok ] draft_email -> vendor-3

  expires in 300s - no answer means the action is abandoned, not allowed
```

**Risk comes from an operator-owned `ToolCatalog`, never from the agent.** Tool annotations arrive over the same channel as the request; an agent able to label its own action "read-only" would. An uncatalogued tool is treated as irreversible, high-magnitude and sensitive — reaching for something nobody declared escalates rather than sails through.

**Escalation is the intersection of magnitude, reversibility and novelty**, combined with a geometric mean so a low value on any axis pulls the result down. An arithmetic mean lets a large but routine and reversible action escalate on size alone, which is what produces constant interruptions under load. Low trust raises severity but cannot invent it: a distrusted agent reading a public document is still reading a public document.

**Arguments are hashed, not carried.** A payload routinely holds exactly the customer data an approval should never copy into a chat channel.

Three tiers — `AUTO`, `OWNER`, `AUTHORITY` — and the last two are deliberately distinct. Routing an unusual API call and a $50,000 transfer to the same overloaded on-call gets both the same low attention, and it is the second that needed care.

## Closing the loop

An answer is evidence in its own right. Discarding it leaves an agent a person just vouched for in exactly the state of one they just rejected, and teaches the reviewer their answer changed nothing.

- **Approval** credits good evidence and leaves the agent above the prior. **Rejection** charges bad evidence.
- **A timeout is not an approval.** Reading silence as consent approves everything precisely when reviewers are most overloaded. It has to be opted into.
- **Thresholds adapt per agent, bounded.** An agent repeatedly approved is interrupted less. The bound is the safety property: without it an agent drifts to a threshold that never fires, stops being checked, stops generating the approvals that would move it back, and a later compromise runs unopposed.
- **Drift decays.** In a well-tuned system verifications land almost only on agents that really are misbehaving, so nearly every outcome is a rejection — without decay the loop becomes a one-way ratchet that marks an agent compromised once as suspect forever.

Approval is asynchronous, in the shape of CIBA's decoupled flow, because a verifier cannot block on someone who is not at their desk. An expired hold becomes a denial, never a release.

### Is anyone still reading?

```
quick-clicker    26 decisions | 100% approved | 1.4s median | spread 0.06 | LOOKS HOLLOW
alice            41 decisions |  78% approved | 96s median  | spread 0.71 | reading
```

Three signals must agree — fast, uniform, near-total approval — because speed alone convicts the experienced and approval rate alone convicts anyone with a healthy fleet. What no attentive reviewer produces is all three at once.

This is also the EU AI Act Art. 14 story: *demonstrable* human oversight, where presence is not practice.

### Does the loop go unstable?

A closed loop on a control signal can run away. `attest.approval_sim` checks, across three kinds of reviewer:

```
attentive     62 checks | 62 rejections | contained 62/66 | exposure 0.118 | hollow no
rubber-stamp  59 checks | 59 approvals  | contained  0/61 | exposure 1.000 | hollow YES
absent        55 checks | 55 timeouts   | offset stayed exactly 0.000
```

Zero offset reversals in every arm — it converges rather than oscillating. The bound held at exactly −0.150 under blanket approval. And the loop does **not** make rubber-stamping worse than a static threshold; the harm there is the rubber-stamping, which is why it is measured.

## The gateway

```bash
curl -X POST localhost:8317/gateway/mcp?agent_id=agent-7 -d @tools_call.json
```

`attest.gateway` takes an intercepted tool call and returns allow, hold or deny. `from_mcp_request` adapts MCP's `tools/call`.

Two questions are kept separate. *Is this agent behaving* is temporal and belongs to the engine; *is this action consequential* is a property of the action and belongs to the catalogue. They fail in opposite directions.

**The verification budget governs proactive checks only.** It does not gate consequential actions — conflating them would mean a fleet that had spent its budget waved a wire transfer through precisely because it could not afford to look, and budget runs out exactly when things are going badly.

Fail-closed throughout: an uncatalogued tool is held, an unanswered hold denies, identity comes from what the gateway authenticated rather than from the payload, and a deeply distrusted agent is refused outright instead of generating a fresh approval per call.

## Delegation chains

Scoring each agent alone misses the failure that matters most: a compromised orchestrator that never touches anything sensitive itself and has five healthy workers do it. Its own messages look ordinary, because all it sends is instructions.

- **Effective trust flows down.** An action is worth no more than the weakest link that authorised it. The worker's own score is untouched — it did nothing wrong.
- **Bad evidence flows up**, gated by a threshold. Good evidence does not: otherwise a compromised principal rebuilds its score by delegating innocuous work.

A verification is aimed at the **weakest link**, not the sender. Challenging a spotless worker returns clean and contains nothing.

```bash
attest delegation
```

```
arm                contained    exposure   budget/1k      wasted       delay
chain-aware            17/17       0.050        0.47        0/17         3.0
chain-blind             0/16       0.945        2.56       92/92         n/a
```

Both arms are the same engine; the blind one never sees the chain, which is what every agent-identity system does today. **This closes one specific hole, not a general improvement** — where the acting agent is itself compromised, the two arms are identical by construction. The scenario is built to expose the gap.

The `backflow` default of 0.5 came out of an ablation, not taste. Below ~0.25 the principal never sinks past the delegate doing its dirty work, and containment collapses to zero.

## Results

```bash
attest frontier --sessions 400
attest bench --sessions 400 --ci
```

400 generated sessions, 102,400 steps, 1,212 episodes, 95% CIs from a session-grouped bootstrap:

| Policy | Budget /1k | Exposure | False verifications /1k benign | Contained |
|---|---|---|---|---|
| **Beta-trust, θ=0.5** | **9.12** | **0.375** | **0.108** | 0.764 |
| Periodic, k=16 | 62.50 | 0.325 | 61.83 | 0.792 |
| Periodic, k=128 | 7.81 | 0.905 | 7.88 | 0.179 |
| Raw threshold, θ=0.995 | 9.67 | 0.519 | 0.000 | 0.527 |

- **Against periodic verification** — what fixed session expiry and calendar credential rotation actually are — comparable exposure at **about a seventh of the budget** and **roughly 570× fewer false verifications**. A clock fires regardless of what the agent is doing.
- **Against thresholding the same probabilities** at matched budget, integrating evidence contains 76% of episodes where instantaneous thresholding contains 53%. Held to the same spend, a raw threshold sits so close to certainty it discards all sub-certain evidence.

### What these numbers are not

The sessions are synthetic and the detector is modelled. This measures **the scheduler, holding perception fixed**. It is not evidence about how well any risk model detects real compromise.

Two caveats the benchmark surfaces rather than hides:

- Under a hard token-bucket cap (`--budget`) rather than a tuned threshold, raw thresholding does *better* on this generator. The simulated detector is near-oracle, and when scores are that clean there is little sub-certain evidence left to integrate. The advantage above is real but lives in the threshold-tuning framing.
- **The trust calculus requires calibrated probabilities.** `attest bench --detector-quality 1.5` shows the failure outright: containment collapses to 0.017. Pinned by a test so it cannot quietly disappear.

## Real-corpus evaluation

Every number above comes from a generator written alongside the thing being measured. That is the single biggest weakness in the argument, and no amount of further synthetic work fixes it.

```bash
attest evaluate --auth auth.txt.gz --redteam redteam.txt.gz
```

The target is LANL's *Comprehensive, Multi-Source Cyber-Security Events* (Kent, 2015) — 58 days of Windows authentication from a real enterprise network, with published red team ground truth. `datasets/lanl.py` streams the 7.2 GB log and filters in one pass, never decompressing to disk. Splits are entity-grouped and stratified; coefficients, temperature and evaluation each see a disjoint set of accounts. Detection quality (ROC-AUC, PR-AUC, ECE) is reported next to the scheduling result, because a scheduler on a weak risk model looks bad for reasons that have nothing to do with scheduling.

**This has not been run on real data.** The harness is built and tested against a fixture in exact LANL wire format, which proves the plumbing and nothing else — the model promptly found the fixture's giveaway feature at coefficient +9.4 and scored ROC-AUC 0.999, which is what a fixture does.

Two other loaders exist and neither closes the gap:

| Corpus | Labels | Can measure |
|---|---|---|
| `datasets.sentry` | Detector-generated | All four metrics, but circularly — a policy scored against threshold-rule labels is marked wrong for firing earlier than the rule |
| `datasets.nodewatch` | None | Budget and interruption rate only; `shadow_corpus` refuses to invent an exposure number |

A labelling decision worth knowing: the red team file marks *individual* events, but compromise is a state. An episode is the interval from an account's first red team event to its last. That inflates the positive class; `--strict-labels` gives the alternative.

## Where the risk score comes from

`LogisticRiskScorer` ships **stated prior weights, not fitted ones** — cryptographic failures weighted heavily, behavioural novelty lightly. Every weight is a guess. `learn.LogisticModel` is the fittable version: logistic regression, minibatch SGD, prior correction for class weighting, temperature calibration, no dependencies, every coefficient printable.

The intended path is shadow mode → collect outcomes → calibrate → replace the scorer.

## Running it

```bash
export ATTEST_BOOTSTRAP_KEY="$(openssl rand -base64 32)"
uvicorn service.app:app --port 8317
```

```bash
cd console && NEXT_PUBLIC_ATTEST_TOKEN=... npm run dev   # http://localhost:3317
```

Six pages: **Fleet** (least trusted first), **Agent detail** (trust trajectory with verification markers and the hysteresis band), **Approvals** (queue, decision packets, oversight), **Decisions** (live SSE with reason codes), **Frontier** (the budget–exposure sweep), **Settings** (parameters and the tool catalogue).

Press **Start simulated feed** on the Fleet page — the SAMACP stack does not need to be running.

`/metrics` reports operational counters only. Exposure, containment and onset delay need ground truth no live deployment has, so they appear on the Frontier page and nowhere else.

### Authentication and tenancy

There is no anonymous path. A security control that answers to whoever asks is worse than no control, because it is trusted. The first credential comes from the environment rather than a database row, so an unconfigured install is unusable rather than open.

| Role | Can | Cannot |
|---|---|---|
| `ingest` | Submit traffic and tool calls | Approve, read the fleet, configure |
| `approver` | Also answer approvals, read the fleet | Change thresholds or mint keys |
| `admin` | Everything | — |

Roles are ordered by blast radius, not seniority. An ingest credential sits on every gateway node, so it is most likely to leak and can do least. An approver deliberately cannot change configuration: a reviewer able to widen the thresholds deciding what reaches them could quietly stop being asked.

Tokens are SHA-256 digests, returned exactly once. Each tenant gets its own engine, gateway, approval queue and catalogue over a tenant-scoped store — isolation by construction rather than a `WHERE` clause somebody has to remember. That extends to rubber-stamp statistics, which would otherwise let one customer's reviewers mask another's.

**The console's key is browser-visible by construction. Give it `approver`, never `admin`.**

## One thing that will bite you

`step_seconds` must track how often an agent actually emits. Steady-state evidence accumulates to roughly `1 / (1 - γ^(interval / step_seconds))`. Leave it at a wall-clock default while agents emit every 30 ms and that reaches several hundred — at which point no realistic compromise can bank enough bad evidence to overcome it, and **the trigger silently never fires**. There is no error; trust simply sits high forever.

Use `TrustParams.from_event_interval(seconds)`, or let `/feed/start` tune it.

## Design

Derived from the re-verification pipeline in *An Interpretable Sequence Model for Adaptive Re-Verification in Zero-Trust Intrusion Detection*, with the perception stage re-targeted from IoT network flows to agent message streams and forgetting re-parameterised from discrete steps to wall-clock time. The trust recurrence is Jøsang and Ismail's Beta reputation with exponential forgetting; the delegation discounting is a simplified, readable form of the same authors' operator.

## Status

**365 tests.** Built and tested: the engine, metrics and bootstrap, delegation-chain trust, the approval loop and rubber-stamp detection, decision packets, the gateway, the SAMACP adapter, the real-corpus harness with three loaders, the HTTP service with auth and tenancy, and the console.

Not built: deployment of any kind — it runs on localhost against a SQLite file — and enforcement actions beyond credential revocation.

Not answered: **the real-data number.** That is the one that decides whether the thesis holds, and it is waiting on a corpus rather than on code.

## Licence

MIT
