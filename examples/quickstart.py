"""A compromised agent, watched from first contact to containment.

Run with::

    python examples/quickstart.py

Shows the two behaviours the design turns on: an agent that behaves normally is
left alone indefinitely, and one whose envelopes start failing verification is
challenged within a few steps - once, not repeatedly.
"""

from attest import Action, AttestEngine, Budget, Envelope, PolicyParams, TrustParams


def envelope(agent: str, t: float, *, healthy: bool = True) -> Envelope:
    return Envelope(
        sender=agent,
        recipient="tool-search" if healthy else "tool-exfil",
        intent="core",
        action="query" if healthy else "bulk_export",
        timestamp=t,
        signature_valid=healthy,
        credential_valid=healthy,
        audit_proof=f"merkle:{int(t)}" if healthy else None,
    )


def main() -> None:
    engine = AttestEngine(
        trust_params=TrustParams(),
        policy_params=PolicyParams(theta_low=0.5, theta_high=0.65, cooldown_seconds=8.0),
        budget=Budget.per_thousand_steps(rate=8.5, step_seconds=1.0),
        shadow=True,
    )

    print(f"{'step':>5}  {'state':<10}  {'p':>6}  {'trust':>6}  action")
    print("-" * 48)

    # 120 steps of ordinary work, then the agent is taken over.
    for t in range(200):
        healthy = t < 120
        decision = engine.observe(envelope("agent-7", float(t), healthy=healthy))

        interesting = (
            t % 20 == 0
            or decision.action is Action.VERIFY
            or 118 <= t <= 124
        )
        if interesting:
            marker = "  <-- verify" if decision.action is Action.VERIFY else ""
            print(
                f"{t:>5}  {'benign' if healthy else 'compromised':<10}  "
                f"{decision.p:>6.3f}  {decision.trust:>6.3f}  "
                f"{decision.action.value}{marker}"
            )

    print()
    print(f"trust now              : {engine.trust_of('agent-7'):.3f}")
    print(f"trust after a day idle : {engine.trust_of('agent-7', now=200 + 86400):.3f}")
    print("\nAn idle agent returns to the 0.5 prior - a past verification stops")
    print("counting for anything once it is old enough.")


if __name__ == "__main__":
    main()
