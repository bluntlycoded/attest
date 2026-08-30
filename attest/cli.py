"""Command-line entry point.

Two subcommands. ``bench`` replays generated sessions through several trigger
policies and prints the operational metrics side by side. ``frontier`` sweeps
the budget for the adaptive and periodic policies and prints the trade-off
curve, which is the comparison the whole design exists to make.
"""

from __future__ import annotations

import argparse
import sys

from .metrics import bootstrap_ci, evaluate
from .policy import Budget, PolicyParams
from .simulate import (
    BetaTrustPolicy,
    EwmaThresholdPolicy,
    GeneratorConfig,
    PeriodicPolicy,
    RawThresholdPolicy,
    benchmark,
    generate_sessions,
    run_policy,
)
from .trust import TrustParams


def _row(label: str, *cells: str, width: int = 16) -> str:
    return f"{label:<16}" + "".join(f"{c:>{width}}" for c in cells)


def _budget_factory(args: argparse.Namespace, config: GeneratorConfig):
    """Build a per-session budget factory, or None for unconstrained."""
    if args.budget is None:
        return None
    # Enough capacity for one session's share of the per-1000-step allowance,
    # with a floor of one so short sessions are not starved outright.
    capacity = max(1.0, args.budget * config.session_length / 1000.0)
    return lambda: Budget.per_thousand_steps(
        args.budget, config.step_seconds, capacity=capacity
    )


def _bench(args: argparse.Namespace) -> int:
    config = GeneratorConfig(detector_quality=args.detector_quality)
    sessions = generate_sessions(args.sessions, config, seed=args.seed)
    budget = _budget_factory(args, config)

    policies = [
        BetaTrustPolicy(
            trust_params=TrustParams(),
            policy_params=PolicyParams(theta_low=args.theta_low),
        ),
        RawThresholdPolicy(theta=args.raw_theta),
        EwmaThresholdPolicy(),
        PeriodicPolicy(k=args.periodic_k),
    ]

    print(
        f"\n{args.sessions} sessions x {config.session_length} steps  |  "
        f"detector quality {config.detector_quality}  |  seed {args.seed}"
    )
    if budget is None:
        print(
            "no budget cap: policies below spend different amounts, so compare "
            "the budget column before the exposure column,\nor re-run with "
            "--budget to hold spend equal."
        )
    else:
        print(f"budget capped at {args.budget:.2f} verifications / 1000 steps")
    print()
    print(_row("policy", "exposure", "contained", "delay", "budget/1k", "false/1k"))
    print("-" * 96)

    results = benchmark(
        sessions, policies, cooldown_seconds=args.cooldown, budget=budget
    )
    for name, m in results.items():
        delay = "n/a" if m.median_onset_delay is None else f"{m.median_onset_delay:.1f}"
        print(
            _row(
                name,
                f"{m.exposure:.3f}",
                f"{m.containment:.3f}",
                delay,
                f"{m.budget_per_1k_steps:.2f}",
                f"{m.false_verifications_per_1k_benign:.3f}",
            )
        )

    if args.ci:
        print("\nsession-grouped bootstrap, 95% CI on exposure")
        for policy in policies:
            records = run_policy(
                sessions, policy, cooldown_seconds=args.cooldown, budget=budget
            )
            lo, hi = bootstrap_ci(records, resamples=args.resamples, seed=args.seed)
            print(f"  {policy.name:<16} [{lo:.3f}, {hi:.3f}]")

    print()
    return 0


def _frontier(args: argparse.Namespace) -> int:
    config = GeneratorConfig(detector_quality=args.detector_quality)
    sessions = generate_sessions(args.sessions, config, seed=args.seed)

    print(
        f"\nbudget-exposure frontier  |  {args.sessions} sessions  |  seed {args.seed}\n"
    )
    print(_row("policy", "setting", "budget/1k", "exposure", "false/1k"))
    print("-" * 96)

    for theta_low in (0.30, 0.40, 0.50, 0.60, 0.70):
        # The hysteresis band travels with the low threshold; holding
        # theta_high fixed would make the sweep incomparable across points.
        policy = BetaTrustPolicy(
            policy_params=PolicyParams(
                theta_low=theta_low, theta_high=min(1.0, theta_low + 0.15)
            )
        )
        m = evaluate(run_policy(sessions, policy, cooldown_seconds=args.cooldown))
        print(
            _row(
                "adaptive",
                f"theta={theta_low:.2f}",
                f"{m.budget_per_1k_steps:.2f}",
                f"{m.exposure:.3f}",
                f"{m.false_verifications_per_1k_benign:.3f}",
            )
        )

    for k in (128, 64, 32, 16, 8):
        m = evaluate(
            run_policy(sessions, PeriodicPolicy(k=k), cooldown_seconds=args.cooldown)
        )
        print(
            _row(
                "periodic",
                f"k={k}",
                f"{m.budget_per_1k_steps:.2f}",
                f"{m.exposure:.3f}",
                f"{m.false_verifications_per_1k_benign:.3f}",
            )
        )

    print()
    return 0


def _delegation(args: argparse.Namespace) -> int:
    from .delegation_sim import DelegationScenario, compare

    scenario = DelegationScenario(
        orchestrators=args.orchestrators,
        workers_each=args.workers,
        steps=args.steps,
        detector_quality=args.detector_quality,
    )
    results = compare(scenario, seed=args.seed)

    print(
        f"\n{scenario.orchestrators} orchestrators x {scenario.workers_each} workers"
        f"  |  {scenario.steps} steps  |  seed {args.seed}"
    )
    print(
        "A compromised orchestrator issues only ordinary-looking instructions;\n"
        "the visibly hostile traffic comes from workers that are themselves clean.\n"
        "Both arms are the same engine - the blind one just never sees the chain.\n"
    )
    print(
        _row("arm", "contained", "exposure", "budget/1k", "wasted", "delay", width=12)
    )
    print("-" * 96)

    for name, outcome in results.items():
        delay = (
            "n/a" if outcome.median_delay is None else f"{outcome.median_delay:.1f}"
        )
        print(
            _row(
                name,
                f"{outcome.contained}/{outcome.episodes}",
                f"{outcome.exposure:.3f}",
                f"{outcome.budget_per_1k_steps:.2f}",
                f"{outcome.wasted}/{outcome.verifications}",
                delay,
                width=12,
            )
        )

    print(
        "\nWasted means the check was aimed at an agent that really was clean,"
        "\nso it returned clean and contained nothing.\n"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attest",
        description="Budgeted re-verification scheduling for agent identity.",
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="command")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--sessions", type=int, default=600, help="sessions to generate")
    common.add_argument("--seed", type=int, default=0, help="generator seed")
    common.add_argument(
        "--detector-quality",
        type=float,
        default=9.0,
        help="Beta concentration modelling detector separation",
    )
    common.add_argument(
        "--cooldown", type=float, default=8.0, help="seconds between verifications"
    )
    common.add_argument(
        "--budget",
        type=float,
        default=None,
        help="cap every policy at this many verifications per 1000 steps",
    )

    bench = sub.add_parser(
        "bench", parents=[common], help="compare trigger policies on generated sessions"
    )
    bench.add_argument("--theta-low", type=float, default=0.5)
    bench.add_argument("--raw-theta", type=float, default=0.9)
    bench.add_argument("--periodic-k", type=int, default=16)
    bench.add_argument("--ci", action="store_true", help="bootstrap confidence intervals")
    bench.add_argument("--resamples", type=int, default=200)
    bench.set_defaults(func=_bench)

    frontier = sub.add_parser(
        "frontier", parents=[common], help="sweep budget against attacker exposure"
    )
    frontier.set_defaults(func=_frontier)

    delegation = sub.add_parser(
        "delegation",
        help="compare chain-aware against chain-blind scheduling",
    )
    delegation.add_argument("--orchestrators", type=int, default=4)
    delegation.add_argument("--workers", type=int, default=5)
    delegation.add_argument("--steps", type=int, default=1500)
    delegation.add_argument("--seed", type=int, default=0)
    delegation.add_argument("--detector-quality", type=float, default=9.0)
    delegation.set_defaults(func=_delegation)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "version", False):
        from . import __version__

        print(__version__)
        return 0

    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
