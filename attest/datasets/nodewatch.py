"""nodewatch host telemetry.

nodewatch already collects the right shape of evidence for every machine it
watches - failed sign-ins, newly exposed ports, account and privilege changes,
file integrity events - all timestamped, all per host. That makes it real
telemetry this project can reach without an access request.

It has no compromise labels
---------------------------
Nothing in nodewatch records that a host *was* compromised. Without that,
exposure, containment and onset delay cannot be computed at all - they are all
defined against ground truth. Loading this corpus and reporting an exposure
number would mean inventing one.

So a nodewatch timeline is deliberately built with every event labelled benign,
and :func:`attest.datasets.run.shadow_corpus` is the only thing that should
consume it. That reports what a shadow deployment genuinely measures: how much
budget each policy spends, and how often it would have interrupted a fleet
believed to be mostly healthy. Those two numbers are worth having. The other
two are not available and should not be manufactured.

Where the risk weights come from
--------------------------------
nodewatch's own ``agent_trust`` view already encodes an operator's judgement
about which host signals matter and by how much - external port count, failed
sign-ins in the last hour, newly exposed ports, privilege changes, critical
file modifications. :func:`host_scorer` carries those judgements across rather
than inventing a fresh set, because that view was tuned against real fleets and
this has not been.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ..evidence import Calibrator
from ..learn import RollingFeatures
from .base import Timeline
from .sql import Connection, rows, to_epoch

__all__ = ["NodewatchConfig", "load", "host_scorer"]

name = "nodewatch"


@dataclass(frozen=True)
class NodewatchConfig:
    """Loader settings.

    Args:
        min_events: Hosts with fewer events than this are dropped.
        max_events_per_entity: Cap per host, oldest kept.
        breadth_window: Window for counting distinct ports and paths touched.
        warmup: Events before novelty signals count fully.
    """

    min_events: int = 30
    max_events_per_entity: int = 4000
    breadth_window: float = 3600.0
    warmup: int = 50


# One query per event table, unioned in memory rather than in SQL. The tables
# have genuinely different shapes, and a UNION would mean padding every one of
# them with nulls for the others' columns.
_QUERIES = (
    (
        "auth",
        "SELECT agent_id, ts, kind AS detail, username AS subject, "
        "CAST(source_ip AS TEXT) AS peer FROM auth_events",
    ),
    (
        "port",
        "SELECT agent_id, ts, action AS detail, "
        "CAST(port AS TEXT) AS subject, bind_addr AS peer, external "
        "FROM port_events",
    ),
    (
        "user",
        "SELECT agent_id, ts, action AS detail, username AS subject, "
        "'' AS peer, sudoer FROM user_events",
    ),
    (
        "fim",
        "SELECT agent_id, ts, action AS detail, path AS subject, "
        "'' AS peer, critical FROM fim_events",
    ),
)


def load(
    connection: Connection, config: NodewatchConfig | None = None
) -> list[Timeline]:
    """Read host telemetry into per-host timelines, all labelled benign.

    Args:
        connection: Any DB-API connection to a nodewatch database.
        config: Loader settings.

    Returns:
        One timeline per retained host. Every event is labelled benign, because
        nodewatch does not know otherwise - use ``shadow_corpus`` to evaluate.
    """
    cfg = config or NodewatchConfig()
    grouped: dict[str, list[tuple[float, str, dict]]] = {}

    for source, sql in _QUERIES:
        for row in rows(connection, sql):
            agent = str(row.get("agent_id") or "")
            if not agent:
                continue
            try:
                at = to_epoch(row["ts"])
            except (ValueError, KeyError):
                continue
            grouped.setdefault(agent, []).append((at, source, row))

    timelines: list[Timeline] = []
    for agent, events in grouped.items():
        events.sort(key=lambda item: item[0])
        events = events[: cfg.max_events_per_entity]
        if len(events) < cfg.min_events:
            continue

        rolling = RollingFeatures(
            breadth_window=cfg.breadth_window, warmup=cfg.warmup
        )
        times, features = [], []
        recent_failures: list[int] = []

        for at, source, row in events:
            detail = str(row.get("detail") or "")
            subject = str(row.get("subject") or "")

            failed = source == "auth" and detail == "login_failed"
            recent_failures.append(1 if failed else 0)
            if len(recent_failures) > 20:
                recent_failures.pop(0)

            feature = rolling.observe(
                at,
                {
                    "source": source,
                    "subject": subject,
                    "peer": str(row.get("peer") or ""),
                },
                peer=subject,
            )
            feature["login_failed"] = 1.0 if failed else 0.0
            feature["failure_rate"] = sum(recent_failures) / len(recent_failures)
            feature["port_opened"] = (
                1.0 if source == "port" and detail == "opened" else 0.0
            )
            feature["external"] = 1.0 if row.get("external") else 0.0
            feature["priv_change"] = (
                1.0 if source == "user" and row.get("sudoer") else 0.0
            )
            feature["account_change"] = 1.0 if source == "user" else 0.0
            # nodewatch flags files an attacker would edit - sudoers, shadow,
            # sshd_config, cron, pam - and weights them far above ordinary
            # /etc churn. Carried across rather than re-derived.
            feature["critical_file"] = 1.0 if row.get("critical") else 0.0
            feature["file_change"] = 1.0 if source == "fim" else 0.0

            times.append(at)
            features.append(feature)

        timelines.append(
            Timeline(
                entity_id=agent,
                times=times,
                features=features,
                is_attack=[False] * len(times),
                episode=[None] * len(times),
            )
        )

    return timelines


# Prior weights in logit units, carried over from nodewatch's agent_trust view.
# Stated judgements, not fitted values - there is nothing here to fit against.
HOST_WEIGHTS: dict[str, float] = {
    "critical_file": 3.0,
    "priv_change": 2.5,
    "failure_rate": 2.0,
    "login_failed": 1.0,
    "external": 1.2,
    "port_opened": 0.8,
    "account_change": 0.6,
    "new_subject": 0.5,
    "new_peer": 0.4,
    "file_change": 0.2,
    "burst": 0.6,
    "breadth": 0.3,
}

# Chosen so a wholly unremarkable event scores about 0.02.
HOST_BIAS = -3.9


def host_scorer(
    weights: dict[str, float] | None = None,
    bias: float = HOST_BIAS,
    calibrator: Calibrator | None = None,
):
    """A hand-specified risk score for host events.

    There are no labels in nodewatch, so nothing can be fitted. This is the
    honest alternative: stated weights, visible and adjustable, carried over
    from the trust view nodewatch already runs.

    Returns:
        A callable mapping a feature row to a probability in [0, 1].
    """
    table = dict(weights or HOST_WEIGHTS)
    scale = calibrator or Calibrator()

    def score(row: dict[str, float]) -> float:
        logit = bias + sum(w * float(row.get(k, 0.0)) for k, w in table.items())
        return scale(logit)

    return score
