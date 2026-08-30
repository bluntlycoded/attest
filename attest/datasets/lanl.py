"""LANL authentication events with red team ground truth.

Kent (2015), *Comprehensive, Multi-Source Cyber-Security Events*: 58 days of
Windows authentication from a real enterprise network, 1.6 billion events over
12,425 users, with a set of red team compromise events published as ground
truth. It is the closest public analogue to the problem this project actually
addresses - a real entity stream, real behaviour, and labels somebody else
assigned.

Getting the data
----------------
It is no longer a direct download; LANL gate it behind a request to
``cyberdata@lanl.gov``. Two files are needed::

    auth.txt.gz      7.2 GB
    redteam.txt.gz   4.8 KB

``auth.txt.gz`` is never decompressed to disk here - it is streamed and
filtered in one pass, which takes a while but needs no free space.

A labelling decision worth stating
----------------------------------
The red team file marks *individual* authentication events. Compromise is a
state rather than an instant: between an account's first and last red team
event it is under attacker control, including on events the red team did not
themselves generate. Marking only the listed events as hostile would make
"exposure" meaningless, because most of an account's compromised activity would
be scored as benign.

So an episode is the closed interval from an account's first red team event to
its last, split wherever the gap exceeds ``episode_gap``, and every event that
account emits inside that interval is labelled compromised. That is a choice,
it inflates the positive class relative to the raw file, and results move if
you change it. ``strict_labels=True`` marks only the literal red team events
instead, for comparison.
"""

from __future__ import annotations

import gzip
import os
import random
from dataclasses import dataclass, field
from typing import Iterator

from ..learn import RollingFeatures
from .base import Timeline

__all__ = ["LanlConfig", "load_redteam", "load"]

name = "lanl"

_AUTH_FIELDS = 9


@dataclass(frozen=True)
class LanlConfig:
    """Loader settings.

    Args:
        benign_entities: How many never-compromised accounts to sample
            alongside every compromised one. The corpus is overwhelmingly
            benign, and keeping all of it is neither necessary nor tractable.
        benign_sample_rate: Chance a newly-seen benign account is admitted to
            the reservoir. Below 1.0 the sample is spread through the log
            rather than drawn entirely from its first minutes. Set to 1.0 on
            small files, where thinning simply starves the sample.
        max_events_per_entity: Cap on events retained per account, oldest kept.
        episode_gap: Seconds of quiet that end a compromise episode.
        breadth_window: Window for counting distinct destination hosts, the
            lateral-movement signal.
        warmup: Events before an account's novelty signals count fully.
        seed: Sampling seed.
    """

    benign_entities: int = 400
    benign_sample_rate: float = 0.05
    max_events_per_entity: int = 4000
    episode_gap: float = 3600.0
    breadth_window: float = 3600.0
    warmup: int = 50
    seed: int = 0


@dataclass
class _Redteam:
    """Ground truth, indexed for lookup while streaming."""

    events: set[tuple[int, str, str, str]] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    windows: dict[str, list[tuple[int, int]]] = field(default_factory=dict)

    def window_for(self, user: str, when: float) -> tuple[int, int] | None:
        for start, end in self.windows.get(user, ()):
            if start <= when <= end:
                return (start, end)
        return None


def _open_text(path: str) -> Iterator[str]:
    """Stream a text file, transparently handling gzip."""
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            yield from handle
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            yield from handle


def load_redteam(path: str, *, episode_gap: float = 3600.0) -> _Redteam:
    """Read the red team file and derive per-account compromise windows."""
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"red team file not found at {path!r}. Request the corpus from "
            "cyberdata@lanl.gov; see the module docstring."
        )

    truth = _Redteam()
    per_user: dict[str, list[int]] = {}
    for line in _open_text(path):
        parts = line.strip().split(",")
        if len(parts) != 4:
            continue
        try:
            when = int(parts[0])
        except ValueError:
            continue
        user, src, dst = parts[1], parts[2], parts[3]
        truth.events.add((when, user, src, dst))
        truth.users.add(user)
        per_user.setdefault(user, []).append(when)

    for user, times in per_user.items():
        times.sort()
        windows, start, previous = [], times[0], times[0]
        for when in times[1:]:
            if when - previous > episode_gap:
                windows.append((start, previous))
                start = when
            previous = when
        windows.append((start, previous))
        truth.windows[user] = windows

    return truth


def load(
    auth_path: str,
    redteam_path: str,
    config: LanlConfig | None = None,
    *,
    strict_labels: bool = False,
    progress: bool = False,
) -> list[Timeline]:
    """Stream the authentication log into per-account timelines.

    Args:
        auth_path: Path to ``auth.txt.gz`` (or an uncompressed copy).
        redteam_path: Path to ``redteam.txt.gz``.
        config: Sampling and feature settings.
        strict_labels: Label only the literal red team events rather than the
            whole compromise window. See the module docstring.
        progress: Print a line every ten million events. The full pass reads
            1.05 billion rows and is not quick.

    Returns:
        One timeline per retained account, each time-ordered.
    """
    cfg = config or LanlConfig()
    if not os.path.exists(auth_path):
        raise FileNotFoundError(
            f"authentication log not found at {auth_path!r}. Request the corpus "
            "from cyberdata@lanl.gov; see the module docstring."
        )

    truth = load_redteam(redteam_path, episode_gap=cfg.episode_gap)
    if not truth.users:
        raise ValueError(f"no red team events parsed from {redteam_path!r}")

    rng = random.Random(cfg.seed)
    # Reservoir of benign accounts, decided on first sight so the pass stays
    # single and streaming.
    keep: dict[str, bool] = {user: True for user in truth.users}
    benign_kept = 0

    raw: dict[str, list[tuple[int, list[str]]]] = {}
    seen = 0

    for line in _open_text(auth_path):
        seen += 1
        if progress and seen % 10_000_000 == 0:
            print(f"  {seen:,} events read, {len(raw)} accounts retained")

        parts = line.rstrip("\n").split(",")
        if len(parts) != _AUTH_FIELDS:
            continue
        user = parts[1]

        decision = keep.get(user)
        if decision is None:
            # Keep the first N distinct benign accounts, thinned by
            # `benign_sample_rate` so the sample is spread across the log
            # rather than taken entirely from its opening minutes. Once the
            # reservoir is short and the file is nearly exhausted there is no
            # way to go back for accounts already skipped, so the sample is
            # biased toward accounts that appear early. With 12,425 accounts in
            # the real corpus that bias is mild; on a small file, raise the
            # rate to 1.0.
            decision = benign_kept < cfg.benign_entities and (
                cfg.benign_sample_rate >= 1.0
                or rng.random() < cfg.benign_sample_rate
            )
            keep[user] = decision
            if decision:
                benign_kept += 1
        if not decision:
            continue

        try:
            when = int(parts[0])
        except ValueError:
            continue

        events = raw.setdefault(user, [])
        if len(events) < cfg.max_events_per_entity:
            events.append((when, parts))

    return _build_timelines(raw, truth, cfg, strict_labels=strict_labels)


def _build_timelines(
    raw: dict[str, list[tuple[int, list[str]]]],
    truth: _Redteam,
    cfg: LanlConfig,
    *,
    strict_labels: bool,
) -> list[Timeline]:
    """Derive features and labels for each retained account."""
    timelines: list[Timeline] = []

    for user, events in raw.items():
        events.sort(key=lambda pair: pair[0])
        rolling = RollingFeatures(
            breadth_window=cfg.breadth_window, warmup=cfg.warmup
        )
        times, features, is_attack, episode = [], [], [], []
        recent_failures: list[int] = []

        for when, parts in events:
            (
                _,
                src_user,
                dst_user,
                src_computer,
                dst_computer,
                auth_type,
                logon_type,
                orientation,
                outcome,
            ) = parts

            failed = outcome == "Fail"
            recent_failures.append(1 if failed else 0)
            if len(recent_failures) > 20:
                recent_failures.pop(0)

            row = rolling.observe(
                float(when),
                {
                    "dst_computer": dst_computer,
                    "src_computer": src_computer,
                    "auth_type": auth_type,
                    "logon_type": logon_type,
                    "orientation": orientation,
                },
                peer=dst_computer,
            )
            row["failed"] = 1.0 if failed else 0.0
            row["failure_rate"] = sum(recent_failures) / len(recent_failures)
            # A machine account authenticating as itself is routine; a user
            # account doing so on a host it does not own is not.
            row["self_auth"] = 1.0 if src_user == dst_user else 0.0
            row["remote"] = 1.0 if src_computer != dst_computer else 0.0

            if strict_labels:
                hostile = (when, user, src_computer, dst_computer) in truth.events
                window = (when, when) if hostile else None
            else:
                window = truth.window_for(user, when)
                hostile = window is not None

            times.append(float(when))
            features.append(row)
            is_attack.append(hostile)
            episode.append(f"{user}@{window[0]}" if window else None)

        if times:
            timelines.append(
                Timeline(
                    entity_id=user,
                    times=times,
                    features=features,
                    is_attack=is_attack,
                    episode=episode,
                )
            )

    return timelines
