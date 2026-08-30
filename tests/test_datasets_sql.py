"""SQL-backed loaders, exercised against fixtures in the real schemas.

The tables here are the ones SENTRY and nodewatch actually define, so a loader
that passes these will read a live database of either. What the fixtures cannot
supply is realistic behaviour, so nothing about detection quality is asserted -
only that labelling, features and the two evaluation paths are correct.
"""

from __future__ import annotations

import sqlite3

import pytest

from attest.datasets import nodewatch, sentry
from attest.datasets.run import shadow_corpus
from attest.datasets.sql import connect, rows, to_epoch


# ------------------------------------------------------------------ fixtures


def _sentry_db(tmp_path, *, principals=8, events=80):
    """A SENTRY database: access_events plus breach_incidents as labels."""
    path = tmp_path / "sentry.db"
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE access_events (
            id INTEGER PRIMARY KEY, tenant_id TEXT, occurred_at REAL,
            principal TEXT, action TEXT, resource TEXT,
            records_touched INTEGER, bytes_out INTEGER,
            source_ip TEXT, succeeded INTEGER
        );
        CREATE TABLE breach_incidents (
            id INTEGER PRIMARY KEY, tenant_id TEXT, detected_at REAL,
            principal TEXT, severity TEXT
        );
        """
    )

    breached = {"u1@x.com", "u2@x.com"}
    for index in range(principals):
        principal = f"u{index}@x.com"
        for step in range(events):
            at = float(step * 60)
            hostile = principal in breached and 40 <= step <= 55
            db.execute(
                "INSERT INTO access_events (tenant_id, occurred_at, principal, "
                "action, resource, records_touched, bytes_out, source_ip, succeeded) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    "t1",
                    at,
                    principal,
                    "export" if hostile else "read",
                    f"table_{step % 40}" if hostile else "table_1",
                    50_000 if hostile else 5,
                    9_000_000 if hostile else 900,
                    "10.9.9.9" if hostile else "10.0.0.1",
                    1,
                ),
            )
    for principal in breached:
        db.execute(
            "INSERT INTO breach_incidents (tenant_id, detected_at, principal, severity)"
            " VALUES (?,?,?,?)",
            ("t1", float(48 * 60), principal, "high"),
        )
    db.commit()
    return db, path


def _nodewatch_db(tmp_path, *, hosts=6, events=60):
    """A nodewatch database: four event tables, no labels anywhere."""
    path = tmp_path / "nodewatch.db"
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE auth_events (
            id INTEGER PRIMARY KEY, agent_id TEXT, ts REAL,
            kind TEXT, username TEXT, source_ip TEXT, raw TEXT
        );
        CREATE TABLE port_events (
            id INTEGER PRIMARY KEY, agent_id TEXT, ts REAL, port INTEGER,
            proto TEXT, bind_addr TEXT, external INTEGER, process TEXT, action TEXT
        );
        CREATE TABLE user_events (
            id INTEGER PRIMARY KEY, agent_id TEXT, ts REAL, username TEXT,
            action TEXT, uid INTEGER, sudoer INTEGER, detail TEXT
        );
        CREATE TABLE fim_events (
            id INTEGER PRIMARY KEY, agent_id TEXT, ts REAL, path TEXT,
            action TEXT, critical INTEGER, sha256 TEXT, mode TEXT,
            size INTEGER, detail TEXT
        );
        """
    )
    for index in range(hosts):
        agent = f"host-{index}"
        for step in range(events):
            at = float(step * 30)
            db.execute(
                "INSERT INTO auth_events (agent_id, ts, kind, username, source_ip, raw)"
                " VALUES (?,?,?,?,?,?)",
                (
                    agent,
                    at,
                    "login_failed" if step % 17 == 0 else "login_ok",
                    "root",
                    "10.0.0.5",
                    "",
                ),
            )
            if step % 10 == 0:
                db.execute(
                    "INSERT INTO fim_events (agent_id, ts, path, action, critical,"
                    " sha256, mode, size, detail) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        agent,
                        at,
                        "/etc/sudoers" if step % 30 == 0 else "/etc/motd",
                        "modified",
                        1 if step % 30 == 0 else 0,
                        "",
                        "",
                        0,
                        "",
                    ),
                )
            if step % 20 == 0:
                db.execute(
                    "INSERT INTO port_events (agent_id, ts, port, proto, bind_addr,"
                    " external, process, action) VALUES (?,?,?,?,?,?,?,?)",
                    (agent, at, 4444, "tcp", "0.0.0.0", 1, "nc", "opened"),
                )
            if step % 25 == 0:
                db.execute(
                    "INSERT INTO user_events (agent_id, ts, username, action, uid,"
                    " sudoer, detail) VALUES (?,?,?,?,?,?,?)",
                    (agent, at, "svc", "added", 1001, 1, ""),
                )
    db.commit()
    return db, path


# ----------------------------------------------------------------- sql utils


def test_connect_accepts_a_bare_path_and_a_sqlite_url(tmp_path):
    _, path = _sentry_db(tmp_path)
    for url in (str(path), f"sqlite:///{path}"):
        connection = connect(url)
        assert list(rows(connection, "SELECT COUNT(*) AS n FROM access_events"))


def test_to_epoch_handles_the_shapes_drivers_return():
    from datetime import datetime, timezone

    assert to_epoch(1234.5) == 1234.5
    moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert to_epoch(moment) == moment.timestamp()
    assert to_epoch("2026-01-01T00:00:00+00:00") == moment.timestamp()


def test_to_epoch_rejects_null():
    with pytest.raises(ValueError, match="null"):
        to_epoch(None)


# -------------------------------------------------------------------- sentry


def test_sentry_loader_reads_principals(tmp_path):
    db, _ = _sentry_db(tmp_path)
    timelines = sentry.load(db, sentry.SentryConfig(min_events=10))
    assert len(timelines) == 8
    assert all(len(t) == 80 for t in timelines)


def test_incidents_become_labelled_episodes(tmp_path):
    db, _ = _sentry_db(tmp_path)
    timelines = sentry.load(db, sentry.SentryConfig(min_events=10))
    by_id = {t.entity_id: t for t in timelines}

    assert by_id["u1@x.com"].attack_events > 0
    assert by_id["u1@x.com"].episodes == 1
    assert by_id["u5@x.com"].attack_events == 0


def test_the_episode_window_extends_before_detection(tmp_path):
    """A detector fires after the behaviour, so a window anchored only at
    detection would label the aftermath and miss the cause."""
    db, _ = _sentry_db(tmp_path)

    narrow = sentry.load(db, sentry.SentryConfig(min_events=10, episode_pad=1.0))
    wide = sentry.load(db, sentry.SentryConfig(min_events=10, episode_pad=1800.0))

    assert sum(t.attack_events for t in wide) > sum(t.attack_events for t in narrow)


def test_sentry_features_include_the_volume_signals(tmp_path):
    db, _ = _sentry_db(tmp_path)
    row = sentry.load(db, sentry.SentryConfig(min_events=10))[0].features[0]
    for expected in ("records", "bytes_out", "export", "new_resource", "breadth"):
        assert expected in row


def test_short_principals_are_dropped(tmp_path):
    db, _ = _sentry_db(tmp_path, events=5)
    assert sentry.load(db, sentry.SentryConfig(min_events=30)) == []


def test_tenant_filter_is_applied(tmp_path):
    db, _ = _sentry_db(tmp_path)
    assert sentry.load(db, sentry.SentryConfig(min_events=10, tenant_id="t1"))
    assert sentry.load(db, sentry.SentryConfig(min_events=10, tenant_id="nope")) == []


def test_sentry_corpus_runs_through_the_full_evaluation(tmp_path):
    from attest.datasets.run import evaluate_corpus

    db, _ = _sentry_db(tmp_path, principals=30, events=90)
    timelines = sentry.load(db, sentry.SentryConfig(min_events=10))
    report = evaluate_corpus(timelines, dataset="sentry", resamples=0)

    assert report.episodes > 0
    assert set(report.policies) == {
        "beta-trust",
        "raw-threshold",
        "ewma-threshold",
        "periodic",
    }


# ----------------------------------------------------------------- nodewatch


def test_nodewatch_loader_merges_the_four_event_tables(tmp_path):
    db, _ = _nodewatch_db(tmp_path)
    timelines = nodewatch.load(db, nodewatch.NodewatchConfig(min_events=10))
    assert len(timelines) == 6

    sources = {
        key
        for t in timelines
        for row in t.features
        for key in ("login_failed", "port_opened", "priv_change", "critical_file")
        if row.get(key)
    }
    assert sources == {"login_failed", "port_opened", "priv_change", "critical_file"}


def test_nodewatch_timelines_are_time_ordered(tmp_path):
    db, _ = _nodewatch_db(tmp_path)
    for timeline in nodewatch.load(db, nodewatch.NodewatchConfig(min_events=10)):
        assert timeline.times == sorted(timeline.times)


def test_nodewatch_carries_no_labels(tmp_path):
    """It has none, and inventing them would make exposure meaningless."""
    db, _ = _nodewatch_db(tmp_path)
    timelines = nodewatch.load(db, nodewatch.NodewatchConfig(min_events=10))
    assert all(t.attack_events == 0 for t in timelines)
    assert all(t.episodes == 0 for t in timelines)


def test_labelled_evaluation_refuses_an_unlabelled_corpus(tmp_path):
    from attest.datasets.run import evaluate_corpus

    db, _ = _nodewatch_db(tmp_path)
    timelines = nodewatch.load(db, nodewatch.NodewatchConfig(min_events=10))
    with pytest.raises(ValueError, match="no compromised entity"):
        evaluate_corpus(timelines, resamples=0)


def test_shadow_mode_reports_cost_and_nothing_it_cannot_know(tmp_path):
    db, _ = _nodewatch_db(tmp_path)
    timelines = nodewatch.load(db, nodewatch.NodewatchConfig(min_events=10))

    report = shadow_corpus(
        timelines, nodewatch.host_scorer(), dataset="nodewatch"
    )

    assert report.entities == 6
    assert set(report.verifications) == {
        "beta-trust",
        "raw-threshold",
        "ewma-threshold",
        "periodic",
    }
    assert all(v >= 0 for v in report.verifications.values())
    # The things ground truth would be needed for are absent by construction.
    for absent in ("exposure", "containment", "median_onset_delay"):
        assert not hasattr(report, absent)
    assert "no exposure" in report.summary()


def test_periodic_costs_more_than_the_trust_policy_on_real_telemetry(tmp_path):
    """The claim shadow mode can actually support: relative spend."""
    db, _ = _nodewatch_db(tmp_path, hosts=12, events=200)
    timelines = nodewatch.load(db, nodewatch.NodewatchConfig(min_events=10))
    report = shadow_corpus(timelines, nodewatch.host_scorer())

    assert (
        report.budget_per_1k_steps["periodic"]
        > report.budget_per_1k_steps["beta-trust"]
    )


def test_host_scorer_ranks_a_critical_file_change_above_routine_traffic():
    score = nodewatch.host_scorer()
    routine = score({"file_change": 1.0})
    critical = score({"file_change": 1.0, "critical_file": 1.0, "priv_change": 1.0})
    assert critical > routine
    assert 0.0 <= routine <= 1.0 and 0.0 <= critical <= 1.0


def test_host_scorer_weights_can_be_overridden():
    default = nodewatch.host_scorer()
    tuned = nodewatch.host_scorer(weights={"critical_file": 8.0})
    assert tuned({"critical_file": 1.0}) > default({"critical_file": 1.0})


def test_shadow_mode_needs_a_corpus():
    with pytest.raises(ValueError, match="no timelines"):
        shadow_corpus([], nodewatch.host_scorer())
