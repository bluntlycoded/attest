"""Exercises the real-corpus path end to end on a fixture in LANL wire format.

The corpus itself is gated behind a request to LANL, so the loader cannot be
tested against it here. What can be tested - and is - is that every step from
raw wire lines through labelling, features, entity-grouped splitting, fitting,
calibration and the four policies works on data shaped exactly like the real
thing. When the file arrives the path is already proven.
"""

from __future__ import annotations

import gzip
import random

import pytest

from attest.datasets import Timeline, split_entities, to_sessions
from attest.datasets import lanl
from attest.datasets.run import _ece, _pr_auc, _roc_auc, evaluate_corpus


# --------------------------------------------------------------- fixtures


def _auth_line(t, user, src, dst, auth="Kerberos", logon="Network", orient="LogOn", ok="Success"):
    return f"{t},{user}@DOM1,{user}@DOM1,{src},{dst},{auth},{logon},{orient},{ok}"


def _write_corpus(tmp_path, *, users=12, events=160, seed=0):
    """Build a small corpus with two accounts under a red team window."""
    rng = random.Random(seed)
    hostile_users = ["U0001", "U0002"]
    window = (400, 520)

    lines, redteam = [], []
    for step in range(events):
        t = step * 10
        for index in range(users):
            user = f"U{index:04d}"
            home = f"C{index:03d}"
            compromised = user in hostile_users and window[0] <= t <= window[1]
            if compromised:
                # Lateral movement: many distinct destinations, some failures.
                dst = f"C{rng.randrange(500, 600)}"
                ok = "Fail" if rng.random() < 0.4 else "Success"
                lines.append(_auth_line(t, user, home, dst, ok=ok))
                redteam.append(f"{t},{user}@DOM1,{home},{dst}")
            else:
                lines.append(_auth_line(t, user, home, home))

    auth_path = tmp_path / "auth.txt.gz"
    redteam_path = tmp_path / "redteam.txt.gz"
    with gzip.open(auth_path, "wt") as fh:
        fh.write("\n".join(lines) + "\n")
    with gzip.open(redteam_path, "wt") as fh:
        fh.write("\n".join(redteam) + "\n")
    return str(auth_path), str(redteam_path)


# ------------------------------------------------------------- timelines


def test_timeline_rejects_ragged_columns():
    with pytest.raises(ValueError, match="ragged columns"):
        Timeline("a", [0.0, 1.0], [{}], [False, False], [None, None])


def test_timeline_rejects_out_of_order_events():
    with pytest.raises(ValueError, match="not time-ordered"):
        Timeline("a", [2.0, 1.0], [{}, {}], [False, False], [None, None])


def _timeline(entity, attacked):
    n = 20
    return Timeline(
        entity_id=entity,
        times=[float(i) for i in range(n)],
        features=[{"x": float(i)} for i in range(n)],
        is_attack=[attacked and i > 10 for i in range(n)],
        episode=[f"{entity}-e0" if attacked and i > 10 else None for i in range(n)],
    )


def test_split_is_by_entity_never_by_event():
    timelines = [_timeline(f"e{i}", i < 6) for i in range(30)]
    train, cal, test = split_entities(timelines, seed=1)
    ids = [{t.entity_id for t in group} for group in (train, cal, test)]
    assert not ids[0] & ids[1]
    assert not ids[0] & ids[2]
    assert not ids[1] & ids[2]
    assert sum(len(g) for g in (train, cal, test)) == 30


def test_split_stratifies_compromised_entities():
    """A naive split routinely puts every labelled episode on one side."""
    timelines = [_timeline(f"e{i}", i < 6) for i in range(30)]
    train, _, test = split_entities(timelines, seed=1)
    assert any(t.attack_events for t in train)
    assert any(t.attack_events for t in test)


@pytest.mark.parametrize(
    "kwargs", [{"train": 0.0}, {"train": 1.0}, {"train": 0.9, "calibrate": 0.2}]
)
def test_invalid_splits_are_rejected(kwargs):
    with pytest.raises(ValueError):
        split_entities([_timeline("a", True)], **kwargs)


def test_to_sessions_preserves_labels_and_order():
    timelines = [_timeline("e0", True)]
    sessions = to_sessions(timelines, lambda row: 0.5)
    assert len(sessions) == 1
    assert sessions[0].is_attack == timelines[0].is_attack
    assert sessions[0].times == timelines[0].times
    assert all(p == 0.5 for p in sessions[0].p)


# ------------------------------------------------------------------ lanl


def test_loader_reads_wire_format(tmp_path):
    auth, redteam = _write_corpus(tmp_path)
    timelines = lanl.load(auth, redteam, lanl.LanlConfig(benign_entities=50))

    assert timelines
    by_id = {t.entity_id: t for t in timelines}
    assert "U0001@DOM1" in by_id
    assert by_id["U0001@DOM1"].attack_events > 0
    assert by_id["U0001@DOM1"].episodes >= 1


def test_window_labelling_covers_more_than_the_literal_events(tmp_path):
    """Compromise is a state; the red team file records only its own events."""
    auth, redteam = _write_corpus(tmp_path)
    config = lanl.LanlConfig(benign_entities=50)

    windowed = lanl.load(auth, redteam, config, strict_labels=False)
    strict = lanl.load(auth, redteam, config, strict_labels=True)

    assert sum(t.attack_events for t in windowed) >= sum(
        t.attack_events for t in strict
    )


def test_features_include_the_lateral_movement_signals(tmp_path):
    auth, redteam = _write_corpus(tmp_path)
    timelines = lanl.load(auth, redteam, lanl.LanlConfig(benign_entities=50))
    row = timelines[0].features[0]
    for expected in ("new_dst_computer", "breadth", "failed", "failure_rate", "remote"):
        assert expected in row


def test_event_cap_is_respected(tmp_path):
    auth, redteam = _write_corpus(tmp_path)
    timelines = lanl.load(
        auth, redteam, lanl.LanlConfig(benign_entities=50, max_events_per_entity=25)
    )
    assert all(len(t) <= 25 for t in timelines)


def test_missing_files_give_an_actionable_error(tmp_path):
    auth, redteam = _write_corpus(tmp_path)
    with pytest.raises(FileNotFoundError, match="cyberdata@lanl.gov"):
        lanl.load(str(tmp_path / "nope.gz"), redteam)
    with pytest.raises(FileNotFoundError, match="cyberdata@lanl.gov"):
        lanl.load(auth, str(tmp_path / "nope.gz"))


def test_redteam_windows_split_on_long_gaps(tmp_path):
    path = tmp_path / "rt.txt"
    path.write_text(
        "\n".join(
            [
                "100,U1@DOM1,C1,C2",
                "150,U1@DOM1,C1,C3",
                "99999,U1@DOM1,C1,C4",
            ]
        )
    )
    truth = lanl.load_redteam(str(path), episode_gap=3600.0)
    assert len(truth.windows["U1@DOM1"]) == 2


# ---------------------------------------------------------------- metrics


def test_roc_auc_matches_known_values():
    assert _roc_auc([0.1, 0.2, 0.3, 0.4], [0, 0, 1, 1]) == pytest.approx(1.0)
    assert _roc_auc([0.4, 0.3, 0.2, 0.1], [0, 0, 1, 1]) == pytest.approx(0.0)
    assert _roc_auc([0.5, 0.5, 0.5, 0.5], [0, 0, 1, 1]) == pytest.approx(0.5)


def test_pr_auc_rewards_ranking_positives_first():
    perfect = _pr_auc([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0])
    inverted = _pr_auc([0.9, 0.8, 0.2, 0.1], [0, 0, 1, 1])
    assert perfect == pytest.approx(1.0)
    assert inverted < perfect


def test_ece_is_zero_for_a_perfectly_calibrated_score():
    scores = [0.0] * 50 + [1.0] * 50
    labels = [0] * 50 + [1] * 50
    assert _ece(scores, labels) == pytest.approx(0.0, abs=1e-9)


def test_ece_penalises_overconfidence():
    assert _ece([0.99] * 100, [0] * 100) > 0.9


# ------------------------------------------------------------ end to end


def test_full_evaluation_runs_on_the_fixture(tmp_path):
    auth, redteam = _write_corpus(tmp_path, users=40, events=200)
    timelines = lanl.load(auth, redteam, lanl.LanlConfig(benign_entities=50))

    report = evaluate_corpus(
        timelines, dataset="fixture", resamples=25, seed=0
    )

    assert report.entities > 0
    assert report.episodes > 0
    assert set(report.policies) == {
        "beta-trust",
        "raw-threshold",
        "ewma-threshold",
        "periodic",
    }
    for metrics in report.policies.values():
        assert 0.0 <= metrics.exposure <= 1.0
    assert report.coefficients
    assert "beta-trust" in report.summary()


def test_evaluation_refuses_a_test_split_with_no_episodes():
    timelines = [_timeline(f"e{i}", False) for i in range(10)]
    with pytest.raises(ValueError, match="no compromised entity"):
        evaluate_corpus(timelines, resamples=0)


def test_evaluation_refuses_an_empty_corpus():
    with pytest.raises(ValueError, match="no timelines"):
        evaluate_corpus([], resamples=0)
