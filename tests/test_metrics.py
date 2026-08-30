import pytest

from attest.metrics import StepRecord, bootstrap_ci, evaluate


def _steps(spec, session="s0", episode="e0", group=None):
    """Build records from a compact spec of (is_attack, verified) pairs."""
    return [
        StepRecord(
            session=session,
            is_attack=a,
            episode=episode if a else None,
            verified=v,
            group=group,
        )
        for a, v in spec
    ]


def test_uncontained_episode_is_fully_exposed():
    records = _steps([(False, False)] * 5 + [(True, False)] * 10)
    m = evaluate(records)
    assert m.attack_steps == 10
    assert m.exposure == 1.0
    assert m.containment == 0.0
    assert m.median_onset_delay is None


def test_containment_stops_exposure_accruing():
    # Four attack steps, verified on the fourth.
    records = _steps([(True, False)] * 3 + [(True, True)] + [(True, False)] * 6)
    m = evaluate(records)
    assert m.attack_steps == 10
    # The step the verification fires on still counts as exposed.
    assert m.exposure == pytest.approx(0.4)
    assert m.containment == 1.0
    assert m.median_onset_delay == 3


def test_verification_on_the_onset_step_gives_zero_delay():
    records = _steps([(True, True)] + [(True, False)] * 9)
    m = evaluate(records)
    assert m.median_onset_delay == 0
    assert m.exposure == pytest.approx(0.1)


def test_false_verifications_are_counted_against_benign_steps():
    records = _steps([(False, True)] * 2 + [(False, False)] * 998)
    m = evaluate(records)
    assert m.benign_steps == 1000
    assert m.false_verifications_per_1k_benign == pytest.approx(2.0)
    assert m.exposure == 0.0


def test_budget_is_reported_per_thousand_steps():
    records = _steps([(False, True)] + [(False, False)] * 499)
    m = evaluate(records)
    assert m.steps == 500
    assert m.verifications == 1
    assert m.budget_per_1k_steps == pytest.approx(2.0)


def test_median_delay_across_several_episodes():
    records = []
    for i, delay in enumerate([0, 4, 10]):
        spec = [(True, False)] * delay + [(True, True)] + [(True, False)] * 5
        records += _steps(spec, session=f"s{i}", episode=f"e{i}")
    m = evaluate(records)
    assert m.episodes == 3
    assert m.containment == 1.0
    assert m.median_onset_delay == 4


def test_second_verification_in_an_episode_does_not_change_the_delay():
    records = _steps([(True, False)] * 2 + [(True, True)] + [(True, True)] * 3)
    m = evaluate(records)
    assert m.median_onset_delay == 2
    assert m.verifications == 4
    assert m.exposure == pytest.approx(3 / 6)


def test_group_breakdown():
    records = _steps([(True, False)] * 4, session="a", episode="ea", group="recon")
    records += _steps([(True, True)] * 4, session="b", episode="eb", group="flood")
    m = evaluate(records, by_group=True)
    assert set(m.by_group) == {"recon", "flood"}
    assert m.by_group["recon"].exposure == 1.0
    assert m.by_group["flood"].exposure == pytest.approx(0.25)


def test_attack_step_without_an_episode_id_is_an_error():
    records = [StepRecord(session="s", is_attack=True, episode=None)]
    with pytest.raises(ValueError, match="no episode id"):
        evaluate(records)


def test_empty_record_set_is_an_error():
    with pytest.raises(ValueError, match="empty record set"):
        evaluate([])


def test_bootstrap_interval_brackets_the_point_estimate():
    records = []
    for i in range(40):
        spec = [(False, False)] * 10 + [(True, False)] * 5 + [(True, True)]
        records += _steps(spec, session=f"s{i}", episode=f"e{i}")

    point = evaluate(records).exposure
    lo, hi = bootstrap_ci(records, resamples=200, seed=7)
    assert lo <= point <= hi


def test_bootstrap_is_deterministic_given_a_seed():
    records = []
    for i in range(20):
        records += _steps(
            [(False, False)] * 8 + [(True, True)] + [(True, False)] * 3,
            session=f"s{i}",
            episode=f"e{i}",
        )
    assert bootstrap_ci(records, resamples=50, seed=3) == bootstrap_ci(
        records, resamples=50, seed=3
    )


def test_bootstrap_rejects_bad_arguments():
    records = _steps([(True, True)])
    with pytest.raises(ValueError):
        bootstrap_ci(records, confidence=1.5)
    with pytest.raises(ValueError):
        bootstrap_ci(records, resamples=1)
