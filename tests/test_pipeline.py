"""
tests/test_pipeline.py
----------------------
End-to-end test of run_pipeline.py: generate -> load -> detect, writing only
into pytest's temporary folder.
"""

import pandas as pd
import pytest

from cybershield.schema import ALERT_COLUMNS, UNIFIED_COLUMNS
from run_pipeline import PipelineOptions, run_pipeline


def options(tmp_path, **changes):
    values = dict(
        start_date="2026-10-01",
        synthetic_path=tmp_path / "raw" / "synthetic.csv",
        local_path=tmp_path / "raw" / "local.csv",          # does not exist: that is fine
        unified_path=tmp_path / "out" / "unified.csv",
        rejected_path=tmp_path / "out" / "rejected.csv",
        alerts_path=tmp_path / "out" / "alerts.csv",
        evidence_path=tmp_path / "out" / "evidence.csv",
    )
    values.update(changes)
    return PipelineOptions(**values)


def test_default_run_catches_the_four_designed_attacks_and_misses_the_other_three(tmp_path):
    summary = run_pipeline(options(tmp_path), log=lambda *_: None)
    alerts = pd.read_csv(tmp_path / "out" / "alerts.csv")
    assert list(alerts.columns) == ALERT_COLUMNS
    assert summary["alerts"] == len(alerts) == 4
    assert set(alerts["source_ip"]) == {"203.0.113.45", "198.51.100.77", "203.0.113.88"}
    assert (alerts["source_ip"] == "203.0.113.45").sum() == 2          # scenarios 1 and 7
    # scenarios 4, 5 and 6 are designed to slip under the rule
    assert not alerts["source_ip"].isin(["203.0.113.99", "203.0.113.120",
                                         "203.0.113.150"]).any()
    assert set(alerts["source_type"]) == {"synthetic"}
    assert summary["rows_rejected"] == 0


def test_bob_alert_is_high_because_a_success_followed(tmp_path):
    run_pipeline(options(tmp_path), log=lambda *_: None)
    alerts = pd.read_csv(tmp_path / "out" / "alerts.csv")
    bob = alerts[alerts["username"] == "bob_demo"].iloc[0]
    assert (bob["severity"], bob["success_after_failures"]) == ("high", "yes")


def test_evidence_rows_point_at_real_events(tmp_path):
    run_pipeline(options(tmp_path), log=lambda *_: None)
    unified = pd.read_csv(tmp_path / "out" / "unified.csv")
    evidence = pd.read_csv(tmp_path / "out" / "evidence.csv")
    alerts = pd.read_csv(tmp_path / "out" / "alerts.csv")
    assert list(unified.columns) == UNIFIED_COLUMNS
    assert evidence["event_id"].isin(unified["event_id"]).all()
    assert set(evidence["alert_id"]) == set(alerts["alert_id"])


def test_same_settings_give_identical_output(tmp_path):
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    run_pipeline(options(first), log=lambda *_: None)
    run_pipeline(options(second), log=lambda *_: None)
    for name in ("unified.csv", "alerts.csv", "evidence.csv"):
        assert (first / "out" / name).read_bytes() == (second / "out" / name).read_bytes()


def test_lower_threshold_finds_the_near_miss(tmp_path):
    summary = run_pipeline(options(tmp_path, threshold=4), log=lambda *_: None)
    alerts = pd.read_csv(tmp_path / "out" / "alerts.csv")
    assert "203.0.113.99" in set(alerts["source_ip"])                  # scenario 4
    assert summary["alerts"] == 5


def test_bad_settings_fail_before_any_file_is_written(tmp_path):
    with pytest.raises(ValueError):
        run_pipeline(options(tmp_path, threshold=1), log=lambda *_: None)
    assert not (tmp_path / "raw").exists()


def test_skip_synthetic_without_a_file_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        run_pipeline(options(tmp_path, skip_synthetic=True), log=lambda *_: None)