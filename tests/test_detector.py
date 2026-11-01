"""
tests/test_detector.py
----------------------
Automated tests for cybershield/detector.py.

Every test builds a tiny DataFrame of events, runs the detector and checks
the alerts. Times are written as "seconds after 10:00:00 UTC on 2026-10-01",
which makes the arithmetic easy to read.
"""

from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from cybershield.detector import (
    DetectorConfig,
    classify_severity,
    detect_brute_force,
    find_episodes,
)
from cybershield.schema import ALERT_COLUMNS, EVENT_COLUMNS

BASE = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)


def at(seconds):
    """UTC timestamp text, `seconds` after the base time."""
    return (BASE + timedelta(seconds=seconds)).isoformat(timespec="seconds")


def event(seconds=0, ip="203.0.113.5", user="alice_demo", outcome="failure",
          source_type="synthetic", environment="simulation", timestamp=None):
    return {
        "timestamp_utc": at(seconds) if timestamp is None else timestamp,
        "source_ip": ip,
        "username": user,
        "event_type": "login_attempt",
        "outcome": outcome,
        "source_type": source_type,
        "environment": environment,
    }


def failures(*seconds, **kwargs):
    return [event(s, **kwargs) for s in seconds]


def detect(rows, **config):
    return detect_brute_force(pd.DataFrame(rows, columns=EVENT_COLUMNS),
                              DetectorConfig(**config))


# ---------------------------------------------------------------- threshold --
def test_four_failures_within_five_minutes_no_alert():
    assert len(detect(failures(0, 60, 120, 180)).alerts) == 0


def test_five_failures_within_five_minutes_alert():
    alerts = detect(failures(0, 60, 120, 180, 240)).alerts
    assert len(alerts) == 1
    assert alerts.loc[0, "attempt_count"] == 5
    assert alerts.loc[0, "severity"] == "low"


def test_five_failures_outside_any_five_minute_window_no_alert():
    # 100 s apart: any 5 in a row span 400 s, and a window holds at most 4.
    assert len(detect(failures(0, 100, 200, 300, 400)).alerts) == 0


def test_window_is_inclusive_at_exactly_five_minutes():
    assert len(detect(failures(0, 75, 150, 225, 300)).alerts) == 1


def test_window_is_exceeded_by_one_second():
    assert len(detect(failures(0, 75, 150, 225, 301)).alerts) == 0


# ---------------------------------------------------------------- successes --
def test_success_does_not_count_as_failure():
    rows = failures(0, 30, 60, 90) + [event(120, outcome="success")]
    assert len(detect(rows).alerts) == 0


def test_success_between_failures_does_not_hide_five_failures():
    rows = failures(0, 30, 60, 90, 120) + [event(45, outcome="success")]
    assert len(detect(rows).alerts) == 1


# ---------------------------------------------------- separate groups -------
def test_different_usernames_are_evaluated_separately():
    rows = (failures(0, 10, 20, user="alice_demo")
            + failures(30, 40, user="bob_demo"))
    assert len(detect(rows).alerts) == 0


def test_different_source_ips_are_evaluated_separately():
    rows = (failures(0, 10, 20, ip="203.0.113.5")
            + failures(30, 40, ip="203.0.113.6"))
    assert len(detect(rows).alerts) == 0


def test_username_case_is_ignored():
    rows = [event(0, user="ALICE_demo"), event(10), event(20, user="Alice_Demo"),
            event(30), event(40)]
    assert len(detect(rows).alerts) == 1


# --------------------------------------------------------------- UTC time ----
def test_mixed_utc_offsets_are_converted_before_comparing():
    rows = [
        event(timestamp="2026-10-01T10:00:00Z"),
        event(timestamp="2026-10-01T15:30:30+05:30"),   # 10:00:30 UTC
        event(timestamp="2026-10-01T10:01:00+00:00"),
        event(timestamp="2026-10-01T05:32:00-04:30"),   # 10:02:00 UTC
        event(timestamp="2026-10-01T10:02:30+00:00"),
    ]
    result = detect(rows)
    assert len(result.alerts) == 1
    assert result.alerts.loc[0, "window_start_utc"] == "2026-10-01T10:00:00+00:00"
    assert result.alerts.loc[0, "window_end_utc"] == "2026-10-01T10:02:30+00:00"


def test_same_clock_digits_with_different_offsets_are_different_instants():
    rows = [event(timestamp=f"2026-10-01T10:0{i}:00+00:00") for i in range(4)]
    rows.append(event(timestamp="2026-10-01T10:04:00+05:30"))   # 04:34 UTC
    assert len(detect(rows).alerts) == 0


def test_timestamps_without_utc_offset_are_skipped_not_guessed():
    result = detect([event(timestamp="2026-10-01T10:00:00")] * 5)
    assert len(result.alerts) == 0
    assert result.skip_reasons == {"timestamp has no UTC offset": 5}


# ------------------------------------------------- missing / invalid data ----
def test_bad_rows_are_skipped_and_valid_rows_still_detected():
    rows = failures(0, 10, 20, 30, 40) + [
        event(timestamp="garbage"),
        event(timestamp=" "),
        event(ip=""),
        event(user=""),
        event(outcome="maybe"),
        {**event(), "event_type": "logout"},
        event(source_type=""),
    ]
    frame = pd.DataFrame(rows, columns=EVENT_COLUMNS)
    frame.loc[len(frame)] = [None] * 7
    frame.loc[len(frame)] = [float("nan")] * 7
    result = detect_brute_force(frame)
    assert len(result.alerts) == 1
    assert result.rows_skipped == 9


def test_empty_input_gives_empty_alerts_with_all_columns():
    result = detect([])
    assert len(result.alerts) == 0
    assert list(result.alerts.columns) == ALERT_COLUMNS


def test_missing_required_columns_raise_value_error():
    with pytest.raises(ValueError):
        detect_brute_force(pd.DataFrame({"unrelated": [1]}))


def test_non_numeric_event_id_row_is_skipped():
    frame = pd.DataFrame(failures(0, 10, 20, 30, 40), columns=EVENT_COLUMNS)
    frame["event_id"] = ["1", "2", "oops", "4", "5"]
    result = detect_brute_force(frame)
    assert result.rows_skipped == 1
    assert len(result.alerts) == 0


# ------------------------------------------------------------- labels --------
def test_synthetic_source_labels_are_preserved():
    alert = detect(failures(0, 10, 20, 30, 40)).alerts.loc[0]
    assert (alert["source_type"], alert["environment"]) == ("synthetic", "simulation")


def test_local_lab_source_labels_are_preserved():
    rows = failures(0, 10, 20, 30, 40, ip="127.0.0.1",
                    source_type="local_lab", environment="localhost_lab")
    alert = detect(rows).alerts.loc[0]
    assert (alert["source_type"], alert["environment"]) == ("local_lab", "localhost_lab")


def test_same_ip_and_user_in_different_source_types_are_never_mixed():
    rows = (failures(0, 10, 20, ip="127.0.0.1", source_type="synthetic")
            + failures(30, 40, ip="127.0.0.1", source_type="local_lab",
                       environment="localhost_lab"))
    assert len(detect(rows).alerts) == 0


# ------------------------------------------------ episodes / duplicates ------
def test_one_burst_produces_one_alert():
    result = detect(failures(*[i * 15 for i in range(14)]))
    assert len(result.alerts) == 1
    assert result.alerts.loc[0, "attempt_count"] == 14
    assert result.alerts.loc[0, "severity"] == "medium"
    assert result.alerts.loc[0, "alert_time_utc"] == at(60)   # the 5th failure


def test_two_separate_bursts_produce_two_alerts_with_separate_evidence():
    rows = failures(*[i * 15 for i in range(5)]) + failures(*[1000 + i * 15 for i in range(5)])
    result = detect(rows)
    assert list(result.alerts["alert_id"]) == ["ALT-0001", "ALT-0002"]
    first = set(result.evidence[result.evidence.alert_id == "ALT-0001"].event_id)
    second = set(result.evidence[result.evidence.alert_id == "ALT-0002"].event_id)
    assert first.isdisjoint(second)


def test_failures_already_reported_are_not_reused_by_a_later_burst():
    result = detect(failures(0, 10, 20, 30, 40, 330, 331, 332, 333))
    assert len(result.alerts) == 1
    assert result.alerts.loc[0, "attempt_count"] == 5


def test_failures_in_the_same_second_each_count():
    result = detect(failures(0, 0, 0, 0, 0))
    assert len(result.alerts) == 1


def test_input_order_does_not_matter():
    result = detect(failures(240, 0, 180, 60, 120))
    assert len(result.alerts) == 1
    assert result.alerts.loc[0, "window_start_utc"] == at(0)


# --------------------------------------------------- severity / success ------
@pytest.mark.parametrize("count, expected", [
    (5, "low"), (9, "low"), (10, "medium"), (14, "medium"), (15, "high"),
])
def test_severity_bands_with_default_threshold(count, expected):
    assert classify_severity(count, 5, success_after=False) == expected


def test_success_after_failures_raises_severity_to_high_and_is_in_evidence():
    rows = failures(*[i * 20 for i in range(8)]) + [event(180, outcome="success")]
    result = detect(rows)
    assert result.alerts.loc[0, "severity"] == "high"
    assert result.alerts.loc[0, "success_after_failures"] == "yes"
    assert len(result.evidence) == 9            # 8 failures + the success


@pytest.mark.parametrize("success", [
    event(1200, outcome="success"),                          # far too late
    event(100, ip="203.0.113.99", outcome="success"),        # different IP
    event(-100, outcome="success"),                          # before the alert
])
def test_unrelated_successes_do_not_raise_the_flag(success):
    rows = failures(*[i * 20 for i in range(8)]) + [success]
    assert detect(rows).alerts.loc[0, "success_after_failures"] == "no"


# ------------------------------------------------------ configuration --------
def test_threshold_and_window_are_configurable():
    assert len(detect(failures(0, 20, 40), threshold=3, window_minutes=1).alerts) == 1
    assert len(detect(failures(0, 20, 61), threshold=3, window_minutes=1).alerts) == 0


def test_configuration_is_recorded_in_the_alert():
    alert = detect(failures(0, 10, 20), threshold=3, window_minutes=0.5).alerts.loc[0]
    assert alert["threshold"] == 3
    assert alert["window_minutes"] == 0.5


@pytest.mark.parametrize("bad", [
    {"threshold": 1}, {"threshold": 0}, {"threshold": True}, {"threshold": 2.5},
    {"window_minutes": 0}, {"window_minutes": -1}, {"window_minutes": float("nan")},
    {"window_minutes": 100000}, {"window_minutes": "x"},
])
def test_invalid_configuration_is_rejected(bad):
    with pytest.raises(ValueError):
        DetectorConfig(**bad)


# ------------------------------------------- the algorithm on its own --------
def test_find_episodes_empty_input():
    assert find_episodes([], 5, 300) == []


def test_find_episodes_returns_start_alert_and_end_positions():
    assert find_episodes([0, 10, 20, 30, 40, 50], 5, 300) == [(0, 4, 5)]


def test_find_episodes_worked_example_from_the_walkthrough():
    assert find_episodes([0, 20, 40, 50, 200, 210, 220], 3, 60) == [(0, 2, 3), (4, 6, 6)]