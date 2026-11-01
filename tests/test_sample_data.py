"""
tests/test_sample_data.py
-------------------------
Checks that the files in data/sample/ are safe to publish and consistent.
If you have not generated the sample yet (python make_sample_data.py), these
tests are skipped instead of failing.
"""

import ipaddress

import pandas as pd
import pytest

from cybershield.schema import (
    ALERT_COLUMNS,
    EVENT_COLUMNS,
    EVIDENCE_COLUMNS,
    SAMPLE_DIR,
    UNIFIED_COLUMNS,
)

pytestmark = pytest.mark.skipif(
    not (SAMPLE_DIR / "unified_events.csv").exists(),
    reason="sample data not generated (run: python make_sample_data.py)",
)

DOCUMENTATION_NETWORKS = [ipaddress.ip_network(n) for n in
                          ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def read(name):
    return pd.read_csv(SAMPLE_DIR / name, dtype=str, keep_default_na=False)


def test_sample_files_have_the_expected_columns():
    assert list(read("synthetic_events.csv").columns) == EVENT_COLUMNS
    assert list(read("local_events.csv").columns) == EVENT_COLUMNS
    assert list(read("unified_events.csv").columns) == UNIFIED_COLUMNS
    assert list(read("alerts.csv").columns) == ALERT_COLUMNS
    assert list(read("alert_evidence.csv").columns) == EVIDENCE_COLUMNS


def test_synthetic_rows_use_only_documentation_ips_and_demo_usernames():
    synthetic = read("synthetic_events.csv")
    assert set(synthetic["source_type"]) == {"synthetic"}
    for ip in synthetic["source_ip"].unique():
        assert any(ipaddress.ip_address(ip) in net for net in DOCUMENTATION_NETWORKS), ip
    assert synthetic["username"].str.endswith("_demo").all()


def test_local_rows_come_only_from_loopback_and_are_labelled_local_lab():
    local = read("local_events.csv")
    assert set(local["source_ip"]) == {"127.0.0.1"}
    assert set(local["source_type"]) == {"local_lab"}
    assert set(local["environment"]) == {"localhost_lab"}


def test_no_password_like_text_anywhere_in_the_sample():
    for path in SAMPLE_DIR.glob("*.csv"):
        text = path.read_text(encoding="utf-8").lower()
        assert "password" not in text.split("\n", 1)[1], path.name
        assert "demoonly" not in text, path.name


def test_nothing_was_rejected_and_alert_evidence_points_at_real_events():
    assert len(read("rejected_records.csv")) == 0
    unified, evidence, alerts = read("unified_events.csv"), read("alert_evidence.csv"), read("alerts.csv")
    assert evidence["event_id"].isin(unified["event_id"]).all()
    assert set(evidence["alert_id"]) == set(alerts["alert_id"])


def test_sample_contains_both_source_types_and_a_high_severity_alert():
    unified, alerts = read("unified_events.csv"), read("alerts.csv")
    assert set(unified["source_type"]) == {"synthetic", "local_lab"}
    assert "high" in set(alerts["severity"])
    assert "local_lab" in set(alerts["source_type"])