"""
tests/test_loader.py
--------------------
Automated tests for cybershield/loader.py (reading, validating, merging).
Files are created in pytest's temporary folder, never in your data/ folder.
"""

import pandas as pd
import pytest

from cybershield.loader import (
    build_unified,
    load_events_file,
    save_outputs,
    validate_events,
)
from cybershield.schema import (
    EVENT_COLUMNS,
    REJECTED_COLUMNS,
    UNIFIED_COLUMNS,
)

HEADER = ",".join(EVENT_COLUMNS)


def row(timestamp="2026-10-01T10:00:00+00:00", ip="203.0.113.5", user="alice_demo",
        event_type="login_attempt", outcome="failure", source_type="synthetic",
        environment="simulation"):
    return ",".join([timestamp, ip, user, event_type, outcome, source_type, environment])


def write(tmp_path, name, *lines, header=HEADER):
    path = tmp_path / name
    path.write_text("\n".join([header, *lines]) + "\n", encoding="utf-8")
    return path


# --------------------------------------------------------- good rows ---------
def test_valid_rows_are_cleaned_and_kept(tmp_path):
    path = write(
        tmp_path, "ok.csv",
        row(),
        row(timestamp="2026-10-01T10:00:00Z", ip="203.0.113.5 ", user="ALICE_Demo",
            outcome="FAILURE"),
        row(timestamp="2026-10-01T15:30:00+05:30", ip="2001:DB8::1", user="bob_demo",
            outcome="success"),
    )
    valid, rejected, rows_read = load_events_file(path)
    assert (rows_read, len(valid), len(rejected)) == (3, 3, 0)
    assert list(valid.columns) == EVENT_COLUMNS
    assert valid.loc[1, "username"] == "alice_demo"
    assert valid.loc[1, "outcome"] == "failure"
    assert valid.loc[1, "source_ip"] == "203.0.113.5"
    assert valid.loc[2, "timestamp_utc"] == "2026-10-01T10:00:00+00:00"   # IST -> UTC
    assert valid.loc[2, "source_ip"] == "2001:db8::1"


def test_local_lab_invalid_username_label_is_a_valid_row(tmp_path):
    path = write(tmp_path, "lab.csv", row(ip="127.0.0.1", user="invalid_username",
                                          source_type="local_lab",
                                          environment="localhost_lab"))
    valid, rejected, _ = load_events_file(path)
    assert len(valid) == 1 and len(rejected) == 0


# -------------------------------------------------------- bad rows -----------
@pytest.mark.parametrize("bad_row, reason", [
    (row(timestamp="2026-10-01T10:00:00"), "timestamp has no UTC offset"),
    (row(timestamp="2026-10-01"), "timestamp has no UTC offset"),
    (row(timestamp="yesterday"), "unparseable timestamp"),
    (row(timestamp=""), "missing timestamp"),
    (row(ip=""), "missing source_ip"),
    (row(ip="999.1.1.1"), "invalid source_ip"),
    (row(user=""), "missing username"),
    (row(user="=cmd|calc"), "invalid username"),
    (row(user="a" * 100), "invalid username"),
    (row(outcome="maybe"), "invalid outcome"),
    (row(event_type="logout"), "invalid event_type"),
    (row(source_type="real"), "invalid source_type"),
    (row(source_type="synthetic", environment="localhost_lab"),
     "source_type and environment contradict each other"),
    ("2026-10-01T10:00:00+00:00,203.0.113.5,alice_demo", "wrong number of fields"),
    (row() + ",extra,stuff", "wrong number of fields"),
])
def test_each_kind_of_bad_row_is_rejected_with_a_reason(tmp_path, bad_row, reason):
    path = write(tmp_path, "bad.csv", row(), bad_row)
    valid, rejected, rows_read = load_events_file(path)
    assert (rows_read, len(valid), len(rejected)) == (2, 1, 1)
    assert reason in rejected.loc[0, "reject_reason"]
    assert rejected.loc[0, "line_number"] == 3          # header is line 1


def test_several_reasons_are_all_reported(tmp_path):
    path = write(tmp_path, "multi.csv", row(ip="nope", user="", outcome="x"))
    _, rejected, _ = load_events_file(path)
    reason = rejected.loc[0, "reject_reason"]
    for part in ("invalid source_ip", "missing username", "invalid outcome"):
        assert part in reason


def test_rejected_formula_text_is_neutralised(tmp_path):
    path = write(tmp_path, "formula.csv", row(timestamp='"=HYPERLINK(""http://x"")"'))
    _, rejected, _ = load_events_file(path)
    assert rejected.loc[0, "raw_record"].startswith("'=")


def test_invalid_utf8_row_is_rejected_without_crashing(tmp_path):
    path = tmp_path / "bytes.csv"
    path.write_bytes((HEADER + "\n").encode()
                     + b"2026-10-01T10:00:00+00:00,1.2.3.4,al\xff\xfece,login_attempt,"
                       b"failure,synthetic,simulation\n")
    valid, rejected, _ = load_events_file(path)
    assert len(valid) == 0 and len(rejected) == 1


def test_validate_events_handles_empty_and_all_invalid_frames():
    valid, rejected = validate_events(pd.DataFrame(columns=EVENT_COLUMNS))
    assert len(valid) == 0 and len(rejected) == 0
    valid, rejected = validate_events(pd.DataFrame([["x"] * 7], columns=EVENT_COLUMNS))
    assert len(valid) == 0 and len(rejected) == 1
    assert list(rejected.columns) == REJECTED_COLUMNS


# ------------------------------------------------------ file shapes ----------
def test_missing_required_column_is_a_hard_error(tmp_path):
    path = tmp_path / "nocol.csv"
    path.write_text("timestamp_utc,source_ip\n2026-10-01T10:00:00+00:00,1.2.3.4\n")
    with pytest.raises(ValueError, match="required column"):
        load_events_file(path)


def test_bom_reordered_columns_extra_column_and_upper_case_header(tmp_path):
    bom = tmp_path / "bom.csv"
    bom.write_bytes(b"\xef\xbb\xbf" + (HEADER + "\n" + row() + "\n").encode())
    assert len(load_events_file(bom)[0]) == 1

    columns = list(reversed(EVENT_COLUMNS)) + ["notes"]
    values = {"timestamp_utc": "2026-10-01T10:00:00+00:00", "source_ip": "1.2.3.4",
              "username": "x1", "event_type": "login_attempt", "outcome": "failure",
              "source_type": "synthetic", "environment": "simulation", "notes": "hi"}
    odd = tmp_path / "odd.csv"
    odd.write_text(",".join(c.upper() for c in columns) + "\n"
                   + ",".join(values[c] for c in columns) + "\n")
    valid, _, _ = load_events_file(odd)
    assert len(valid) == 1 and list(valid.columns) == EVENT_COLUMNS


def test_header_only_and_zero_byte_files_have_no_rows(tmp_path):
    header_only = write(tmp_path, "h.csv")
    zero = tmp_path / "zero.csv"
    zero.write_text("")
    assert load_events_file(header_only)[2] == 0
    assert load_events_file(zero)[2] == 0


# --------------------------------------------------------- merging -----------
def test_merge_sorts_by_time_numbers_events_and_keeps_labels(tmp_path):
    synthetic = write(tmp_path, "s.csv", row(timestamp="2026-10-01T10:00:09+00:00"),
                      row(timestamp="2026-10-01T10:00:05+00:00", user="u1"))
    local = write(tmp_path, "l.csv", row(timestamp="2026-10-01T10:00:05+00:00", ip="127.0.0.1",
                                         user="u2", source_type="local_lab",
                                         environment="localhost_lab"))
    unified, rejected, report = build_unified([synthetic, local])
    assert list(unified.columns) == UNIFIED_COLUMNS
    assert list(unified["event_id"]) == [1, 2, 3]
    assert unified["timestamp_utc"].is_monotonic_increasing
    assert list(unified["username"][:2]) == ["u1", "u2"]          # tie keeps file order
    assert report.valid_by_source_type == {"synthetic": 2, "local_lab": 1}
    assert set(unified["source_type"]) == {"synthetic", "local_lab"}


def test_identical_rows_are_kept_and_only_counted(tmp_path):
    path = write(tmp_path, "dup.csv", row(), row(), row())
    unified, _, report = build_unified([path])
    assert len(unified) == 3
    assert report.duplicate_rows_kept == 2


def test_same_file_listed_twice_is_loaded_once(tmp_path):
    path = write(tmp_path, "a.csv", row(), row(timestamp="2026-10-01T10:00:01+00:00"))
    unified, _, report = build_unified([path, path])
    assert len(unified) == 2
    assert report.files_skipped_same_path == ["a.csv"]


def test_missing_file_is_skipped_but_no_files_at_all_is_an_error(tmp_path):
    present = write(tmp_path, "here.csv", row())
    unified, _, report = build_unified([tmp_path / "gone.csv", present])
    assert len(unified) == 1 and len(report.files_missing) == 1
    with pytest.raises(FileNotFoundError):
        build_unified([tmp_path / "gone1.csv", tmp_path / "gone2.csv"])


def test_save_outputs_writes_both_files_with_headers_and_no_temp_files(tmp_path):
    path = write(tmp_path, "a.csv", row(), row(timestamp="bad"))
    unified, rejected, _ = build_unified([path])
    unified_path, rejected_path = save_outputs(
        unified, rejected, tmp_path / "out" / "u.csv", tmp_path / "out" / "r.csv")
    assert list(pd.read_csv(unified_path).columns) == UNIFIED_COLUMNS
    assert list(pd.read_csv(rejected_path).columns) == REJECTED_COLUMNS
    assert not list((tmp_path / "out").glob("*.tmp"))