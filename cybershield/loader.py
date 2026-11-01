"""
cybershield/loader.py
---------------------
Loads, validates and merges authentication-event CSV files.

Pipeline for each input file
    1. read_raw_events()  : read every row as TEXT; rows with the wrong
                            number of fields are rejected immediately.
    2. validate_events()  : check each remaining row. Good rows are cleaned
                            (UTC timestamps, normalised IPs, lowercase
                            categories); bad rows are set aside with a reason.
Then build_unified() merges all files, sorts by time and numbers the events.

Design rules
    * A file with missing required COLUMNS is a hard error (ValueError):
      something is structurally wrong and the dashboard would mislead.
    * A bad ROW is never fatal. It is rejected, counted and saved to
      rejected_records.csv so nothing disappears silently.
    * Rows are NEVER de-duplicated. Our logs have one-second resolution and
      no unique event id, so two identical rows can be two real attempts.
      Exact duplicates are only counted and reported.
    * source_type and environment are preserved on every row.

Run from the project root:
    python -m cybershield.loader
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from cybershield.schema import (
    COL_ENVIRONMENT,
    COL_EVENT_ID,
    COL_EVENT_TYPE,
    COL_OUTCOME,
    COL_REJ_LINE,
    COL_REJ_RAW,
    COL_REJ_REASON,
    COL_REJ_SOURCE_FILE,
    COL_SOURCE_IP,
    COL_SOURCE_TYPE,
    COL_TIMESTAMP,
    COL_USERNAME,
    EVENT_COLUMNS,
    LOCAL_EVENTS_PATH,
    REJECTED_COLUMNS,
    REJECTED_RECORDS_PATH,
    SOURCE_ENV_PAIRS,
    SYNTHETIC_EVENTS_PATH,
    UNIFIED_COLUMNS,
    UNIFIED_EVENTS_PATH,
    VALID_ENVIRONMENTS,
    VALID_EVENT_TYPES,
    VALID_OUTCOMES,
    VALID_SOURCE_TYPES,
)

# ----------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------
# Usernames: letters, digits, _ . @ -  ; start with a letter or digit;
# at most 64 characters. (Lowercase only, because we lowercase first.)
USERNAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.@-]{0,63}")

# A timestamp must END with a clock time followed by an explicit UTC offset,
# such as "...T10:15:00+00:00", "...T10:15:00Z" or "...T15:45:00+05:30".
# A timestamp with no offset is ambiguous (whose clock?) and is rejected.
TIMEZONE_PATTERN = r"\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}(?::?\d{2})?)$"

OUTPUT_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S+00:00"   # always UTC, whole seconds

LINE_COLUMN = "_line"            # internal: row's line number in its source file
RAW_RECORD_MAX_CHARS = 300       # how much of a rejected row we keep
FORMULA_STARTERS = ("=", "+", "-", "@")


# ----------------------------------------------------------------------
# Report object
# ----------------------------------------------------------------------
@dataclass
class LoadReport:
    """Everything that happened while loading, for printing and for tests."""

    files_loaded: list = field(default_factory=list)
    files_missing: list = field(default_factory=list)
    files_skipped_same_path: list = field(default_factory=list)
    per_file: dict = field(default_factory=dict)          # name -> counts
    rows_read: int = 0
    rows_valid: int = 0
    rows_rejected: int = 0
    duplicate_rows_kept: int = 0
    rejected_by_reason: dict = field(default_factory=dict)
    valid_by_source_type: dict = field(default_factory=dict)

    def summary_lines(self) -> list:
        lines = ["Load summary (actual counts from this run)"]
        for name, counts in self.per_file.items():
            lines.append(
                f"  {name}: read {counts['read']}, valid {counts['valid']}, "
                f"rejected {counts['rejected']}"
            )
        for path in self.files_missing:
            lines.append(f"  NOT FOUND (skipped): {path}")
        for name in self.files_skipped_same_path:
            lines.append(f"  Same file listed twice, loaded once: {name}")
        lines.append(
            f"  TOTAL: read {self.rows_read}, valid {self.rows_valid}, "
            f"rejected {self.rows_rejected}"
        )
        if self.valid_by_source_type:
            lines.append(f"  Valid rows by source_type: {self.valid_by_source_type}")
        if self.rejected_by_reason:
            lines.append("  Rejections by reason:")
            for reason, count in sorted(self.rejected_by_reason.items()):
                lines.append(f"    {count:>5}  {reason}")
        lines.append(
            f"  Exact duplicate rows KEPT (not removed): {self.duplicate_rows_kept}"
        )
        return lines


# ----------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------
def _as_text(value) -> str:
    """Turn None / NaN / numbers into plain text."""
    if value is None:
        return ""
    if isinstance(value, float) and value != value:   # NaN check
        return ""
    return str(value)


def _normalise_ip(text: str):
    """Return the canonical form of a valid IPv4/IPv6 address, else None."""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _safe_raw_text(values) -> str:
    """
    Join a rejected row's values into one safe, short text cell.

    The row failed validation, so it may contain anything. We therefore:
      * replace control characters (newlines, tabs, ...) with spaces,
      * cut it to RAW_RECORD_MAX_CHARS,
      * put a ' in front if it starts with = + - @, so Excel will not run it
        as a formula (CSV / formula injection).
    """
    text = " | ".join(_as_text(v) for v in values)
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)[:RAW_RECORD_MAX_CHARS]
    if text.startswith(FORMULA_STARTERS):
        text = "'" + text
    return text


def _reason_series(mask: pd.Series, message: str) -> pd.Series:
    """A Series holding `message` where mask is True and '' elsewhere."""
    return pd.Series(np.where(mask, message, ""), index=mask.index)


def _empty_valid() -> pd.DataFrame:
    return pd.DataFrame(columns=EVENT_COLUMNS, dtype=object)


def _rejected_frame(records: list) -> pd.DataFrame:
    return pd.DataFrame(records, columns=REJECTED_COLUMNS)


# ----------------------------------------------------------------------
# Step 1: read raw rows as text
# ----------------------------------------------------------------------
def read_raw_events(path):
    """
    Read a CSV file without interpreting anything.

    Returns (raw_df, malformed_df):
      raw_df       : rows with the right number of fields, every value as text,
                     plus a hidden line-number column
      malformed_df : rows with too many or too few fields (already in the
                     rejected-records format)

    Raises ValueError if required columns are missing.
    Headers are matched by NAME, so column order does not matter and extra
    columns are ignored. A leading BOM (added by some Excel versions) is
    removed. Bytes that are not valid UTF-8 are replaced, which makes the
    affected row fail validation instead of crashing the whole run.
    """
    path = Path(path)
    good_rows = []
    malformed = []

    try:
        with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
            reader = csv.DictReader(handle)
            header = reader.fieldnames
            if header is None:                      # completely empty file
                return (pd.DataFrame(columns=EVENT_COLUMNS + [LINE_COLUMN]),
                        _rejected_frame([]))

            reader.fieldnames = [str(name).strip().lower() for name in header]
            missing = [c for c in EVENT_COLUMNS if c not in reader.fieldnames]
            if missing:
                raise ValueError(
                    f"{path.name}: required column(s) missing: {missing}. "
                    f"Found: {reader.fieldnames}"
                )

            for row in reader:
                line_number = reader.line_num
                too_many = None in row                        # extra fields
                too_few = any(v is None for v in row.values())  # missing fields
                if too_many or too_few:
                    values = [v for k, v in row.items() if k is not None]
                    if too_many:
                        values.extend(row[None])
                    malformed.append({
                        COL_REJ_SOURCE_FILE: path.name,
                        COL_REJ_LINE: line_number,
                        COL_REJ_REASON: "wrong number of fields",
                        COL_REJ_RAW: _safe_raw_text(values),
                    })
                    continue

                record = {column: row[column] for column in EVENT_COLUMNS}
                record[LINE_COLUMN] = line_number
                good_rows.append(record)
    except csv.Error as exc:
        raise ValueError(f"{path.name}: the file is not readable as CSV ({exc})") from exc

    raw_df = pd.DataFrame(good_rows, columns=EVENT_COLUMNS + [LINE_COLUMN])
    return raw_df, _rejected_frame(malformed)


# ----------------------------------------------------------------------
# Step 2: validate and clean rows
# ----------------------------------------------------------------------
def validate_events(raw: pd.DataFrame, source_file: str = "<memory>"):
    """
    Validate a DataFrame of text values.

    Returns (valid_df, rejected_df).
      valid_df    : EVENT_COLUMNS only, cleaned (see below), same order as input
      rejected_df : REJECTED_COLUMNS, one row per bad record with every
                    reason that applies

    Cleaning applied to valid rows
      * timestamp  -> UTC, written as YYYY-MM-DDTHH:MM:SS+00:00
      * source_ip  -> canonical text form
      * username, event_type, outcome, source_type, environment
                   -> trimmed and lowercased
    Rejection reasons
      missing/unparseable timestamp, timestamp without UTC offset,
      missing/invalid source_ip, missing/invalid username,
      missing/invalid event_type, outcome, source_type or environment,
      source_type and environment that contradict each other.
    """
    missing = [c for c in EVENT_COLUMNS if c not in raw.columns]
    if missing:
        raise ValueError(f"required column(s) missing: {missing}")

    if raw.empty:
        return _empty_valid(), _rejected_frame([])

    df = raw.copy().reset_index(drop=True)
    if LINE_COLUMN not in df.columns:
        # No real line numbers (data built in memory): header is line 1.
        df[LINE_COLUMN] = range(2, len(df) + 2)

    original = df[EVENT_COLUMNS].copy()          # untouched copy for the audit text
    for column in EVENT_COLUMNS:
        df[column] = df[column].map(_as_text).str.strip()
    for column in (COL_USERNAME, COL_EVENT_TYPE, COL_OUTCOME,
                   COL_SOURCE_TYPE, COL_ENVIRONMENT):
        df[column] = df[column].str.lower()

    reasons = []

    # ---- timestamp ----------------------------------------------------
    ts_text = df[COL_TIMESTAMP]
    parsed = pd.to_datetime(ts_text, format="ISO8601", utc=True, errors="coerce")
    has_offset = ts_text.str.contains(TIMEZONE_PATTERN, regex=True)
    reasons.append(_reason_series(ts_text == "", "missing timestamp"))
    reasons.append(_reason_series((ts_text != "") & parsed.isna(), "unparseable timestamp"))
    reasons.append(_reason_series(
        (ts_text != "") & parsed.notna() & ~has_offset, "timestamp has no UTC offset"
    ))

    # ---- source_ip ----------------------------------------------------
    ip_text = df[COL_SOURCE_IP]
    ip_clean = ip_text.map(_normalise_ip)
    reasons.append(_reason_series(ip_text == "", "missing source_ip"))
    reasons.append(_reason_series((ip_text != "") & ip_clean.isna(), "invalid source_ip"))

    # ---- username -----------------------------------------------------
    user_text = df[COL_USERNAME]
    user_ok = user_text.map(lambda s: USERNAME_PATTERN.fullmatch(s) is not None)
    reasons.append(_reason_series(user_text == "", "missing username"))
    reasons.append(_reason_series((user_text != "") & ~user_ok, "invalid username"))

    # ---- categorical columns -------------------------------------------
    for column, allowed in (
        (COL_EVENT_TYPE, VALID_EVENT_TYPES),
        (COL_OUTCOME, VALID_OUTCOMES),
        (COL_SOURCE_TYPE, VALID_SOURCE_TYPES),
        (COL_ENVIRONMENT, VALID_ENVIRONMENTS),
    ):
        reasons.append(_reason_series(df[column] == "", f"missing {column}"))
        reasons.append(_reason_series(
            (df[column] != "") & ~df[column].isin(allowed), f"invalid {column}"
        ))

    # ---- source_type must match environment -----------------------------
    expected_env = df[COL_SOURCE_TYPE].map(SOURCE_ENV_PAIRS)
    both_known = expected_env.notna() & df[COL_ENVIRONMENT].isin(VALID_ENVIRONMENTS)
    reasons.append(_reason_series(
        both_known & (expected_env != df[COL_ENVIRONMENT]),
        "source_type and environment contradict each other",
    ))

    # ---- combine ---------------------------------------------------------
    reason_text = pd.Series(
        ["; ".join(part for part in parts if part) for parts in zip(*reasons)],
        index=df.index,
    )
    is_valid = reason_text == ""

    valid = df.loc[is_valid, EVENT_COLUMNS].copy()
    valid[COL_TIMESTAMP] = parsed[is_valid].dt.strftime(OUTPUT_TIMESTAMP_FORMAT)
    valid[COL_SOURCE_IP] = ip_clean[is_valid]
    valid = valid.reset_index(drop=True)

    rejected_records = [
        {
            COL_REJ_SOURCE_FILE: source_file,
            COL_REJ_LINE: int(df.at[i, LINE_COLUMN]),
            COL_REJ_REASON: reason_text.at[i],
            COL_REJ_RAW: _safe_raw_text(original.loc[i].tolist()),
        }
        for i in df.index[~is_valid]
    ]
    return valid, _rejected_frame(rejected_records)


# ----------------------------------------------------------------------
# One file: read + validate
# ----------------------------------------------------------------------
def load_events_file(path):
    """
    Read and validate one events CSV.

    Returns (valid_df, rejected_df, rows_read).
    """
    path = Path(path)
    raw_df, malformed_df = read_raw_events(path)
    valid_df, rejected_df = validate_events(raw_df, source_file=path.name)

    parts = [part for part in (malformed_df, rejected_df) if not part.empty]
    if parts:
        rejected_all = (pd.concat(parts, ignore_index=True)
                        .sort_values(COL_REJ_LINE, kind="stable")
                        .reset_index(drop=True))
    else:
        rejected_all = _rejected_frame([])

    rows_read = len(raw_df) + len(malformed_df)
    return valid_df, rejected_all, rows_read


# ----------------------------------------------------------------------
# Many files: merge
# ----------------------------------------------------------------------
def build_unified(paths=None):
    """
    Load every existing file in `paths`, merge, sort by time, number the events.

    Returns (unified_df, rejected_df, report).
    Missing files are skipped (and reported); if NO file exists, or a file has
    the wrong columns, an error is raised instead of producing a misleading
    dataset.
    """
    if paths is None:
        paths = [SYNTHETIC_EVENTS_PATH, LOCAL_EVENTS_PATH]

    report = LoadReport()
    valid_parts = []
    rejected_parts = []
    seen = set()

    for item in paths:
        path = Path(item)
        resolved = path.resolve()
        if resolved in seen:
            report.files_skipped_same_path.append(path.name)
            continue
        seen.add(resolved)

        if not path.exists():
            report.files_missing.append(str(path))
            continue

        valid_df, rejected_df, rows_read = load_events_file(path)
        report.files_loaded.append(path.name)
        report.per_file[path.name] = {
            "read": rows_read, "valid": len(valid_df), "rejected": len(rejected_df)
        }
        report.rows_read += rows_read
        if not valid_df.empty:
            valid_parts.append(valid_df)
        if not rejected_df.empty:
            rejected_parts.append(rejected_df)

    if not report.files_loaded:
        raise FileNotFoundError(
            "None of the input files exist: " + ", ".join(report.files_missing)
            + ". Generate data first, for example: python -m cybershield.synthetic"
        )

    if valid_parts:
        unified = pd.concat(valid_parts, ignore_index=True)
        # Timestamps share one fixed text format, so a STABLE sort on the text
        # is a time sort, and rows with the same second keep their file order.
        unified = unified.sort_values(COL_TIMESTAMP, kind="stable").reset_index(drop=True)
    else:
        unified = _empty_valid()
    unified.insert(0, COL_EVENT_ID, range(1, len(unified) + 1))

    rejected = (pd.concat(rejected_parts, ignore_index=True)
                if rejected_parts else _rejected_frame([]))

    report.rows_valid = len(unified)
    report.rows_rejected = len(rejected)
    report.duplicate_rows_kept = int(unified.duplicated(subset=EVENT_COLUMNS).sum())
    report.valid_by_source_type = (
        unified[COL_SOURCE_TYPE].value_counts().to_dict() if len(unified) else {}
    )
    for reason_text in rejected[COL_REJ_REASON]:
        for reason in reason_text.split("; "):
            report.rejected_by_reason[reason] = report.rejected_by_reason.get(reason, 0) + 1

    return unified[UNIFIED_COLUMNS], rejected, report


# ----------------------------------------------------------------------
# Saving
# ----------------------------------------------------------------------
def _write_csv_atomically(df: pd.DataFrame, path) -> Path:
    """Write to a temporary file, then rename, so readers never see half a file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + ".tmp")
    df.to_csv(temp_path, index=False)
    temp_path.replace(path)
    return path


def save_outputs(unified, rejected,
                 unified_path=UNIFIED_EVENTS_PATH,
                 rejected_path=REJECTED_RECORDS_PATH):
    """
    Write unified_events.csv and rejected_records.csv.

    The rejected file is written EVERY time (header only when empty), so an
    old file from a previous run can never be mistaken for current results.
    """
    unified_out = _write_csv_atomically(unified, unified_path)
    rejected_out = _write_csv_atomically(rejected, rejected_path)
    return unified_out, rejected_out


# ----------------------------------------------------------------------
# Command-line interface
# ----------------------------------------------------------------------
def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        description="Validate and merge CyberShield event CSV files."
    )
    parser.add_argument("--synthetic", default=str(SYNTHETIC_EVENTS_PATH),
                        help="synthetic events CSV")
    parser.add_argument("--local", default=str(LOCAL_EVENTS_PATH),
                        help="local-lab events CSV written by app.py")
    parser.add_argument("--output", default=str(UNIFIED_EVENTS_PATH),
                        help="unified events CSV to write")
    parser.add_argument("--rejected-output", default=str(REJECTED_RECORDS_PATH),
                        help="rejected-records CSV to write")
    args = parser.parse_args(argv)

    try:
        unified, rejected, report = build_unified([args.synthetic, args.local])
        unified_out, rejected_out = save_outputs(
            unified, rejected, args.output, args.rejected_output
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        sys.exit(f"ERROR: {exc}")

    for line in report.summary_lines():
        print(line)
    print()
    print(f"Unified events written to : {unified_out}")
    print(f"Rejected records written to: {rejected_out}")
    if len(unified):
        print(f"Time span (UTC): {unified[COL_TIMESTAMP].iloc[0]}  to  "
              f"{unified[COL_TIMESTAMP].iloc[-1]}")
        print()
        print("First 5 unified rows:")
        print(unified.head(5).to_string(index=False))


if __name__ == "__main__":
    main()