"""
cybershield/detector.py
-----------------------
Brute-force detection: repeated FAILED logins in a rolling time window.

The rule (all values configurable)
    Raise an alert when a single (source_ip, username) pair has at least
    `threshold` failed logins within `window_minutes`.
    Defaults: 5 failures within 5 minutes.

How an alert is built (one alert per "episode", not one per failure)
    * Only outcome == "failure" rows are counted. Successes never count.
    * Rows are grouped by source_ip + username + source_type + environment,
      so simulated and real (local-lab) events are never mixed.
    * Inside a group we slide a window over the failures. The alert fires on
      the failure that first brings the window count up to the threshold
      (alert_time_utc).
    * The episode continues as long as every new failure still has at least
      `threshold` failures inside its own window. The first failure that does
      not ends the episode, and exactly one alert is written for it.
    * A failure belongs to at most ONE alert. Later activity can start a new
      alert, but never re-uses failures that were already reported.
    * "Within the window" is inclusive: first and last failure exactly
      window_minutes apart still count together.

Severity (explained in classify_severity)
    low / medium / high from the number of failures, raised to HIGH when a
    successful login from the same IP + username follows (possible
    compromised account).

Run from the project root:
    python -m cybershield.detector
"""

from __future__ import annotations

import argparse
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from cybershield.loader import TIMEZONE_PATTERN
from cybershield.schema import (
    ALERT_COLUMNS,
    ALERT_EVIDENCE_PATH,
    ALERT_TYPE_BRUTE_FORCE,
    ALERTS_PATH,
    COL_ALERT_ID,
    COL_ALERT_TIME,
    COL_ALERT_TYPE,
    COL_ATTEMPT_COUNT,
    COL_ENVIRONMENT,
    COL_EVENT_ID,
    COL_EVENT_TYPE,
    COL_OUTCOME,
    COL_SEVERITY,
    COL_SOURCE_IP,
    COL_SOURCE_TYPE,
    COL_SUCCESS_AFTER,
    COL_THRESHOLD,
    COL_TIMESTAMP,
    COL_USERNAME,
    COL_WINDOW_END,
    COL_WINDOW_MINUTES,
    COL_WINDOW_START,
    EVENT_TYPE_LOGIN,
    EVIDENCE_COLUMNS,
    FLAG_NO,
    FLAG_YES,
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    UNIFIED_EVENTS_PATH,
)

# ----------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 5.0
MAX_WINDOW_MINUTES = 24 * 60          # sanity limit: one day

# Severity: medium at 2x the threshold, high at 3x (e.g. 10 and 15 failures
# when the threshold is 5).
MEDIUM_MULTIPLIER = 2
HIGH_MULTIPLIER = 3

OUTPUT_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S+00:00"

# Names of helper columns that exist only inside this module.
_PARSED = "_parsed_time"
_SECONDS = "_seconds"
_EPOCH = pd.Timestamp("1970-01-01", tz="UTC")

REQUIRED_COLUMNS = [
    COL_TIMESTAMP, COL_SOURCE_IP, COL_USERNAME,
    COL_OUTCOME, COL_SOURCE_TYPE, COL_ENVIRONMENT,
]
GROUP_COLUMNS = [COL_SOURCE_IP, COL_USERNAME, COL_SOURCE_TYPE, COL_ENVIRONMENT]


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class DetectorConfig:
    """Detection settings. Invalid values raise ValueError immediately."""

    threshold: int = DEFAULT_THRESHOLD
    window_minutes: float = DEFAULT_WINDOW_MINUTES

    def __post_init__(self) -> None:
        if isinstance(self.threshold, bool) or not isinstance(self.threshold, int):
            raise ValueError("threshold must be a whole number")
        if self.threshold < 2:
            raise ValueError("threshold must be at least 2 (1 would alert on every failure)")
        try:
            window = float(self.window_minutes)
        except (TypeError, ValueError):
            raise ValueError("window_minutes must be a number") from None
        if not math.isfinite(window) or window <= 0:
            raise ValueError("window_minutes must be greater than 0")
        if window > MAX_WINDOW_MINUTES:
            raise ValueError(f"window_minutes must be at most {MAX_WINDOW_MINUTES}")

    @property
    def window_seconds(self) -> float:
        return float(self.window_minutes) * 60.0


@dataclass
class DetectionResult:
    """What detect_brute_force returns."""

    alerts: pd.DataFrame
    evidence: pd.DataFrame
    config: DetectorConfig
    rows_received: int = 0
    rows_used: int = 0
    rows_skipped: int = 0
    skip_reasons: dict = field(default_factory=dict)
    failures_examined: int = 0
    groups_examined: int = 0


# ----------------------------------------------------------------------
# Step 1: clean the incoming events (defensive; the loader already did this)
# ----------------------------------------------------------------------
def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value != value:     # NaN
        return ""
    return str(value)


def _mark(reason: pd.Series, mask: pd.Series, message: str) -> None:
    """Record `message` for rows in `mask` that have no reason yet."""
    reason.loc[mask & (reason == "")] = message


def prepare_events(events: pd.DataFrame):
    """
    Keep only rows the detector can trust; skip (never crash on) the rest.

    Returns (clean_df, skip_reasons):
      clean_df     : columns event_id, source_ip, username, outcome,
                     source_type, environment, plus two internal time columns
      skip_reasons : {reason text: number of rows}

    A row is skipped when its timestamp is missing/unparseable or has no UTC
    offset, when source_ip or username is empty, when outcome is not
    success/failure, when event_type is present but not login_attempt, when
    source_type/environment is empty, or when event_id is present but not a
    number. If there is no event_id column, ids 1..N are assigned by row order.
    """
    missing = [c for c in REQUIRED_COLUMNS if c not in events.columns]
    if missing:
        raise ValueError(f"events are missing required column(s): {missing}")

    columns = REQUIRED_COLUMNS + ([COL_EVENT_TYPE] if COL_EVENT_TYPE in events.columns else [])
    df = events[columns].copy().reset_index(drop=True)
    for column in columns:
        df[column] = df[column].map(_text).str.strip()
    for column in (COL_USERNAME, COL_OUTCOME, COL_SOURCE_TYPE, COL_ENVIRONMENT):
        df[column] = df[column].str.lower()

    if COL_EVENT_ID in events.columns:
        ids = pd.to_numeric(events[COL_EVENT_ID].reset_index(drop=True), errors="coerce")
    else:
        ids = pd.Series(range(1, len(df) + 1), dtype="float64")

    parsed = pd.to_datetime(df[COL_TIMESTAMP], format="ISO8601", utc=True, errors="coerce")
    has_offset = df[COL_TIMESTAMP].str.contains(TIMEZONE_PATTERN, regex=True)

    reason = pd.Series("", index=df.index, dtype=object)
    _mark(reason, parsed.isna(), "missing or unparseable timestamp")
    _mark(reason, ~has_offset, "timestamp has no UTC offset")
    _mark(reason, df[COL_SOURCE_IP] == "", "missing source_ip")
    _mark(reason, df[COL_USERNAME] == "", "missing username")
    _mark(reason, ~df[COL_OUTCOME].isin([OUTCOME_SUCCESS, OUTCOME_FAILURE]),
          "outcome is not success or failure")
    if COL_EVENT_TYPE in df.columns:
        _mark(reason, df[COL_EVENT_TYPE].str.lower() != EVENT_TYPE_LOGIN,
              "event_type is not login_attempt")
    _mark(reason, (df[COL_SOURCE_TYPE] == "") | (df[COL_ENVIRONMENT] == ""),
          "missing source_type or environment")
    _mark(reason, ids.isna(), "invalid event_id")

    keep = reason == ""
    skip_reasons = reason[~keep].value_counts().to_dict()

    clean = df.loc[keep, [COL_SOURCE_IP, COL_USERNAME, COL_OUTCOME,
                          COL_SOURCE_TYPE, COL_ENVIRONMENT]].copy()
    clean.insert(0, COL_EVENT_ID, ids[keep].astype("int64"))
    clean[_PARSED] = parsed[keep]
    clean[_SECONDS] = (parsed[keep] - _EPOCH) / pd.Timedelta(seconds=1)
    return clean.reset_index(drop=True), skip_reasons


# ----------------------------------------------------------------------
# Step 2: the sliding-window algorithm (pure function, easy to test)
# ----------------------------------------------------------------------
def find_episodes(times, threshold: int, window_seconds: float):
    """
    Find detection episodes in ONE group's failure times.

    times          : failure times in seconds, sorted ascending
    threshold      : failures needed inside one window
    window_seconds : window length (inclusive)

    Returns a list of (start_index, alert_index, end_index):
      start_index : first failure counted in the episode
      alert_index : the failure that first reached the threshold
      end_index   : last failure counted in the episode
    All indexes refer to positions in `times`.
    """
    episodes = []
    left = 0                      # oldest failure still inside the window
    in_episode = False
    start = alert = end = 0

    for i in range(len(times)):
        # Slide the window: drop failures older than window_seconds.
        while times[i] - times[left] > window_seconds:
            left += 1
        count = i - left + 1      # failures currently inside the window

        if in_episode:
            if count >= threshold:
                end = i           # still hot: extend the episode
                continue
            episodes.append((start, alert, end))   # cooled down: close it
            in_episode = False
            left = i              # failures already reported are never re-used
            count = 1

        if count >= threshold:    # threshold reached: open an episode
            in_episode = True
            start, alert, end = left, i, i

    if in_episode:
        episodes.append((start, alert, end))
    return episodes


# ----------------------------------------------------------------------
# Step 3: severity
# ----------------------------------------------------------------------
def classify_severity(attempt_count: int, threshold: int, success_after: bool) -> str:
    """
    high   : a success followed the failures, or failures >= 3 x threshold
    medium : failures >= 2 x threshold
    low    : anything else that reached the threshold
    """
    if success_after or attempt_count >= HIGH_MULTIPLIER * threshold:
        return SEVERITY_HIGH
    if attempt_count >= MEDIUM_MULTIPLIER * threshold:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def _clean_number(value: float):
    """5.0 -> 5 (so the CSV shows 5, not 5.0); 0.5 stays 0.5."""
    return int(value) if float(value).is_integer() else float(value)


# ----------------------------------------------------------------------
# Step 4: put it together
# ----------------------------------------------------------------------
def detect_brute_force(events: pd.DataFrame, config: DetectorConfig | None = None) -> DetectionResult:
    """
    Detect brute-force episodes in an events DataFrame.

    `events` needs the columns timestamp_utc, source_ip, username, outcome,
    source_type, environment (event_type and event_id are used if present).
    Returns a DetectionResult with the alerts and the supporting evidence.
    """
    config = config or DetectorConfig()
    clean, skip_reasons = prepare_events(events)

    failures = clean[clean[COL_OUTCOME] == OUTCOME_FAILURE]
    successes = clean[clean[COL_OUTCOME] == OUTCOME_SUCCESS]

    # Successes per group, sorted by time, for the "success followed" check.
    success_lookup = {}
    for key, group in successes.groupby(GROUP_COLUMNS, sort=False):
        group = group.sort_values([_SECONDS, COL_EVENT_ID], kind="stable")
        success_lookup[key] = (group[_SECONDS].to_numpy(), group[COL_EVENT_ID].to_numpy())

    pending = []                      # one dict per alert, before ids are assigned
    groups_examined = 0
    for key, group in failures.groupby(GROUP_COLUMNS, sort=False):
        groups_examined += 1
        group = group.sort_values([_SECONDS, COL_EVENT_ID], kind="stable")
        seconds = group[_SECONDS].to_numpy()
        event_ids = group[COL_EVENT_ID].to_numpy()
        stamps = group[_PARSED].reset_index(drop=True)

        for start, alert_index, end in find_episodes(
            seconds, config.threshold, config.window_seconds
        ):
            attempt_count = end - start + 1

            # Did the same IP + username log in successfully after the alert
            # fired, no later than one window after the last failure?
            success_ids = np.array([], dtype="int64")
            if key in success_lookup:
                s_seconds, s_ids = success_lookup[key]
                low = np.searchsorted(s_seconds, seconds[alert_index], side="left")
                high = np.searchsorted(s_seconds, seconds[end] + config.window_seconds,
                                       side="right")
                success_ids = s_ids[low:high]
            success_after = len(success_ids) > 0

            pending.append({
                "sort_time": seconds[alert_index],
                COL_ALERT_TIME: stamps[alert_index].strftime(OUTPUT_TIMESTAMP_FORMAT),
                COL_SOURCE_IP: key[0],
                COL_USERNAME: key[1],
                COL_ATTEMPT_COUNT: attempt_count,
                COL_WINDOW_START: stamps[start].strftime(OUTPUT_TIMESTAMP_FORMAT),
                COL_WINDOW_END: stamps[end].strftime(OUTPUT_TIMESTAMP_FORMAT),
                COL_WINDOW_MINUTES: _clean_number(config.window_minutes),
                COL_THRESHOLD: config.threshold,
                COL_SEVERITY: classify_severity(attempt_count, config.threshold, success_after),
                COL_SUCCESS_AFTER: FLAG_YES if success_after else FLAG_NO,
                COL_ALERT_TYPE: ALERT_TYPE_BRUTE_FORCE,
                COL_SOURCE_TYPE: key[2],
                COL_ENVIRONMENT: key[3],
                "evidence_ids": [int(x) for x in event_ids[start:end + 1]]
                                + [int(x) for x in success_ids],
            })

    # Stable, readable ordering and ids: by alert time, then IP, then username.
    pending.sort(key=lambda a: (a["sort_time"], a[COL_SOURCE_IP], a[COL_USERNAME]))
    alert_rows = []
    evidence_rows = []
    for number, alert in enumerate(pending, start=1):
        alert_id = f"ALT-{number:04d}"
        row = {COL_ALERT_ID: alert_id}
        row.update({c: alert[c] for c in ALERT_COLUMNS if c != COL_ALERT_ID})
        alert_rows.append(row)
        evidence_rows.extend({COL_ALERT_ID: alert_id, COL_EVENT_ID: eid}
                             for eid in alert["evidence_ids"])

    return DetectionResult(
        alerts=pd.DataFrame(alert_rows, columns=ALERT_COLUMNS),
        evidence=pd.DataFrame(evidence_rows, columns=EVIDENCE_COLUMNS),
        config=config,
        rows_received=len(events),
        rows_used=len(clean),
        rows_skipped=len(events) - len(clean),
        skip_reasons=skip_reasons,
        failures_examined=len(failures),
        groups_examined=groups_examined,
    )


# ----------------------------------------------------------------------
# Saving and command line
# ----------------------------------------------------------------------
def _write_csv(df: pd.DataFrame, path) -> Path:
    """Write to a temporary file, then rename, so readers never see half a file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + ".tmp")
    df.to_csv(temp_path, index=False)
    temp_path.replace(path)
    return path


def save_detection(result: DetectionResult, alerts_path=ALERTS_PATH,
                   evidence_path=ALERT_EVIDENCE_PATH):
    """Write alerts.csv and alert_evidence.csv (headers only when empty)."""
    return (_write_csv(result.alerts, alerts_path),
            _write_csv(result.evidence, evidence_path))


def _print_summary(result: DetectionResult, alerts_path, evidence_path) -> None:
    cfg = result.config
    print("Brute-force detection (actual results from this run)")
    print(f"  Rule      : >= {cfg.threshold} failures within "
          f"{_clean_number(cfg.window_minutes)} minute(s), per source_ip + username")
    print(f"  Events    : received {result.rows_received}, used {result.rows_used}, "
          f"skipped {result.rows_skipped}")
    for reason, count in sorted(result.skip_reasons.items()):
        print(f"              skipped {count:>4}  {reason}")
    print(f"  Failures examined: {result.failures_examined} "
          f"in {result.groups_examined} (ip, user) groups")
    print(f"  Alerts    : {len(result.alerts)}")
    if len(result.alerts):
        counts = result.alerts[COL_SEVERITY].value_counts().to_dict()
        print(f"  By severity: {counts}")
        print()
        columns = [COL_ALERT_ID, COL_ALERT_TIME, COL_SOURCE_IP, COL_USERNAME,
                   COL_ATTEMPT_COUNT, COL_SEVERITY, COL_SUCCESS_AFTER, COL_SOURCE_TYPE]
        print(result.alerts[columns].to_string(index=False))
    print()
    print(f"Alerts written to  : {alerts_path}")
    print(f"Evidence written to: {evidence_path}")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Detect brute-force login attempts.")
    parser.add_argument("--input", default=str(UNIFIED_EVENTS_PATH),
                        help="unified events CSV (from cybershield.loader)")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help=f"failures needed to alert (default {DEFAULT_THRESHOLD})")
    parser.add_argument("--window-minutes", type=float, default=DEFAULT_WINDOW_MINUTES,
                        help=f"rolling window length (default {DEFAULT_WINDOW_MINUTES:g})")
    parser.add_argument("--alerts-output", default=str(ALERTS_PATH))
    parser.add_argument("--evidence-output", default=str(ALERT_EVIDENCE_PATH))
    args = parser.parse_args(argv)

    try:
        config = DetectorConfig(threshold=args.threshold, window_minutes=args.window_minutes)
        events = pd.read_csv(args.input, dtype=str, keep_default_na=False,
                             encoding="utf-8-sig")
        result = detect_brute_force(events, config)
        alerts_out, evidence_out = save_detection(
            result, args.alerts_output, args.evidence_output
        )
    except FileNotFoundError:
        sys.exit(f"ERROR: {args.input} not found. Run: python -m cybershield.loader")
    except (ValueError, OSError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
        sys.exit(f"ERROR: {exc}")

    _print_summary(result, alerts_out, evidence_out)


if __name__ == "__main__":
    main()