"""
cybershield/synthetic.py
------------------------
Generates SYNTHETIC (fake) authentication events for the CyberShield project.

Everything produced here is simulated:
  * usernames end in "_demo" and belong to nobody real
  * IP addresses come from reserved documentation ranges
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
  * no passwords exist anywhere in the data
  * every row is labelled source_type="synthetic", environment="simulation"

Run from the project root:
    python -m cybershield.synthetic
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from cybershield.schema import (
    COL_ENVIRONMENT,
    COL_EVENT_TYPE,
    COL_OUTCOME,
    COL_SOURCE_IP,
    COL_SOURCE_TYPE,
    COL_TIMESTAMP,
    COL_USERNAME,
    ENV_SIMULATION,
    EVENT_COLUMNS,
    EVENT_TYPE_LOGIN,
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    SOURCE_SYNTHETIC,
    SYNTHETIC_EVENTS_PATH,
)

# ----------------------------------------------------------------------
# Fake users and their usual (documentation-range) IP addresses
# ----------------------------------------------------------------------
DEMO_USERS = {
    "admin_demo": "192.0.2.10",
    "alice_demo": "198.51.100.10",
    "bob_demo": "198.51.100.11",
    "carol_demo": "198.51.100.12",
    "dave_demo": "192.0.2.20",
    "erin_demo": "192.0.2.21",
    "frank_demo": "192.0.2.22",
    "grace_demo": "198.51.100.13",
    "heidi_demo": "198.51.100.14",
    "ivan_demo": "192.0.2.23",
}

# Sometimes a user logs in from a different place (mobile, travel, ...).
ALTERNATE_IP_POOL = [f"192.0.2.{n}" for n in range(100, 110)]
ALTERNATE_IP_PROBABILITY = 0.15

# Working hours are simulated as 04:00 to 14:00 UTC each day.
WORK_START_HOUR_UTC = 4
WORK_WINDOW_MINUTES = 10 * 60
MIN_SESSIONS_PER_DAY = 2
MAX_SESSIONS_PER_DAY = 5  # inclusive

# Chance that a login session starts with typing mistakes (1 to 3 failures).
MISTAKE_PROBABILITY = 0.10

# What each built-in attack scenario is designed to show. These are the
# DESIGN INTENTS under the default rule (5 failures in 5 minutes per
# source_ip + username), not measured results. The detector's real output
# is what counts, and we will compare the two later.
SCENARIO_NOTES = [
    "1. 203.0.113.45  -> admin_demo : 14 fast failures           -> EXPECT ALERT (clear brute force)",
    "2. 198.51.100.77 -> bob_demo   : 8 failures, then a success -> EXPECT ALERT (possible compromise)",
    "3. 203.0.113.88  -> alice_demo : exactly 5 failures         -> EXPECT ALERT (boundary case)",
    "4. 203.0.113.99  -> carol_demo : 4 failures                  -> EXPECT NO ALERT (just under threshold)",
    "5. 203.0.113.120 -> dave_demo  : 6 failures spread out       -> EXPECT NO ALERT (slow-and-low evasion)",
    "6. 203.0.113.150 -> 10 users   : 2 failures each (spraying)  -> EXPECT NO ALERT (rule limitation)",
    "7. 203.0.113.45  -> admin_demo : 9 failures on a later day   -> EXPECT ALERT (repeat offender)",
]


# ----------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------
def _row(ts: datetime, ip: str, username: str, outcome: str) -> dict:
    """Build one event record. ts must be timezone-aware (UTC)."""
    return {
        COL_TIMESTAMP: ts.isoformat(timespec="seconds"),
        COL_SOURCE_IP: ip,
        COL_USERNAME: username,
        COL_EVENT_TYPE: EVENT_TYPE_LOGIN,
        COL_OUTCOME: outcome,
        COL_SOURCE_TYPE: SOURCE_SYNTHETIC,
        COL_ENVIRONMENT: ENV_SIMULATION,
    }


def _login_session(rng, start: datetime, ip: str, username: str) -> list[dict]:
    """One normal login: sometimes a few typos first, then a success."""
    rows = []
    n_mistakes = 0
    if rng.random() < MISTAKE_PROBABILITY:
        n_mistakes = int(rng.choice([1, 2, 3], p=[0.6, 0.3, 0.1]))

    t = start
    for _ in range(n_mistakes):
        rows.append(_row(t, ip, username, OUTCOME_FAILURE))
        t = t + timedelta(seconds=int(rng.integers(8, 41)))
    rows.append(_row(t, ip, username, OUTCOME_SUCCESS))
    return rows


def _failure_run(rng, start, ip, username, count, min_gap, max_gap):
    """
    Create `count` failed logins, each min_gap..max_gap seconds apart.
    Returns (rows, time_after_last_gap) so a caller can append a success.
    """
    rows = []
    t = start
    for _ in range(count):
        rows.append(_row(t, ip, username, OUTCOME_FAILURE))
        t = t + timedelta(seconds=int(rng.integers(min_gap, max_gap + 1)))
    return rows, t


def _day(day_starts: list[datetime], index: int) -> datetime:
    """Pick a day by index, clamped so short datasets still work."""
    return day_starts[min(index, len(day_starts) - 1)]


# ----------------------------------------------------------------------
# Normal background activity
# ----------------------------------------------------------------------
def _normal_activity(rng, day_starts: list[datetime]) -> list[dict]:
    rows = []
    for day_start in day_starts:
        work_start = day_start + timedelta(hours=WORK_START_HOUR_UTC)
        for username, home_ip in DEMO_USERS.items():
            n_sessions = int(
                rng.integers(MIN_SESSIONS_PER_DAY, MAX_SESSIONS_PER_DAY + 1)
            )
            # Split the working window into equal slots and place one login
            # in the middle half of each slot, so a user's logins are always
            # far apart and never pile up by accident.
            slot_minutes = WORK_WINDOW_MINUTES / n_sessions
            for slot in range(n_sessions):
                offset = (slot + rng.uniform(0.25, 0.75)) * slot_minutes
                session_start = work_start + timedelta(minutes=float(offset))
                if rng.random() < ALTERNATE_IP_PROBABILITY:
                    ip = str(rng.choice(ALTERNATE_IP_POOL))
                else:
                    ip = home_ip
                rows.extend(_login_session(rng, session_start, ip, username))
    return rows


# ----------------------------------------------------------------------
# Controlled attack scenarios (see SCENARIO_NOTES)
# ----------------------------------------------------------------------
def _attack_scenarios(rng, day_starts: list[datetime]) -> list[dict]:
    rows = []

    # 1. Clear brute force: 14 failures, 8-22 s apart (all within ~5 min).
    start = _day(day_starts, 1) + timedelta(hours=2, minutes=10)
    run, _ = _failure_run(rng, start, "203.0.113.45", "admin_demo", 14, 8, 22)
    rows += run

    # 2. Failures followed by a success (possible compromised account).
    start = _day(day_starts, 3) + timedelta(hours=3, minutes=20)
    run, t_after = _failure_run(rng, start, "198.51.100.77", "bob_demo", 8, 15, 30)
    rows += run
    rows.append(_row(t_after, "198.51.100.77", "bob_demo", OUTCOME_SUCCESS))

    # 3. Exactly at the threshold: 5 failures within ~2 minutes.
    start = _day(day_starts, 4) + timedelta(hours=1, minutes=30)
    run, _ = _failure_run(rng, start, "203.0.113.88", "alice_demo", 5, 20, 40)
    rows += run

    # 4. Near miss: only 4 failures (one short of the threshold).
    start = _day(day_starts, 2) + timedelta(hours=15)
    run, _ = _failure_run(rng, start, "203.0.113.99", "carol_demo", 4, 20, 40)
    rows += run

    # 5. Slow-and-low: 6 failures about 2.5 minutes apart. Any five of them
    #    span over 9 minutes, so a 5-minute window never sees five.
    start = _day(day_starts, 3) + timedelta(hours=16)
    run, _ = _failure_run(rng, start, "203.0.113.120", "dave_demo", 6, 140, 160)
    rows += run

    # 6. Password spraying: one IP, every user, 2 failures each. Per
    #    (source_ip, username) no pair reaches 5, so the default rule is blind.
    t = _day(day_starts, 5) + timedelta(hours=18)
    for _ in range(2):
        for username in DEMO_USERS:
            rows.append(_row(t, "203.0.113.150", username, OUTCOME_FAILURE))
            t = t + timedelta(seconds=int(rng.integers(10, 21)))

    # 7. Repeat offender: same attacker IP and account as scenario 1.
    start = _day(day_starts, 5) + timedelta(hours=2, minutes=40)
    run, _ = _failure_run(rng, start, "203.0.113.45", "admin_demo", 9, 10, 25)
    rows += run

    return rows


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
def generate_synthetic_events(
    days: int = 7,
    seed: int = 42,
    first_day: datetime | None = None,
) -> pd.DataFrame:
    """
    Build a DataFrame of synthetic events with the columns in EVENT_COLUMNS.

    days      : number of full UTC days to simulate (1 or more)
    seed      : random seed; same seed + same first_day = identical output
    first_day : UTC midnight of the first simulated day. If None, the data
                covers the `days` full days that ended at today's UTC midnight
                (so no timestamp is in the future).
    """
    if days < 1:
        raise ValueError("days must be at least 1")

    rng = np.random.default_rng(seed)

    if first_day is None:
        today = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        first_day = today - timedelta(days=days)
    elif first_day.tzinfo is None:
        first_day = first_day.replace(tzinfo=timezone.utc)

    day_starts = [first_day + timedelta(days=i) for i in range(days)]

    rows = []
    rows.extend(_normal_activity(rng, day_starts))
    rows.extend(_attack_scenarios(rng, day_starts))

    df = pd.DataFrame(rows, columns=EVENT_COLUMNS)
    # All timestamps share one fixed text format, so sorting the text sorts time.
    df = df.sort_values(COL_TIMESTAMP, kind="stable").reset_index(drop=True)
    return df


def save_events(df: pd.DataFrame, path) -> Path:
    """Write events to CSV, creating the folder if needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)
    return path


# ----------------------------------------------------------------------
# Command-line interface
# ----------------------------------------------------------------------
def _print_summary(df: pd.DataFrame, out_path: Path) -> None:
    print("Synthetic events generated (SYNTHETIC DATA - not real logs)")
    print(f"Saved to : {out_path}")
    print(f"Rows     : {len(df)}")
    print(f"Outcomes : {df[COL_OUTCOME].value_counts().to_dict()}")
    print(f"Time span: {df[COL_TIMESTAMP].min()}  to  {df[COL_TIMESTAMP].max()}")
    print()
    print("Built-in attack scenarios (expected under the default 5-in-5-minutes rule):")
    for note in SCENARIO_NOTES:
        print("  " + note)
    print()
    print("First 5 rows:")
    print(df.head(5).to_string(index=False))


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic authentication events for CyberShield."
    )
    parser.add_argument("--days", type=int, default=7,
                        help="number of UTC days to simulate (default 7)")
    parser.add_argument("--seed", type=int, default=42,
                        help="random seed (default 42)")
    parser.add_argument("--start-date", type=str, default=None,
                        help="first UTC day as YYYY-MM-DD (default: derived from today)")
    parser.add_argument("--output", type=str, default=str(SYNTHETIC_EVENTS_PATH),
                        help="output CSV path")
    args = parser.parse_args(argv)

    if args.days < 1:
        parser.error("--days must be at least 1")

    first_day = None
    if args.start_date:
        try:
            first_day = datetime.strptime(args.start_date, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            parser.error("--start-date must look like 2026-10-01")

    df = generate_synthetic_events(days=args.days, seed=args.seed, first_day=first_day)
    out_path = save_events(df, args.output)
    _print_summary(df, out_path)


if __name__ == "__main__":
    main()