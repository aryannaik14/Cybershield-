"""
make_sample_data.py
-------------------
Creates a small, SAFE-TO-PUBLISH sample dataset in data/sample/ so anyone who
clones the repository can open the CSV files (or load them into Power BI)
without generating anything first.

What goes into data/sample/
    synthetic_events.csv   7 days of synthetic events (fixed seed and dates,
                           so it is identical every time)
    local_events.csv       a short, SCRIPTED session against the real demo
                           app (app.py), run through Flask's test client.
                           Every row was written by app.py itself, but no
                           human typed these attempts. Its timestamps are the
                           moment you run this script.
    unified_events.csv, rejected_records.csv, alerts.csv, alert_evidence.csv
                           the pipeline outputs for those two inputs
    README.md              what the files are

Safety: only synthetic names and documentation-range IPs, plus 127.0.0.1 and
the fake "_demo" accounts. No passwords are written (the app never logs them).

Run from the project root:
    python make_sample_data.py
"""

from __future__ import annotations

import re
import sys

from app import DEMO_CREDENTIALS, create_app
from cybershield.schema import SAMPLE_DIR
from run_pipeline import PipelineOptions, run_pipeline

# The only files this script is allowed to create or overwrite.
OWNED_FILES = [
    "synthetic_events.csv", "local_events.csv", "unified_events.csv",
    "rejected_records.csv", "alerts.csv", "alert_evidence.csv", "README.md",
]

SAMPLE_START_DATE = "2026-10-01"
SAMPLE_SEED = 42
SAMPLE_DAYS = 7

README_TEXT = """# CyberShield sample data

Everything in this folder is safe to publish: it is synthetic or came from the
local demo app with fake `_demo` accounts. No passwords are stored anywhere.

| File | What it is |
|---|---|
| `synthetic_events.csv` | 7 days of SYNTHETIC login events (seed 42, start 2026-10-01). Documentation-range IPs only. |
| `local_events.csv` | A short SCRIPTED session against `app.py` (run by `make_sample_data.py`, not typed by a person). All events come from 127.0.0.1. Timestamps are the day the script was run. |
| `unified_events.csv` | Both inputs validated, merged and numbered (`event_id`). |
| `rejected_records.csv` | Rows that failed validation (header only if none). |
| `alerts.csv` | Brute-force alerts (default rule: 5 failures within 5 minutes per IP + username). |
| `alert_evidence.csv` | Which events support which alert (`alert_id`, `event_id`). |

Regenerate with `python make_sample_data.py`. The live pipeline writes to
`data/processed/` instead, which is not committed to Git.
"""


def _attempt(client, username: str, password: str) -> None:
    """Fetch the login form (for its CSRF token), then submit it."""
    html = client.get("/").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    client.post("/login", data={"username": username, "password": password,
                                "csrf_token": token})


def scripted_local_session(events_path) -> int:
    """Drive the real login app through a short, scripted story. Returns attempts made."""
    client = create_app(events_path=events_path).test_client()
    attempts = 0

    def attempt(username, password):
        nonlocal attempts
        _attempt(client, username, password)
        attempts += 1

    # 1. A normal login.
    attempt("alice_demo", DEMO_CREDENTIALS["alice_demo"])
    # 2. Two mistyped attempts for an account that does not exist (below threshold).
    for n in range(2):
        attempt("root", f"not-a-real-password-{n}")
    # 3. A burst against admin_demo that never succeeds (a low-severity alert).
    for n in range(6):
        attempt("admin_demo", f"not-the-password-{n}")
    # 4. A burst against alice_demo, then the right password (a high-severity alert).
    for n in range(5):
        attempt("alice_demo", f"not-the-password-{n}")
    attempt("alice_demo", DEMO_CREDENTIALS["alice_demo"])
    # 5. One badly formatted username (logged as invalid_username).
    attempt("bad user!", "x")
    return attempts


def main() -> None:
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    # Remove only the files this script owns, so the sample is rebuilt cleanly.
    for name in OWNED_FILES:
        (SAMPLE_DIR / name).unlink(missing_ok=True)

    print(f"Writing sample data to {SAMPLE_DIR}")
    attempts = scripted_local_session(SAMPLE_DIR / "local_events.csv")
    print(f"Scripted local session: {attempts} login attempts sent to the demo app")

    options = PipelineOptions(
        days=SAMPLE_DAYS,
        seed=SAMPLE_SEED,
        start_date=SAMPLE_START_DATE,
        synthetic_path=SAMPLE_DIR / "synthetic_events.csv",
        local_path=SAMPLE_DIR / "local_events.csv",
        unified_path=SAMPLE_DIR / "unified_events.csv",
        rejected_path=SAMPLE_DIR / "rejected_records.csv",
        alerts_path=SAMPLE_DIR / "alerts.csv",
        evidence_path=SAMPLE_DIR / "alert_evidence.csv",
    )
    try:
        run_pipeline(options)
    except (ValueError, FileNotFoundError, OSError) as exc:
        sys.exit(f"ERROR: {exc}")

    (SAMPLE_DIR / "README.md").write_text(README_TEXT, encoding="utf-8")
    print("Wrote README.md")
    print("Done. These files are safe to commit (data/sample/ is not git-ignored).")


if __name__ == "__main__":
    main()