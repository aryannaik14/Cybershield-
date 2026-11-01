# CyberShield sample data

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
