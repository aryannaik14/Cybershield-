"""
cybershield/schema.py
---------------------
Single source of truth for column names, allowed values and file paths.

Every other module imports from here, so a column name is spelled in
exactly one place.
"""

from pathlib import Path

# ----------------------------------------------------------------------
# 1. Event (authentication log) columns
# ----------------------------------------------------------------------
COL_TIMESTAMP = "timestamp_utc"
COL_SOURCE_IP = "source_ip"
COL_USERNAME = "username"
COL_EVENT_TYPE = "event_type"
COL_OUTCOME = "outcome"
COL_SOURCE_TYPE = "source_type"
COL_ENVIRONMENT = "environment"

# The order of columns in every RAW events CSV file
# (synthetic_events.csv and local_events.csv).
EVENT_COLUMNS = [
    COL_TIMESTAMP,
    COL_SOURCE_IP,
    COL_USERNAME,
    COL_EVENT_TYPE,
    COL_OUTCOME,
    COL_SOURCE_TYPE,
    COL_ENVIRONMENT,
]

# The unified file adds one extra column: a number that identifies each
# event. Power BI uses it to link alerts to their supporting evidence.
COL_EVENT_ID = "event_id"
UNIFIED_COLUMNS = [COL_EVENT_ID] + EVENT_COLUMNS

# ----------------------------------------------------------------------
# 2. Allowed values for the categorical columns
# ----------------------------------------------------------------------
EVENT_TYPE_LOGIN = "login_attempt"
VALID_EVENT_TYPES = {EVENT_TYPE_LOGIN}

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
VALID_OUTCOMES = {OUTCOME_SUCCESS, OUTCOME_FAILURE}

# source_type says WHERE the evidence came from, so simulated data is
# never confused with logs from the real (local) application.
SOURCE_SYNTHETIC = "synthetic"
SOURCE_LOCAL_LAB = "local_lab"
VALID_SOURCE_TYPES = {SOURCE_SYNTHETIC, SOURCE_LOCAL_LAB}

ENV_SIMULATION = "simulation"
ENV_LOCALHOST_LAB = "localhost_lab"
VALID_ENVIRONMENTS = {ENV_SIMULATION, ENV_LOCALHOST_LAB}

# Each source_type belongs with exactly one environment. A row that mixes
# them (for example synthetic + localhost_lab) is contradictory, so the
# loader rejects it.
SOURCE_ENV_PAIRS = {
    SOURCE_SYNTHETIC: ENV_SIMULATION,
    SOURCE_LOCAL_LAB: ENV_LOCALHOST_LAB,
}

# ----------------------------------------------------------------------
# 3. Alert columns (written by the detector, read by Power BI)
# ----------------------------------------------------------------------
COL_ALERT_ID = "alert_id"
COL_ALERT_TIME = "alert_time_utc"
COL_ATTEMPT_COUNT = "attempt_count"
COL_WINDOW_START = "window_start_utc"
COL_WINDOW_END = "window_end_utc"
COL_WINDOW_MINUTES = "window_minutes"
COL_THRESHOLD = "threshold"
COL_SEVERITY = "severity"
COL_SUCCESS_AFTER = "success_after_failures"
COL_ALERT_TYPE = "alert_type"

ALERT_COLUMNS = [
    COL_ALERT_ID,
    COL_ALERT_TIME,
    COL_SOURCE_IP,
    COL_USERNAME,
    COL_ATTEMPT_COUNT,
    COL_WINDOW_START,
    COL_WINDOW_END,
    COL_WINDOW_MINUTES,
    COL_THRESHOLD,
    COL_SEVERITY,
    COL_SUCCESS_AFTER,
    COL_ALERT_TYPE,
    COL_SOURCE_TYPE,
    COL_ENVIRONMENT,
]

ALERT_TYPE_BRUTE_FORCE = "brute_force_repeated_failures"

# Severity levels, lowest to highest.
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_ORDER = [SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH]

# Values of the success_after_failures column.
FLAG_YES = "yes"
FLAG_NO = "no"

# The detector will also write a small "bridge" file listing which events
# support which alert (one row per alert + event pair). It is used on the
# Power BI investigation page.
EVIDENCE_COLUMNS = [COL_ALERT_ID, COL_EVENT_ID]

# ----------------------------------------------------------------------
# 4. Rejected-record columns (written by the loader for audit)
# ----------------------------------------------------------------------
COL_REJ_SOURCE_FILE = "source_file"
COL_REJ_LINE = "line_number"
COL_REJ_REASON = "reject_reason"
COL_REJ_RAW = "raw_record"

REJECTED_COLUMNS = [
    COL_REJ_SOURCE_FILE,
    COL_REJ_LINE,
    COL_REJ_REASON,
    COL_REJ_RAW,
]

# ----------------------------------------------------------------------
# 5. File locations (always relative to the project root, so scripts
#    work no matter which folder you run them from)
# ----------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
SAMPLE_DIR = DATA_DIR / "sample"

SYNTHETIC_EVENTS_PATH = RAW_DIR / "synthetic_events.csv"
LOCAL_EVENTS_PATH = RAW_DIR / "local_events.csv"
UNIFIED_EVENTS_PATH = PROCESSED_DIR / "unified_events.csv"
ALERTS_PATH = PROCESSED_DIR / "alerts.csv"
ALERT_EVIDENCE_PATH = PROCESSED_DIR / "alert_evidence.csv"
REJECTED_RECORDS_PATH = PROCESSED_DIR / "rejected_records.csv"