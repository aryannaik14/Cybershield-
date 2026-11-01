"""
tests/test_app.py
-----------------
Automated tests for app.py (the localhost demo login application).
They use Flask's built-in test client: no real server is started and no
network is used. Events go to a temporary CSV, never to data/raw/.
"""

import csv
import re

import pytest
from werkzeug.security import generate_password_hash as real_generate_hash

import app as app_module
from app import DEMO_CREDENTIALS, create_app, normalise_username
from cybershield.schema import EVENT_COLUMNS

ALICE_PASSWORD = DEMO_CREDENTIALS["alice_demo"]


@pytest.fixture(autouse=True)
def fast_password_hashing(monkeypatch):
    """Use a cheap hash cost in tests so they run in seconds (real code: 600k rounds)."""
    monkeypatch.setattr(
        app_module, "generate_password_hash",
        lambda password, method=None: real_generate_hash(password, method="pbkdf2:sha256:1000"),
    )


@pytest.fixture
def events_file(tmp_path):
    return tmp_path / "events.csv"


@pytest.fixture
def client(events_file):
    return create_app(events_path=events_file).test_client()


def csrf_token(client):
    html = client.get("/").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(client, username, password, token=None, headers=None):
    return client.post("/login", headers=headers or {}, data={
        "username": username, "password": password,
        "csrf_token": csrf_token(client) if token is None else token,
    })


def logged_rows(path):
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


# ------------------------------------------------------------ logging -------
def test_wrong_password_returns_401_and_logs_a_failure(client, events_file):
    assert login(client, "alice_demo", "wrong").status_code == 401
    row = logged_rows(events_file)[0]
    assert (row["username"], row["outcome"]) == ("alice_demo", "failure")
    assert (row["source_type"], row["environment"]) == ("local_lab", "localhost_lab")
    assert row["event_type"] == "login_attempt"


def test_correct_password_returns_200_and_logs_a_success(client, events_file):
    assert login(client, "alice_demo", ALICE_PASSWORD).status_code == 200
    assert logged_rows(events_file)[0]["outcome"] == "success"


def test_csv_has_the_expected_header(client, events_file):
    login(client, "alice_demo", "x")
    with open(events_file, newline="", encoding="utf-8") as handle:
        assert next(csv.reader(handle)) == EVENT_COLUMNS


def test_timestamps_are_utc(client, events_file):
    login(client, "alice_demo", "x")
    assert logged_rows(events_file)[0]["timestamp_utc"].endswith("+00:00")


def test_passwords_are_never_written_anywhere(client, events_file):
    login(client, "alice_demo", "SuperSecretWrongPassword")
    login(client, "alice_demo", ALICE_PASSWORD)
    text = events_file.read_text(encoding="utf-8")
    assert "SuperSecretWrongPassword" not in text
    assert ALICE_PASSWORD not in text


def test_username_is_trimmed_and_lowercased(client, events_file):
    assert login(client, "  ALICE_DEMO ", ALICE_PASSWORD).status_code == 200
    assert logged_rows(events_file)[0]["username"] == "alice_demo"


# --------------------------------------------------- never trust headers -----
def test_forwarded_ip_headers_are_ignored(client, events_file):
    login(client, "alice_demo", "x", headers={"X-Forwarded-For": "8.8.8.8",
                                              "X-Real-IP": "9.9.9.9",
                                              "Forwarded": "for=7.7.7.7"})
    assert logged_rows(events_file)[0]["source_ip"] == "127.0.0.1"


# --------------------------------------------------------- input checks -----
def test_formula_injection_username_is_never_written(client, events_file):
    assert login(client, "=cmd|' /C calc'!A0", "x").status_code == 401
    row = logged_rows(events_file)[0]
    assert row["username"] == "invalid_username"
    assert "=" not in events_file.read_text(encoding="utf-8").split("\n", 1)[1]


def test_unknown_user_is_logged_and_gets_the_same_generic_message(client, events_file):
    unknown = login(client, "root", "x")
    known = login(client, "alice_demo", "x")
    assert unknown.status_code == known.status_code == 401
    assert b"Invalid username or password." in unknown.data
    assert b"Invalid username or password." in known.data
    assert logged_rows(events_file)[0]["username"] == "root"


@pytest.mark.parametrize("password", ["", "p" * 500])
def test_empty_or_oversized_password_is_a_failure(client, events_file, password):
    assert login(client, "alice_demo", password).status_code == 401
    assert logged_rows(events_file)[0]["outcome"] == "failure"


def test_oversized_request_body_is_refused(client):
    token = csrf_token(client)
    response = client.post("/login", data={"username": "a", "password": "x" * 9000,
                                           "csrf_token": token})
    assert response.status_code == 413


@pytest.mark.parametrize("raw, expected", [
    ("Alice_Demo ", "alice_demo"), ("a", "a"), ("", None), ("=x", None),
    ("-x", None), ("a b", None), ("a" * 33, None), ("a" * 32, "a" * 32),
])
def test_normalise_username(raw, expected):
    assert normalise_username(raw) == expected


# -------------------------------------------------------------- CSRF --------
def test_missing_or_wrong_csrf_token_is_refused_and_not_logged(client, events_file):
    client.get("/")
    missing = client.post("/login", data={"username": "alice_demo", "password": "x"})
    wrong = login(client, "alice_demo", "x", token="not-the-token")
    assert missing.status_code == wrong.status_code == 400
    assert logged_rows(events_file) == []


# ---------------------------------------------------------- rate limit ------
def test_rate_limit_returns_429_and_does_not_log_the_extra_requests(events_file):
    client = create_app(events_path=events_file, rate_limit_max=3,
                        rate_limit_window=60).test_client()
    token = csrf_token(client)
    codes = [login(client, "alice_demo", "x", token=token).status_code for _ in range(5)]
    assert codes == [401, 401, 401, 429, 429]
    assert len(logged_rows(events_file)) == 3
    assert int(login(client, "alice_demo", "x", token=token).headers["Retry-After"]) >= 1


# ------------------------------------------------ local-only guards ---------
def test_non_local_host_header_is_refused(client):
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400


def test_non_loopback_peer_is_refused(client):
    assert client.get("/", environ_base={"REMOTE_ADDR": "192.168.1.50"}).status_code == 403


def test_security_headers_are_present(client):
    headers = client.get("/").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert headers["Cache-Control"] == "no-store"


def test_app_is_hard_wired_to_loopback():
    assert app_module.HOST == "127.0.0.1"


# --------------------------------------------------- the log file itself ----
def test_existing_file_with_wrong_header_is_refused(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("a,b,c\n1,2,3\n")
    with pytest.raises(RuntimeError):
        create_app(events_path=bad)


def test_restarting_the_app_keeps_old_events_and_one_header(events_file):
    create_app(events_path=events_file).test_client()
    client = create_app(events_path=events_file).test_client()
    login(client, "alice_demo", "x")
    create_app(events_path=events_file)
    assert events_file.read_text(encoding="utf-8").count("timestamp_utc,source_ip") == 1
    assert len(logged_rows(events_file)) == 1