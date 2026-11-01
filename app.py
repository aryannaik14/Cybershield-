"""
app.py
------
CyberShield DEMO login application (local lab only).

What it is
    A tiny Flask web app with ONE login form. Every login attempt, success
    or failure, is appended to data/raw/local_events.csv using the same
    columns as the synthetic data, labelled source_type="local_lab".

What it is NOT
    A real authentication system. It has no sessions, no user database and
    no real accounts. It exists only to produce honest log events for the
    detector to analyse.

Safety design (each point is explained in the chat walkthrough)
    * Binds to 127.0.0.1 only. The address is a constant, not an option.
    * Debug mode is off (Flask's debugger can run code in the browser).
    * Passwords are never stored, logged or written to the CSV.
    * The source IP is request.remote_addr (the real network connection).
      X-Forwarded-For and similar headers are IGNORED, because any client
      can forge them.
    * Usernames are validated before they are written to the CSV, which
      blocks CSV/formula injection and oversized values.
    * A small in-memory rate limiter caps login POSTs per minute.
    * A CSRF token stops other web pages from submitting the form for you.
    * Requests whose Host header is not 127.0.0.1 or localhost are refused.

Run from the project root:
    python app.py
Then open http://127.0.0.1:5000 in your browser.
"""

from __future__ import annotations

import argparse
import csv
import hmac
import ipaddress
import re
import secrets
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, make_response, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from cybershield.schema import (
    ENV_LOCALHOST_LAB,
    EVENT_COLUMNS,
    EVENT_TYPE_LOGIN,
    LOCAL_EVENTS_PATH,
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    SOURCE_LOCAL_LAB,
)

# ----------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------
HOST = "127.0.0.1"          # loopback only. Never change this to 0.0.0.0.
DEFAULT_PORT = 5000

# DEMO-ONLY credentials. They protect nothing and exist only so you have an
# account to test against. They are hashed when the app starts.
DEMO_CREDENTIALS = {
    "alice_demo": "DemoOnly-Alice-2026",
    "admin_demo": "DemoOnly-Admin-2026",
}

# Username rules: 1 to 32 characters, must start with a letter or digit,
# then letters, digits, underscore, dot or hyphen. Starting with a letter or
# digit means a value can never begin with = + - @ (spreadsheet formula
# characters).
USERNAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.-]{0,31}")
INVALID_USERNAME_LABEL = "invalid_username"   # logged when the format is bad

MAX_PASSWORD_LENGTH = 128                     # longer inputs are rejected unchecked
MAX_REQUEST_BYTES = 4096                      # whole request body limit

RATE_LIMIT_MAX_REQUESTS = 20                  # login POSTs allowed ...
RATE_LIMIT_WINDOW_SECONDS = 60                # ... per this many seconds

ALLOWED_HOSTNAMES = {"127.0.0.1", "localhost"}


# ----------------------------------------------------------------------
# Page template (autoescaping is ON for render_template_string, so values
# like usernames can never inject HTML)
# ----------------------------------------------------------------------
PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CyberShield Demo Login</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #f4f5f7; margin: 0; }
    main { max-width: 380px; margin: 48px auto; padding: 0 16px; }
    .banner { background: #fff3cd; border: 1px solid #e0c36a; padding: 8px 12px;
              border-radius: 6px; font-size: 14px; }
    h1 { font-size: 22px; }
    form { background: #fff; padding: 16px; border-radius: 8px;
           border: 1px solid #d5d8dc; }
    label { display: block; margin-bottom: 12px; font-size: 14px; }
    input[type=text], input[type=password] { display: block; width: 100%;
           box-sizing: border-box; padding: 8px; margin-top: 4px; font-size: 15px; }
    button { padding: 8px 18px; font-size: 15px; cursor: pointer; }
    .msg { padding: 10px 12px; border-radius: 6px; font-size: 14px; }
    .ok { background: #e3f6e8; border: 1px solid #8fd19e; }
    .error { background: #fde8e8; border: 1px solid #e29a9a; }
    small { color: #555; display: block; margin-top: 16px; }
  </style>
</head>
<body>
<main>
  <p class="banner">DEMO ONLY: CyberShield local lab (127.0.0.1). Not a real login system.</p>
  <h1>Demo Login</h1>
  {% if message %}
    <p class="msg {{ kind }}" role="alert">{{ message }}</p>
  {% endif %}
  {% if show_form %}
  <form method="post" action="/login" autocomplete="off">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <label>Username
      <input type="text" name="username" maxlength="32" required>
    </label>
    <label>Password
      <input type="password" name="password" maxlength="128" required autocomplete="off">
    </label>
    <button type="submit">Sign in</button>
  </form>
  {% else %}
    <p><a href="/">Back to the login form</a></p>
  {% endif %}
  <small>Each attempt is recorded (time, IP, username, outcome) in a local CSV file.
         Passwords are never stored or logged.</small>
</main>
</body>
</html>
"""


# ----------------------------------------------------------------------
# Helper class 1: CSV event logger
# ----------------------------------------------------------------------
class EventLogger:
    """Appends one authentication event per call to a CSV file (thread-safe)."""

    def __init__(self, path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._prepare_file()

    def _prepare_file(self) -> None:
        """Create the file with a header, or check an existing header."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.stat().st_size > 0:
            # utf-8-sig quietly removes the BOM that Excel sometimes adds.
            with self.path.open("r", newline="", encoding="utf-8-sig") as f:
                header = next(csv.reader(f), [])
            if header != EVENT_COLUMNS:
                raise RuntimeError(
                    f"{self.path} exists but its header is not the expected one.\n"
                    f"  expected: {EVENT_COLUMNS}\n"
                    f"  found   : {header}\n"
                    "Move or delete that file and start the app again."
                )
        else:
            with self.path.open("w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(EVENT_COLUMNS)

    def record(self, source_ip: str, username: str, outcome: str) -> None:
        """Append one event. There is deliberately no password parameter."""
        row = [
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            source_ip,
            username,
            EVENT_TYPE_LOGIN,
            outcome,
            SOURCE_LOCAL_LAB,
            ENV_LOCALHOST_LAB,
        ]
        with self._lock:
            with self.path.open("a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(row)


# ----------------------------------------------------------------------
# Helper class 2: sliding-window rate limiter
# ----------------------------------------------------------------------
class RateLimiter:
    """
    Allows at most `max_requests` per `window_seconds` for each key.

    It remembers the time of each recent request in a deque (a list that is
    cheap to remove from at the front) and forgets entries older than the
    window. Refused requests are not remembered, so memory stays small.
    """

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        if max_requests < 1 or window_seconds <= 0:
            raise ValueError("max_requests must be >= 1 and window_seconds > 0")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        """Return (allowed, seconds_to_wait)."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] >= self.window_seconds:
                hits.popleft()
            if len(hits) >= self.max_requests:
                wait = int(self.window_seconds - (now - hits[0])) + 1
                return False, wait
            hits.append(now)
            return True, 0


# ----------------------------------------------------------------------
# Small pure helpers
# ----------------------------------------------------------------------
def normalise_username(raw: str) -> str | None:
    """Trim, lowercase and validate. Returns None if the format is not allowed."""
    candidate = raw.strip().lower()
    if USERNAME_PATTERN.fullmatch(candidate):
        return candidate
    return None


# ----------------------------------------------------------------------
# Application factory
# ----------------------------------------------------------------------
def create_app(
    events_path=LOCAL_EVENTS_PATH,
    rate_limit_max: int = RATE_LIMIT_MAX_REQUESTS,
    rate_limit_window: float = RATE_LIMIT_WINDOW_SECONDS,
) -> Flask:
    """
    Build the Flask app. A "factory" function lets our unit tests create a
    fresh app that writes to a temporary file instead of the real log.
    """
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secrets.token_hex(32),      # new random key at every start
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES,
    )

    logger = EventLogger(events_path)
    limiter = RateLimiter(rate_limit_max, rate_limit_window)

    # Hash the demo passwords once at start-up. pbkdf2 is used because it
    # works on every Python build. The dummy hash lets us do the same amount
    # of work for unknown usernames, so response time does not reveal which
    # usernames exist.
    demo_hashes = {
        name: generate_password_hash(pw, method="pbkdf2:sha256")
        for name, pw in DEMO_CREDENTIALS.items()
    }
    dummy_hash = generate_password_hash(secrets.token_hex(16), method="pbkdf2:sha256")

    def credentials_valid(username: str, password: str) -> bool:
        stored = demo_hashes.get(username)
        password_ok = check_password_hash(stored or dummy_hash, password)
        return stored is not None and password_ok

    def page(message: str = "", kind: str = "error", show_form: bool = True):
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return render_template_string(
            PAGE_TEMPLATE,
            message=message,
            kind=kind,
            show_form=show_form,
            csrf_token=session["csrf_token"],
        )

    def csrf_ok() -> bool:
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        return bool(expected) and hmac.compare_digest(expected, supplied)

    # ---- guards that run before every request -------------------------
    @app.before_request
    def only_local_requests():
        """Defence in depth: refuse anything that is not clearly local."""
        hostname = request.host.partition(":")[0].lower()
        if hostname not in ALLOWED_HOSTNAMES:
            abort(400)
        try:
            peer_ok = ipaddress.ip_address(request.remote_addr or "").is_loopback
        except ValueError:
            peer_ok = False
        if not peer_ok:
            abort(403)

    @app.after_request
    def add_security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    # ---- the one real route -------------------------------------------
    @app.route("/", methods=["GET"])
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return page()

        # The IP of the real network connection. Headers such as
        # X-Forwarded-For are NOT consulted: a client can put anything there.
        source_ip = request.remote_addr

        allowed, wait = limiter.allow(source_ip)
        if not allowed:
            app.logger.warning("Rate limit reached; request refused (not logged as an event).")
            response = make_response(
                page("Too many attempts. Please wait and try again.", show_form=False), 429
            )
            response.headers["Retry-After"] = str(wait)
            return response

        if not csrf_ok():
            return page("This form expired or is invalid. Reload the page and try again.",
                        show_form=False), 400

        username = normalise_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        if username is None:
            logged_username = INVALID_USERNAME_LABEL   # never write the raw input
            success = False
        elif not password or len(password) > MAX_PASSWORD_LENGTH:
            logged_username = username
            success = False
        else:
            logged_username = username
            success = credentials_valid(username, password)

        outcome = OUTCOME_SUCCESS if success else OUTCOME_FAILURE
        try:
            logger.record(source_ip, logged_username, outcome)
        except OSError:
            # Fail closed: no event could be written, so report an error
            # rather than pretend the attempt was handled.
            app.logger.error("Could not write the event log.")
            return page("Server error: the event log could not be written.",
                        show_form=False), 500

        if success:
            session["csrf_token"] = secrets.token_urlsafe(32)   # rotate after success
            return page(f"Demo login successful for {logged_username}. "
                        "No real session was created.", kind="ok", show_form=False)
        return page("Invalid username or password."), 401

    return app


# ----------------------------------------------------------------------
# Command-line entry point
# ----------------------------------------------------------------------
def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="CyberShield demo login app (localhost only).")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"port number, 1024-65535 (default {DEFAULT_PORT})")
    parser.add_argument("--events-file", default=str(LOCAL_EVENTS_PATH),
                        help="CSV file that receives the events")
    args = parser.parse_args(argv)

    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535")

    try:
        app = create_app(events_path=args.events_file)
    except RuntimeError as exc:
        sys.exit(f"ERROR: {exc}")

    print("=" * 64)
    print(" CyberShield DEMO login app  (local lab, not a real system)")
    print(f" Open in your browser : http://{HOST}:{args.port}")
    print(f" Events are written to: {args.events_file}")
    print(" Demo usernames       : " + ", ".join(DEMO_CREDENTIALS))
    print(" Demo passwords       : see DEMO_CREDENTIALS near the top of app.py")
    print(" Stop the app         : press Ctrl+C")
    print("=" * 64)

    app.run(host=HOST, port=args.port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()