import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, jsonify, make_response, request
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "authx_fixed.db"
COOKIE_NAME = "auth_session"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"
SESSION_MINUTES = 30
MAX_LOGIN_ATTEMPTS = 5
LOCK_MINUTES = 5
RESET_TOKEN_MINUTES = 10

app = Flask(__name__)


# Simple IP limiter for login bursts; account lock is enforced in DB.
LOGIN_IP_WINDOW = {}
IP_WINDOW_SECONDS = 60
IP_MAX_ATTEMPTS = 20


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now_utc():
    return datetime.utcnow()


def now_iso():
    return now_utc().isoformat()


def parse_iso(value):
    if not value:
        return None
    return datetime.fromisoformat(value)


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'USER',
            created_at TEXT NOT NULL,
            failed_login_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            user_agent TEXT,
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            owner_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            resource_id TEXT,
            timestamp TEXT NOT NULL,
            ip_address TEXT,
            details TEXT
        )
        """
    )

    conn.commit()
    conn.close()


def log_action(user_id, action, resource, resource_id=None, details=""):
    conn = get_db()
    conn.execute(
        """
        INSERT INTO audit_logs(user_id, action, resource, resource_id, timestamp, ip_address, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, action, resource, resource_id, now_iso(), request.remote_addr, details),
    )
    conn.commit()
    conn.close()


def password_is_strong(password):
    if len(password) < 10:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True


def generic_invalid_credentials(start_time, status=401):
    elapsed = time.monotonic() - start_time
    min_time = 0.35
    if elapsed < min_time:
        time.sleep(min_time - elapsed)
    return jsonify({"error": "Invalid credentials"}), status


def too_many_attempts_from_ip(ip):
    now_ts = time.time()
    attempts = LOGIN_IP_WINDOW.get(ip, [])
    attempts = [x for x in attempts if now_ts - x <= IP_WINDOW_SECONDS]
    attempts.append(now_ts)
    LOGIN_IP_WINDOW[ip] = attempts
    return len(attempts) > IP_MAX_ATTEMPTS


def create_session(user):
    raw_token = secrets.token_urlsafe(32)
    token_hash = sha256_text(raw_token)

    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    conn.execute(
        """
        INSERT INTO sessions(user_id, token_hash, created_at, expires_at, user_agent, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user["id"],
            token_hash,
            now_iso(),
            (now_utc() + timedelta(minutes=SESSION_MINUTES)).isoformat(),
            request.headers.get("User-Agent", ""),
            request.remote_addr,
        ),
    )
    conn.commit()
    conn.close()

    return raw_token


def get_current_user():
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None

    token_hash = sha256_text(token)
    conn = get_db()
    row = conn.execute(
        """
        SELECT u.*, s.expires_at AS session_expires_at
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
        LIMIT 1
        """,
        (token_hash,),
    ).fetchone()

    if not row:
        conn.close()
        return None

    expires_at = parse_iso(row["session_expires_at"])
    if not expires_at or expires_at <= now_utc():
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        conn.commit()
        conn.close()
        return None

    conn.close()
    return row


@app.errorhandler(Exception)
def handle_unexpected_error(_error):
    return jsonify({"error": "Internal server error"}), 500


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "username, email and password are required"}), 400

    if not password_is_strong(password):
        return (
            jsonify(
                {
                    "error": "Password policy failed",
                    "policy": "Min 10 chars, upper, lower, digit, special",
                }
            ),
            400,
        )

    password_hash = generate_password_hash(password, method="scrypt")

    conn = get_db()
    try:
        cur = conn.execute(
            """
            INSERT INTO users(username, email, password_hash, role, created_at)
            VALUES (?, ?, ?, 'USER', ?)
            """,
            (username, email, password_hash, now_iso()),
        )
        conn.commit()
        user_id = cur.lastrowid
        log_action(user_id, "REGISTER", "auth", str(user_id))
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username or email already exists"}), 409

    conn.close()
    return jsonify({"message": "Account created", "role": "USER"}), 201


@app.post("/login")
def login():
    start_time = time.monotonic()
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    ip_address = request.remote_addr or "unknown"

    if too_many_attempts_from_ip(ip_address):
        return generic_invalid_credentials(start_time, status=429)

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user:
        conn.close()
        log_action(None, "LOGIN_FAILED", "auth", None, "unknown user")
        return generic_invalid_credentials(start_time)

    locked_until = parse_iso(user["locked_until"])
    if locked_until and locked_until > now_utc():
        conn.close()
        log_action(user["id"], "LOGIN_BLOCKED", "auth", str(user["id"]), "account locked")
        return generic_invalid_credentials(start_time)

    if not check_password_hash(user["password_hash"], password):
        attempts = user["failed_login_attempts"] + 1
        new_locked_until = None
        if attempts >= MAX_LOGIN_ATTEMPTS:
            attempts = 0
            new_locked_until = (now_utc() + timedelta(minutes=LOCK_MINUTES)).isoformat()

        conn.execute(
            "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
            (attempts, new_locked_until, user["id"]),
        )
        conn.commit()
        conn.close()

        log_action(user["id"], "LOGIN_FAILED", "auth", str(user["id"]), "bad password")
        return generic_invalid_credentials(start_time)

    conn.execute(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
        (user["id"],),
    )
    conn.commit()
    conn.close()

    session_token = create_session(user)
    log_action(user["id"], "LOGIN_SUCCESS", "auth", str(user["id"]))

    response = make_response(jsonify({"message": "Login successful"}))
    response.set_cookie(
        COOKIE_NAME,
        session_token,
        max_age=SESSION_MINUTES * 60,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="Strict",
    )
    return response


@app.post("/logout")
def logout():
    token = request.cookies.get(COOKIE_NAME)
    if token:
        token_hash = sha256_text(token)
        conn = get_db()
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        conn.commit()
        conn.close()

    response = make_response(jsonify({"message": "Logged out"}))
    response.delete_cookie(COOKIE_NAME)
    return response


@app.get("/me")
def me():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    return jsonify(
        {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        }
    )


@app.post("/forgot-password")
def forgot_password():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if user:
        raw_token = secrets.token_urlsafe(32)
        token_hash = sha256_text(raw_token)
        conn.execute(
            """
            INSERT INTO password_reset_tokens(user_id, token_hash, created_at, expires_at, used)
            VALUES (?, ?, ?, ?, 0)
            """,
            (
                user["id"],
                token_hash,
                now_iso(),
                (now_utc() + timedelta(minutes=RESET_TOKEN_MINUTES)).isoformat(),
            ),
        )
        conn.commit()
        log_action(user["id"], "FORGOT_PASSWORD", "auth", str(user["id"]))

        # For lab visibility we return the token in API response; in production send by email only.
        response_payload = {
            "message": "If the account exists, reset instructions were sent",
            "reset_token_for_lab": raw_token,
            "expires_in_minutes": RESET_TOKEN_MINUTES,
        }
    else:
        response_payload = {
            "message": "If the account exists, reset instructions were sent"
        }

    conn.close()
    return jsonify(response_payload)


@app.post("/reset-password")
def reset_password():
    data = request.get_json(silent=True) or {}
    token = data.get("token") or ""
    new_password = data.get("new_password") or ""

    if not token or not new_password:
        return jsonify({"error": "token and new_password are required"}), 400

    if not password_is_strong(new_password):
        return jsonify({"error": "Password policy failed"}), 400

    token_hash = sha256_text(token)
    conn = get_db()
    token_row = conn.execute(
        """
        SELECT * FROM password_reset_tokens
        WHERE token_hash = ? AND used = 0
        ORDER BY id DESC
        LIMIT 1
        """,
        (token_hash,),
    ).fetchone()

    if not token_row:
        conn.close()
        return jsonify({"error": "Invalid or expired token"}), 400

    expires_at = parse_iso(token_row["expires_at"])
    if not expires_at or expires_at <= now_utc():
        conn.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE id = ?", (token_row["id"],)
        )
        conn.commit()
        conn.close()
        return jsonify({"error": "Invalid or expired token"}), 400

    new_password_hash = generate_password_hash(new_password, method="scrypt")

    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, token_row["user_id"]))
    conn.execute("UPDATE password_reset_tokens SET used = 1 WHERE id = ?", (token_row["id"],))
    conn.commit()
    conn.close()

    log_action(token_row["user_id"], "PASSWORD_RESET", "auth", str(token_row["user_id"]))
    return jsonify({"message": "Password updated"})


@app.post("/tickets")
def create_ticket():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    description = (data.get("description") or "").strip()
    severity = (data.get("severity") or "LOW").strip().upper()

    if not title or not description:
        return jsonify({"error": "title and description are required"}), 400

    if severity not in {"LOW", "MED", "HIGH"}:
        return jsonify({"error": "severity must be LOW, MED or HIGH"}), 400

    conn = get_db()
    cur = conn.execute(
        """
        INSERT INTO tickets(title, description, severity, status, owner_id, created_at, updated_at)
        VALUES (?, ?, ?, 'OPEN', ?, ?, ?)
        """,
        (title, description, severity, user["id"], now_iso(), now_iso()),
    )
    conn.commit()
    ticket_id = cur.lastrowid
    conn.close()

    log_action(user["id"], "CREATE_TICKET", "ticket", str(ticket_id))
    return jsonify({"message": "Ticket created", "ticket_id": ticket_id}), 201


@app.get("/tickets/<int:ticket_id>")
def view_ticket(ticket_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    conn = get_db()
    ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    conn.close()

    if not ticket:
        return jsonify({"error": "Ticket not found"}), 404

    if ticket["owner_id"] != user["id"] and user["role"] != "MANAGER":
        return jsonify({"error": "Forbidden"}), 403

    return jsonify(dict(ticket))


@app.get("/audit")
def audit_entries():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    if user["role"] != "MANAGER":
        return jsonify({"error": "Forbidden"}), 403

    conn = get_db()
    rows = conn.execute(
        "SELECT id, user_id, action, resource, resource_id, timestamp, ip_address, details FROM audit_logs ORDER BY id DESC LIMIT 100"
    ).fetchall()
    conn.close()

    return jsonify([dict(row) for row in rows])


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "mode": "fixed",
            "cookie_secure": COOKIE_SECURE,
            "session_minutes": SESSION_MINUTES,
        }
    )


if __name__ == "__main__":
    os.makedirs(BASE_DIR, exist_ok=True)
    init_db()
    app.run(host="127.0.0.1", port=5001, debug=False)
