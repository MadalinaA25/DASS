import os
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, jsonify, make_response, request

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "authx_vulnerable.db"

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_plaintext TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'USER',
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            created_at TEXT NOT NULL,
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
            ip_address TEXT
        )
        """
    )

    conn.commit()
    conn.close()


def now_iso():
    return datetime.utcnow().isoformat()


def log_action(user_id, action, resource, resource_id=None):
    conn = get_db()
    conn.execute(
        """
        INSERT INTO audit_logs(user_id, action, resource, resource_id, timestamp, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, action, resource, resource_id, now_iso(), request.remote_addr),
    )
    conn.commit()
    conn.close()


def current_user_from_cookie():
    token = request.cookies.get("auth_token")
    if not token:
        return None

    conn = get_db()
    row = conn.execute(
        """
        SELECT u.*
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ?
        ORDER BY s.id DESC
        LIMIT 1
        """,
        (token,),
    ).fetchone()
    conn.close()

    return row


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "username, email and password are required"}), 400

    conn = get_db()
    try:
        cur = conn.execute(
            """
            INSERT INTO users(username, email, password_plaintext, role, created_at)
            VALUES (?, ?, ?, 'USER', ?)
            """,
            (username, email, password, now_iso()),
        )
        conn.commit()
        user_id = cur.lastrowid
        log_action(user_id, "REGISTER", "auth", str(user_id))
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "username or email already exists"}), 409

    conn.close()
    return jsonify({"message": "Account created", "role": "USER"}), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "User does not exist"}), 404

    if user["password_plaintext"] != password:
        conn.close()
        return jsonify({"error": "Wrong password"}), 401

    token = f"{username}-{int(time.time())}"
    expires_at = (datetime.utcnow() + timedelta(days=30)).isoformat()
    conn.execute(
        """
        INSERT INTO sessions(user_id, token, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (user["id"], token, now_iso(), expires_at),
    )
    conn.commit()
    conn.close()

    log_action(user["id"], "LOGIN_SUCCESS", "auth", str(user["id"]))

    response = make_response(
        jsonify(
            {
                "message": "Login successful",
                "token": token,
                "note": "Cookie is intentionally insecure in v1",
            }
        )
    )
    response.set_cookie("auth_token", token, max_age=30 * 24 * 3600)
    return response


@app.get("/me")
def me():
    user = current_user_from_cookie()
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


@app.post("/logout")
def logout():
    token = request.cookies.get("auth_token")
    if token:
        conn = get_db()
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()

    response = make_response(jsonify({"message": "Logged out"}))
    response.delete_cookie("auth_token")
    return response


@app.post("/forgot-password")
def forgot_password():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    reset_token = f"reset-{user['id']}"
    conn.execute(
        "INSERT INTO password_reset_tokens(user_id, token, created_at) VALUES (?, ?, ?)",
        (user["id"], reset_token, now_iso()),
    )
    conn.commit()
    conn.close()

    log_action(user["id"], "FORGOT_PASSWORD", "auth", str(user["id"]))
    return jsonify(
        {
            "message": "Reset token generated",
            "reset_token": reset_token,
            "warning": "This token is intentionally weak and reusable in v1",
        }
    )


@app.post("/reset-password")
def reset_password():
    data = request.get_json(silent=True) or {}
    reset_token = data.get("token") or ""
    new_password = data.get("new_password") or ""

    if not reset_token or not new_password:
        return jsonify({"error": "token and new_password are required"}), 400

    conn = get_db()
    token_row = conn.execute(
        "SELECT * FROM password_reset_tokens WHERE token = ? ORDER BY id DESC LIMIT 1",
        (reset_token,),
    ).fetchone()

    if not token_row:
        conn.close()
        return jsonify({"error": "Invalid reset token"}), 400

    conn.execute(
        "UPDATE users SET password_plaintext = ? WHERE id = ?",
        (new_password, token_row["user_id"]),
    )
    conn.commit()
    conn.close()

    log_action(token_row["user_id"], "PASSWORD_RESET", "auth", str(token_row["user_id"]))
    return jsonify({"message": "Password updated"})


@app.post("/tickets")
def create_ticket():
    user = current_user_from_cookie()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    description = (data.get("description") or "").strip()
    severity = (data.get("severity") or "LOW").strip().upper()

    if not title or not description:
        return jsonify({"error": "title and description are required"}), 400

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
    user = current_user_from_cookie()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    conn = get_db()
    ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    conn.close()

    if not ticket:
        return jsonify({"error": "Ticket not found"}), 404

    return jsonify(dict(ticket))


@app.get("/health")
def health():
    return jsonify({"status": "ok", "mode": "vulnerable"})


if __name__ == "__main__":
    os.makedirs(BASE_DIR, exist_ok=True)
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
