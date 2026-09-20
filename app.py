#!/usr/bin/env python3

import os
import re
import csv
import glob
import shutil
import socket
import logging
import sqlite3
import subprocess
import tempfile
import secrets
import time
import json
from datetime import datetime

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from flask import (
    Flask,
    request,
    jsonify,
    render_template_string,
    redirect,
    send_file,
    session,
)


# ============================================================
# CONFIGURATION & CONSTANTS
# ============================================================

PBX_NAME = "TPbx"

APP_DIR = "/opt/my-pbx"
DB_FILE = os.path.join(APP_DIR, "pbx.db")
UPD_SCRIPT_PATH = os.path.join(APP_DIR, "upd.py")

# ============================================================
# BRANDING
# ============================================================

BRANDING_DIR = os.path.join(APP_DIR, "branding")

BRANDING_LOGO = os.path.join(BRANDING_DIR, "logo.png")
BRANDING_FAVICON = os.path.join(BRANDING_DIR, "favicon.png")
BRANDING_LOGIN = os.path.join(BRANDING_DIR, "login.png")

# General uploads directory used by backups and any other uploads.
UPLOAD_DIR = os.path.join(APP_DIR, "uploads")

MAX_UPLOAD_BYTES = 8 * 1024 * 1024
ALLOWED_IMAGE_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "ico",
}

ASTERISK_DIR = "/etc/asterisk"
BACKUP_DIR = os.path.join(APP_DIR, "backups")

HOST = "0.0.0.0"
PORT = 8080

ASTERISK_BINARY = "/usr/sbin/asterisk"
ASTERISK_SERVICE = "asterisk"

EXT_COMMAND = "/usr/local/bin/ext"

EXT_ADMIN_PASSWORD = os.environ.get(
    "PBX_EXT_ADMIN_PASSWORD",
    "1256",
)

# Default extension map
ATA_EXTENSIONS = {
    "101": "ATA",
    "115": "ATA",
}

EXTENSIONS_CONF = os.path.join(
    ASTERISK_DIR,
    "extensions.conf",
)

LOG_LINES = 500

# ------------------------------------------------------------
# MUSIC ON HOLD & RECORDINGS
# ------------------------------------------------------------
MOH_DIR = "/var/lib/asterisk/moh/webui"
MOH_CONF = os.path.join(ASTERISK_DIR, "musiconhold_my_pbx.conf")
MOH_MAIN_CONF = os.path.join(ASTERISK_DIR, "musiconhold.conf")
MOH_CLASS = "webui"
MOH_SAMPLE_RATE = 44100
MOH_INCLUDE = "#include musiconhold_my_pbx.conf"

RECORDING_DIR = "/var/spool/asterisk/monitor"


# ============================================================
# FLASK INIT & DIRECTORIES
# ============================================================

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 12

logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("flask.app").setLevel(logging.ERROR)
app.logger.disabled = True

os.makedirs(APP_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(BRANDING_DIR, exist_ok=True)


# ============================================================
# DATABASE SETUP & HELPERS
# ============================================================

def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS extension_settings (
            extension TEXT PRIMARY KEY,
            display_name TEXT DEFAULT '',
            device_type TEXT DEFAULT 'IP Phone'
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            permissions TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL
        )
    """)

    defaults = {
        "pbx_name": PBX_NAME,
        "recording_enabled": "0",
        "recording_format": "wav",
        "recording_retention": "30",
        "moh_default": "1",
        "moh_previous_default": "default",
        "moh_default_taken_over": "0",
    }

    for key, value in defaults.items():
        conn.execute(
            """
            INSERT OR IGNORE INTO settings(key, value)
            VALUES (?, ?)
            """,
            (key, value),
        )

    admin = conn.execute(
        "SELECT username FROM users WHERE username=?",
        ("admin",),
    ).fetchone()

    if not admin:
        conn.execute(
            """
            INSERT INTO users(username, password_hash, role, permissions, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "admin",
                generate_password_hash("admin"),
                "admin",
                json.dumps(["*"]),
                datetime.now().isoformat(timespec="seconds"),
            ),
        )

    conn.commit()
    conn.close()


def get_setting(key, default=""):
    conn = db()

    row = conn.execute(
        """
        SELECT value
        FROM settings
        WHERE key=?
        """,
        (key,),
    ).fetchone()

    conn.close()

    if row:
        return row["value"]

    return default


def set_setting(key, value):
    conn = db()

    conn.execute(
        """
        INSERT INTO settings(key, value)
        VALUES (?, ?)
        ON CONFLICT(key)
        DO UPDATE SET value=excluded.value
        """,
        (key, value),
    )

    conn.commit()
    conn.close()


# ============================================================
# WEB AUTHENTICATION & PERMISSIONS
# ============================================================

ALL_PERMISSIONS = [
    "dashboard",
    "calls",
    "history",
    "logs",
    "extensions",
    "moh",
    "settings",
    "system",
    "backups",
    "accounts",
]

ROLE_DEFAULTS = {
    "admin": ALL_PERMISSIONS,
    "operator": [
        "dashboard",
        "calls",
        "history",
        "logs",
        "extensions",
        "moh",
    ],
    "viewer": [
        "dashboard",
        "calls",
        "history",
    ],
}

LOGIN_EXEMPT_ENDPOINTS = {
    "login",
    "favicon",
    "fav_png",
    "logo_png",
    "login_png",
    "static",
}

LOGIN_FAILURES = {}
LOGIN_FAILURE_WINDOW = 300
LOGIN_FAILURE_LIMIT = 5


def ensure_secret_key():
    key = get_setting("web_secret_key", "")

    if not key:
        key = secrets.token_hex(32)
        set_setting("web_secret_key", key)

    app.secret_key = key


def get_user(username):
    if not username:
        return None

    conn = db()

    row = conn.execute(
        """
        SELECT username, password_hash, role, permissions, created_at
        FROM users
        WHERE username=?
        """,
        (username,),
    ).fetchone()

    conn.close()

    if not row:
        return None

    try:
        permissions = json.loads(row["permissions"] or "[]")
    except Exception:
        permissions = []

    return {
        "username": row["username"],
        "password_hash": row["password_hash"],
        "role": row["role"],
        "permissions": permissions,
        "created_at": row["created_at"],
    }


def list_users():
    conn = db()

    rows = conn.execute(
        """
        SELECT username, role, permissions, created_at
        FROM users
        ORDER BY username COLLATE NOCASE
        """
    ).fetchall()

    conn.close()

    result = []

    for row in rows:
        try:
            permissions = json.loads(row["permissions"] or "[]")
        except Exception:
            permissions = []

        result.append({
            "username": row["username"],
            "role": row["role"],
            "permissions": permissions,
            "created_at": row["created_at"],
        })

    return result


def save_user(username, password=None, role="viewer", permissions=None):
    role = role if role in ROLE_DEFAULTS else "viewer"

    permissions = (
        ROLE_DEFAULTS[role]
        if permissions is None
        else permissions
    )

    if role == "admin":
        permissions = ["*"]

    conn = db()

    if password is None:
        conn.execute(
            """
            UPDATE users
            SET role=?, permissions=?
            WHERE username=?
            """,
            (
                role,
                json.dumps(permissions),
                username,
            ),
        )
    else:
        conn.execute(
            """
            UPDATE users
            SET password_hash=?, role=?, permissions=?
            WHERE username=?
            """,
            (
                generate_password_hash(password),
                role,
                json.dumps(permissions),
                username,
            ),
        )

    conn.commit()
    conn.close()


def create_user(username, password, role):
    username = username.strip()

    if not re.fullmatch(
        r"[A-Za-z0-9_.-]{3,32}",
        username,
    ):
        return (
            False,
            "Username must be 3-32 characters and use only letters, numbers, dot, underscore, or hyphen.",
        )

    if len(password) < 8:
        return (
            False,
            "Password must be at least 8 characters long.",
        )

    if role not in ROLE_DEFAULTS:
        return False, "Invalid account role."

    permissions = (
        ["*"]
        if role == "admin"
        else ROLE_DEFAULTS[role]
    )

    conn = db()

    try:
        conn.execute(
            """
            INSERT INTO users(
                username,
                password_hash,
                role,
                permissions,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                username,
                generate_password_hash(password),
                role,
                json.dumps(permissions),
                datetime.now().isoformat(timespec="seconds"),
            ),
        )

        conn.commit()

        return True, ""

    except sqlite3.IntegrityError:
        return False, "That username already exists."

    finally:
        conn.close()


def delete_user(username):
    if username == "admin":
        return (
            False,
            "The built-in admin account cannot be deleted.",
        )

    if username == session.get("username"):
        return (
            False,
            "You cannot delete the account you are currently using.",
        )

    conn = db()

    cur = conn.execute(
        "DELETE FROM users WHERE username=?",
        (username,),
    )

    conn.commit()
    conn.close()

    return (
        (True, "")
        if cur.rowcount
        else (False, "Account not found.")
    )


def user_has_permission(user, permission):
    return bool(
        user
        and (
            user["role"] == "admin"
            or "*" in user["permissions"]
            or permission in user["permissions"]
        )
    )


def current_user():
    return get_user(session.get("username"))


def csrf_token():
    token = session.get("csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token

    return token


def check_csrf():
    expected = session.get("csrf_token")
    supplied = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRF-Token")
    )

    return bool(
        expected
        and supplied
        and secrets.compare_digest(
            expected,
            supplied,
        )
    )


def required_permission(path):
    exact_or_prefix = {
        "/api/status": "dashboard",
        "/api/history": "history",
        "/api/logs": "logs",
        "/api/asterisk/restart": "system",
        "/recording": "history",
        "/extensions": "extensions",
        "/moh": "moh",
        "/settings": "settings",
        "/system": "system",
        "/backups": "backups",
        "/accounts": "accounts",
        "/calls": "calls",
        "/history": "history",
        "/logs": "logs",
    }

    for prefix, permission in exact_or_prefix.items():
        if path == prefix or path.startswith(prefix + "/"):
            return permission

    if path == "/":
        return "dashboard"

    return None


@app.context_processor
def inject_auth_context():
    user = current_user()

    return {
        "current_user": user,
        "current_username": user["username"] if user else "",
        "csrf_token": (
            csrf_token()
            if user
            else session.get("login_csrf_token", "")
        ),
        "is_admin": bool(
            user and user["role"] == "admin"
        ),
        "pbx_name": PBX_NAME,
    }


@app.before_request
def require_login_and_permission():
    if request.endpoint in LOGIN_EXEMPT_ENDPOINTS:
        return None

    if request.endpoint == "logout":
        if not session.get("username"):
            return redirect("/login")

        if (
            request.method == "POST"
            and not check_csrf()
        ):
            return "Invalid security token.", 400

        return None

    user = current_user()

    if not user:
        return redirect(
            "/login?next=" + request.path
        )

    if (
        request.method == "POST"
        and not check_csrf()
    ):
        return (
            "Invalid security token. Please refresh the page and try again.",
            400,
        )

    permission = required_permission(
        request.path
    )

    if permission and not user_has_permission(
        user,
        permission,
    ):
        return render_template_string(
            ACCESS_DENIED_HTML,
            pbx_name=PBX_NAME,
            hostname=hostname(),
            permission=permission,
        ), 403

    return None


# ============================================================
# ASTERISK & PROCESS CONTROL
# ============================================================

def run_asterisk(command):
    try:
        result = subprocess.run(
            [
                "sudo",
                "-n",
                ASTERISK_BINARY,
                "-rx",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

        return (
            result.stdout,
            result.stderr,
            result.returncode,
        )

    except Exception as exc:
        return "", str(exc), 1


def run_systemctl(command):
    try:
        result = subprocess.run(
            [
                "sudo",
                "-n",
                "/bin/systemctl",
            ] + command,
            capture_output=True,
            text=True,
            timeout=30,
        )

        return (
            result.stdout,
            result.stderr,
            result.returncode,
        )

    except Exception as exc:
        return "", str(exc), 1


def asterisk_online():
    stdout, stderr, code = run_asterisk(
        "core show version"
    )

    return (
        code == 0
        and bool(stdout.strip())
    )


def ensure_asterisk_running():
    """Checks if Asterisk is running; starts the system service if down."""

    if not asterisk_online():
        logging.info(
            "Asterisk is not running. Starting Asterisk service..."
        )

        stdout, stderr, code = run_systemctl(
            [
                "start",
                ASTERISK_SERVICE,
            ]
        )

        if code == 0:
            return (
                True,
                "Asterisk service started successfully.",
            )

        return (
            False,
            f"Failed to start Asterisk: {stdout + stderr}",
        )

    return True, "Asterisk is actively running."


def ensure_upd_running():
    """Start upd.py as an independent detached supervisor."""

    try:
        if not os.path.isfile(
            UPD_SCRIPT_PATH
        ):
            return (
                False,
                f"upd.py not found: {UPD_SCRIPT_PATH}",
            )

        pid_file = os.path.join(
            APP_DIR,
            "upd.pid",
        )

        if os.path.isfile(pid_file):
            try:
                with open(
                    pid_file,
                    "r",
                    encoding="utf-8",
                ) as file:
                    pid = int(
                        file.read().strip()
                    )

                os.kill(pid, 0)

                return (
                    True,
                    f"upd.py is already running (PID {pid}).",
                )

            except (
                ValueError,
                ProcessLookupError,
                PermissionError,
            ):
                try:
                    os.remove(pid_file)
                except OSError:
                    pass

        log_path = os.path.join(
            APP_DIR,
            "upd.log",
        )

        log_file = open(
            log_path,
            "a",
            encoding="utf-8",
            buffering=1,
        )

        process = subprocess.Popen(
            [
                "python3",
                UPD_SCRIPT_PATH,
            ],
            cwd=APP_DIR,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=log_file,
            start_new_session=True,
            close_fds=True,
        )

        log_file.close()

        return (
            True,
            f"upd.py started independently (PID {process.pid}).",
        )

    except Exception as exc:
        return (
            False,
            f"Failed to start independent upd.py: {exc}",
        )


def restart_asterisk():
    stdout, stderr, code = run_systemctl(
        [
            "restart",
            ASTERISK_SERVICE,
        ]
    )

    return (
        code == 0,
        stdout + stderr,
    )


def reload_dialplan():
    stdout, stderr, code = run_asterisk(
        "dialplan reload"
    )

    return (
        code == 0,
        stdout + stderr,
    )


# ============================================================
# CUSTOM EXT COMMAND & IP DETECTION
# ============================================================

def resolve_ext_command():
    candidates = [
        EXT_COMMAND,
        "/usr/local/sbin/ext",
        "/usr/sbin/ext",
        "/usr/bin/ext",
        "/bin/ext",
    ]

    for candidate in candidates:
        if (
            candidate
            and os.path.isfile(candidate)
            and os.access(candidate, os.X_OK)
        ):
            return candidate

    return "ext"


def run_ext(args, input_text=None):
    command = resolve_ext_command()

    try:
        result = subprocess.run(
            [
                "sudo",
                "-n",
                command,
            ] + args,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=30,
        )

        return (
            result.stdout,
            result.stderr,
            result.returncode,
        )

    except Exception as exc:
        return "", str(exc), 1


def parse_ext_list(text):
    """
    Parses output from 'ext LIST'.
    Extracts extension numbers, registration status,
    and clean IPv4 addresses.
    """

    extensions = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        lower = line.lower()

        if (
            lower.startswith("registered extensions")
            or lower.startswith("extension")
            or lower.startswith("-")
            or lower.startswith("enter admin")
        ):
            continue

        parts = line.split()

        if not parts:
            continue

        number = parts[0]

        if not number.isdigit():
            continue

        ip = None
        status = "Not Registered"

        ip_match = re.search(
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            line,
        )

        if ip_match:
            ip = ip_match.group(0)

        if (
            "unregistered" in lower
            or "not registered" in lower
            or "offline" in lower
        ):
            status = "Not Registered"

        elif (
            "registered" in lower
            or "ok" in lower
            or "online" in lower
            or "avail" in lower
        ):
            status = "Registered"

        extensions.append({
            "extension": number,
            "ip": ip,
            "status": status,
            "registered": status == "Registered",
        })

    return extensions


def ext_list():
    stdout, stderr, code = run_ext(
        ["LIST"]
    )

    if code != 0:
        return [], (
            stdout + stderr
        ).strip()

    return (
        parse_ext_list(stdout),
        "",
    )


def ext_list_passwords():
    input_text = (
        EXT_ADMIN_PASSWORD
        + "\n"
    )

    stdout, stderr, code = run_ext(
        ["LISTPWD"],
        input_text=input_text,
    )

    if code != 0:
        return [], (
            stdout + stderr
        ).strip()

    return (
        parse_ext_passwords(stdout),
        "",
    )


def parse_ext_passwords(text):
    passwords = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        lower = line.lower()

        if (
            lower.startswith("extension passwords")
            or lower.startswith("extension")
            or lower.startswith("-")
            or lower.startswith("enter admin")
        ):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        extension = parts[0]

        if not extension.isdigit():
            continue

        passwords.append({
            "extension": extension,
            "password": parts[1],
        })

    return passwords


def get_extension_password_map():
    passwords, error = ext_list_passwords()

    if error:
        return {}, error

    return {
        item["extension"]: item["password"]
        for item in passwords
    }, ""


def get_all_extensions():
    registered, list_error = ext_list()

    passwords, password_error = ext_list_passwords()

    if list_error and password_error:
        return [], (
            list_error
            + "\n"
            + password_error
        )

    by_extension = {
        item["extension"]: item
        for item in registered
    }

    for item in passwords:
        extension = item["extension"]

        if extension not in by_extension:
            by_extension[extension] = {
                "extension": extension,
                "ip": None,
                "status": "Not Registered",
                "registered": False,
            }

    return (
        sorted(
            by_extension.values(),
            key=lambda item: int(
                item["extension"]
            ),
        ),
        password_error,
    )


# ============================================================
# EXTENSION INFORMATION & WEB LINKS
# ============================================================

def hostname():
    try:
        return socket.gethostname()
    except Exception:
        return "Unknown"


def get_extension_data():
    extensions, error = get_all_extensions()

    if error and not extensions:
        return [], error

    password_map, password_error = (
        get_extension_password_map()
    )

    conn = db()
    result = []

    for item in extensions:
        extension = item["extension"]

        row = conn.execute(
            """
            SELECT *
            FROM extension_settings
            WHERE extension=?
            """,
            (extension,),
        ).fetchone()

        if row:
            display_name = (
                row["display_name"]
                or extension
            )

            device_type = (
                row["device_type"]
                or "IP Phone"
            )
        else:
            display_name = extension

            device_type = ATA_EXTENSIONS.get(
                extension,
                "IP Phone",
            )

        ip = item["ip"]
        web_url = None

        clean_device_type = (
            device_type
            or ""
        ).strip().lower()

        if (
            item["registered"]
            and ip
            and clean_device_type not in (
                "ata",
                "softphone",
            )
        ):
            web_url = (
                f"http://{ip}"
            )

        result.append({
            "extension": extension,
            "name": display_name,
            "device_type": device_type,
            "registered": item["registered"],
            "status": item["status"],
            "ip": ip,
            "password": password_map.get(
                extension
            ),
            "web_url": web_url,
        })

    conn.close()

    return result, password_error


def add_extension_via_ext(
    extension,
    password,
):
    stdout, stderr, code = run_ext(
        [
            "ADD",
            extension,
            password,
        ]
    )

    return (
        code == 0,
        (
            stdout + stderr
        ).strip(),
    )


def remove_extension_via_ext(extension):
    stdout, stderr, code = run_ext(
        [
            "RM",
            extension,
        ]
    )

    return (
        code == 0,
        (
            stdout + stderr
        ).strip(),
    )


# ============================================================
# MUSIC ON HOLD
# ============================================================

def ensure_moh_directories():
    os.makedirs(
        MOH_DIR,
        exist_ok=True,
    )

    os.makedirs(
        RECORDING_DIR,
        exist_ok=True,
    )


def remember_existing_moh_default():
    if not os.path.isfile(
        MOH_MAIN_CONF
    ):
        return

    try:
        with open(
            MOH_MAIN_CONF,
            "r",
            errors="replace",
        ) as file:
            text = file.read()

        for line in text.splitlines():
            m = re.match(
                r"^\s*default_class\s*=\s*(.+)$",
                line,
                re.I,
            )

            if m:
                val = m.group(1).strip()

                if val != MOH_CLASS:
                    set_setting(
                        "moh_previous_default",
                        val,
                    )

                break

    except Exception:
        pass


def moh_files():
    ensure_moh_directories()

    files = []

    for name in os.listdir(MOH_DIR):
        path = os.path.join(
            MOH_DIR,
            name,
        )

        if os.path.isfile(path):
            files.append({
                "name": name,
                "path": path,
                "size": os.path.getsize(path),
                "modified": datetime.fromtimestamp(
                    os.path.getmtime(path)
                ).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
            })

    return sorted(
        files,
        key=lambda item: item["name"].lower(),
    )


def write_moh_config(make_default=True):
    try:
        ensure_moh_directories()

        with open(
            MOH_CONF,
            "w",
        ) as file:
            file.write(
                f"; Generated by {PBX_NAME} Web Interface.\n"
                f"[{MOH_CLASS}]\n"
                "mode=files\n"
                f"directory={MOH_DIR}\n"
                "random=yes\n"
            )

        if not os.path.isfile(
            MOH_MAIN_CONF
        ):
            with open(
                MOH_MAIN_CONF,
                "w",
            ) as file:
                file.write(
                    "[general]\n"
                )

        with open(
            MOH_MAIN_CONF,
            "r",
            errors="replace",
        ) as file:
            text = file.read()

        if MOH_INCLUDE not in text:
            if text and not text.endswith("\n"):
                text += "\n"

            text += (
                "\n"
                + MOH_INCLUDE
                + "\n"
            )

        if make_default:
            lines = text.splitlines(
                keepends=True
            )

            general_start = None
            general_end = len(lines)

            for i, line in enumerate(lines):
                if line.strip().lower() == "[general]":
                    general_start = i
                    break

            if general_start is None:
                lines.insert(
                    0,
                    "[general]\n",
                )
                general_start = 0
                general_end = len(lines)

            else:
                for i in range(
                    general_start + 1,
                    len(lines),
                ):
                    stripped = lines[i].strip()

                    if (
                        stripped.startswith("[")
                        and stripped.endswith("]")
                    ):
                        general_end = i
                        break

            replaced = False

            for i in range(
                general_start + 1,
                general_end,
            ):
                if re.match(
                    r"^\s*default_class\s*=",
                    lines[i],
                    re.I,
                ):
                    lines[i] = (
                        f"default_class={MOH_CLASS}\n"
                    )
                    replaced = True
                    break

            if not replaced:
                lines.insert(
                    general_start + 1,
                    f"default_class={MOH_CLASS}\n",
                )

            text = "".join(lines)

        with open(
            MOH_MAIN_CONF,
            "w",
        ) as file:
            file.write(text)

        return True, ""

    except Exception as exc:
        return False, str(exc)


def set_moh_default(enabled):
    try:
        if not os.path.isfile(
            MOH_MAIN_CONF
        ):
            with open(
                MOH_MAIN_CONF,
                "w",
            ) as file:
                file.write(
                    "[general]\n"
                )

        with open(
            MOH_MAIN_CONF,
            "r",
            errors="replace",
        ) as file:
            text = file.read()

        lines = text.splitlines(
            keepends=True
        )

        general_start = None
        general_end = len(lines)

        for i, line in enumerate(lines):
            if line.strip().lower() == "[general]":
                general_start = i
                break

        if general_start is None:
            lines.insert(
                0,
                "[general]\n",
            )

            general_start = 0
            general_end = len(lines)

        else:
            for i in range(
                general_start + 1,
                general_end,
            ):
                stripped = lines[i].strip()

                if (
                    stripped.startswith("[")
                    and stripped.endswith("]")
                ):
                    general_end = i
                    break

        value = (
            MOH_CLASS
            if enabled
            else get_setting(
                "moh_previous_default",
                "default",
            )
        )

        replaced = False

        for i in range(
            general_start + 1,
            general_end,
        ):
            if re.match(
                r"^\s*default_class\s*=",
                lines[i],
                re.I,
            ):
                lines[i] = (
                    f"default_class={value}\n"
                )

                replaced = True
                break

        if not replaced:
            lines.insert(
                general_start + 1,
                f"default_class={value}\n",
            )

        with open(
            MOH_MAIN_CONF,
            "w",
        ) as file:
            file.writelines(lines)

        return True, ""

    except Exception as exc:
        return False, str(exc)


def reload_moh():
    return run_asterisk(
        "moh reload"
    )


def convert_to_mono_wav(
    input_path,
    output_path,
):
    try:
        result = subprocess.run(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-i",
                input_path,
                "-vn",
                "-ac",
                "1",
                "-ar",
                str(MOH_SAMPLE_RATE),
                "-c:a",
                "pcm_s16le",
                output_path,
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

        if result.returncode != 0:
            return (
                False,
                result.stderr.strip()
                or "ffmpeg failed.",
            )

        return True, ""

    except FileNotFoundError:
        return (
            False,
            "ffmpeg is not installed.",
        )

    except Exception as exc:
        return False, str(exc)


def upload_moh_files(uploaded_files):
    ensure_moh_directories()

    uploaded_count = 0
    errors = []

    for uploaded in uploaded_files:
        if (
            not uploaded
            or not uploaded.filename
        ):
            continue

        original = secure_filename(
            uploaded.filename
        )

        if not original:
            errors.append(
                "One uploaded file had an invalid filename."
            )
            continue

        stem = os.path.splitext(
            original
        )[0]

        stem = re.sub(
            r"[^A-Za-z0-9_-]+",
            "_",
            stem,
        ).strip("_") or "music"

        output_name = (
            stem
            + ".wav"
        )

        output_path = os.path.join(
            MOH_DIR,
            output_name,
        )

        fd, temp_path = tempfile.mkstemp(
            prefix="moh_upload_",
            suffix=".input",
            dir=APP_DIR,
        )

        os.close(fd)

        try:
            uploaded.save(
                temp_path
            )

            ok, error = convert_to_mono_wav(
                temp_path,
                output_path,
            )

            if not ok:
                errors.append(
                    f"{original}: {error}"
                )

                try:
                    os.remove(
                        output_path
                    )
                except FileNotFoundError:
                    pass

                continue

            uploaded_count += 1

        finally:
            try:
                os.remove(
                    temp_path
                )
            except FileNotFoundError:
                pass

    if uploaded_count:
        ok, error = write_moh_config(
            make_default=False
        )

        if not ok:
            errors.append(
                "Could not write Music On Hold configuration: "
                + error
            )

        else:
            ok, error = set_moh_default(
                get_setting(
                    "moh_default",
                    "1",
                ) == "1"
            )

            if not ok:
                errors.append(
                    "Could not set default Music On Hold class: "
                    + error
                )

            else:
                stdout, stderr, code = reload_moh()

                if code != 0:
                    errors.append(
                        "Music On Hold reload failed: "
                        + (
                            stdout + stderr
                        ).strip()
                    )

    return (
        uploaded_count,
        errors,
    )


def delete_moh_file(name):
    safe = secure_filename(name)

    if not safe or safe != name:
        return (
            False,
            "Invalid music filename.",
        )

    path = os.path.realpath(
        os.path.join(
            MOH_DIR,
            safe,
        )
    )

    if not path.startswith(
        os.path.realpath(MOH_DIR) + os.sep
    ):
        return (
            False,
            "Invalid music path.",
        )

    if not os.path.isfile(path):
        return (
            False,
            "Music file not found.",
        )

    try:
        os.remove(path)

        stdout, stderr, code = reload_moh()

        if code != 0:
            return (
                False,
                "File deleted, but MOH reload failed: "
                + (
                    stdout + stderr
                ).strip(),
            )

        return True, ""

    except Exception as exc:
        return False, str(exc)


# ============================================================
# ACTIVE CALLS
# ============================================================

def extract_extension(channel):
    match = re.search(
        r"PJSIP/(\d+)-",
        channel,
    )

    if match:
        return match.group(1)

    return None


def get_active_channels():
    stdout, stderr, code = run_asterisk(
        "core show channels concise"
    )

    if code != 0:
        return []

    channels = []

    for line in stdout.splitlines():
        if not line.strip():
            continue

        parts = line.split("!")

        if len(parts) < 5:
            continue

        channels.append({
            "channel": parts[0],
            "state": parts[4],
            "application": (
                parts[5]
                if len(parts) > 5
                else ""
            ),
            "app_data": (
                parts[6]
                if len(parts) > 6
                else ""
            ),
            "caller_id": (
                parts[7]
                if len(parts) > 7
                else ""
            ),
            "linked_id": (
                parts[-1]
                if parts
                else ""
            ),
        })

    return channels


def get_active_calls():
    channels = get_active_channels()
    groups = {}

    for channel in channels:
        key = (
            channel["linked_id"]
            or channel["channel"]
        )

        groups.setdefault(
            key,
            [],
        ).append(channel)

    calls = []

    for linked_id, group in groups.items():
        endpoints = []

        for channel in group:
            extension = extract_extension(
                channel["channel"]
            )

            if extension:
                endpoints.append(
                    extension
                )

        endpoints = list(
            dict.fromkeys(endpoints)
        )

        calls.append({
            "from": (
                endpoints[0]
                if len(endpoints) > 0
                else "?"
            ),
            "to": (
                endpoints[1]
                if len(endpoints) > 1
                else "?"
            ),
            "state": (
                group[0]["state"]
                if group
                else "Unknown"
            ),
            "channels": len(group),
            "linked_id": linked_id,
        })

    return calls


# ============================================================
# CALL HISTORY & RECORDINGS
# ============================================================

def find_recording(
    source,
    destination,
):
    monitor_dir = RECORDING_DIR

    if not os.path.isdir(
        monitor_dir
    ):
        return None

    patterns = [
        f"*{source}*{destination}*",
        f"*{destination}*{source}*",
    ]

    for pattern in patterns:
        matches = glob.glob(
            os.path.join(
                monitor_dir,
                pattern,
            )
        )

        if matches:
            matches.sort(
                key=os.path.getmtime
            )

            return matches[-1]

    return None


def get_call_history():
    cdr_files = [
        "/var/log/asterisk/cdr-csv/Master.csv",
        "/var/log/asterisk/cdr-custom/Master.csv",
    ]

    cdr_file = None

    for path in cdr_files:
        if os.path.isfile(path):
            cdr_file = path
            break

    if not cdr_file:
        return []

    calls = []

    try:
        with open(
            cdr_file,
            "r",
            errors="replace",
            newline="",
        ) as file:
            reader = csv.reader(file)

            for fields in reader:
                if len(fields) < 14:
                    continue

                source = fields[1]
                destination = fields[2]

                calls.append({
                    "source": source,
                    "destination": destination,
                    "callerid": fields[3],
                    "channel": fields[4],
                    "dstchannel": fields[5],
                    "lastapp": fields[6],
                    "lastdata": fields[7],
                    "start": fields[8],
                    "answer": fields[9],
                    "end": fields[10],
                    "duration": fields[11],
                    "billsec": fields[12],
                    "disposition": fields[13],
                    "recording": find_recording(
                        source,
                        destination,
                    ),
                })

    except Exception:
        return []

    return list(
        reversed(calls)
    )


# ============================================================
# BACKUPS
# ============================================================

def create_backup():
    timestamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S"
    )

    destination = os.path.join(
        BACKUP_DIR,
        timestamp,
    )

    try:
        os.makedirs(
            destination,
            exist_ok=False,
        )

        shutil.copytree(
            ASTERISK_DIR,
            os.path.join(
                destination,
                "asterisk",
            ),
            dirs_exist_ok=True,
        )

        if os.path.isdir(
            MOH_DIR
        ):
            shutil.copytree(
                MOH_DIR,
                os.path.join(
                    destination,
                    "moh",
                ),
                dirs_exist_ok=True,
            )

        if os.path.isdir(
            UPLOAD_DIR
        ):
            shutil.copytree(
                UPLOAD_DIR,
                os.path.join(
                    destination,
                    "uploads",
                ),
                dirs_exist_ok=True,
            )

        # Include the branding directory in backups.
        if os.path.isdir(
            BRANDING_DIR
        ):
            shutil.copytree(
                BRANDING_DIR,
                os.path.join(
                    destination,
                    "branding",
                ),
                dirs_exist_ok=True,
            )

        with open(
            os.path.join(
                destination,
                "backup.info",
            ),
            "w",
        ) as file:
            file.write(
                f"{PBX_NAME} configuration backup\n"
            )

            file.write(
                "Created: "
                + datetime.now().isoformat()
                + "\n"
            )

            file.write(
                "Hostname: "
                + socket.gethostname()
                + "\n"
            )

        return destination

    except Exception as exc:
        shutil.rmtree(
            destination,
            ignore_errors=True,
        )

        print(
            "Backup error:",
            exc,
        )

        return None


def list_backups():
    backups = []

    if not os.path.isdir(
        BACKUP_DIR
    ):
        return backups

    for name in os.listdir(
        BACKUP_DIR
    ):
        path = os.path.join(
            BACKUP_DIR,
            name,
        )

        if not os.path.isdir(path):
            continue

        if not os.path.isdir(
            os.path.join(
                path,
                "asterisk",
            )
        ):
            continue

        try:
            timestamp = datetime.strptime(
                name,
                "%Y%m%d-%H%M%S",
            )

            display_time = timestamp.strftime(
                "%B %d, %Y %I:%M:%S %p"
            )

        except Exception:
            display_time = name

        backups.append({
            "name": name,
            "display_time": display_time,
        })

    backups.sort(
        key=lambda item: item["name"],
        reverse=True,
    )

    return backups


def get_backup(name):
    if not re.fullmatch(
        r"\d{8}-\d{6}",
        name,
    ):
        return None

    path = os.path.join(
        BACKUP_DIR,
        name,
    )

    if not os.path.isdir(path):
        return None

    asterisk_path = os.path.join(
        path,
        "asterisk",
    )

    if not os.path.isdir(
        asterisk_path
    ):
        return None

    return path


def restore_backup(name):
    backup = get_backup(name)

    if not backup:
        return (
            False,
            "Backup not found.",
        )

    emergency = create_backup()

    if not emergency:
        return (
            False,
            "Could not create automatic backup.",
        )

    try:
        shutil.copytree(
            os.path.join(
                backup,
                "asterisk",
            ),
            ASTERISK_DIR,
            dirs_exist_ok=True,
        )

        backup_moh = os.path.join(
            backup,
            "moh",
        )

        if os.path.isdir(
            backup_moh
        ):
            shutil.copytree(
                backup_moh,
                MOH_DIR,
                dirs_exist_ok=True,
            )

        backup_uploads = os.path.join(
            backup,
            "uploads",
        )

        if os.path.isdir(
            backup_uploads
        ):
            shutil.copytree(
                backup_uploads,
                UPLOAD_DIR,
                dirs_exist_ok=True,
            )

        backup_branding = os.path.join(
            backup,
            "branding",
        )

        if os.path.isdir(
            backup_branding
        ):
            shutil.copytree(
                backup_branding,
                BRANDING_DIR,
                dirs_exist_ok=True,
            )

    except Exception as exc:
        return (
            False,
            "Restore failed: "
            + str(exc),
        )

    success, output = restart_asterisk()

    if not success:
        return (
            False,
            "Configuration restored, but Asterisk restart failed.\n\n"
            + output,
        )

    return (
        True,
        "Backup restored successfully.",
    )


def delete_backup(name):
    backup = get_backup(name)

    if not backup:
        return False

    try:
        shutil.rmtree(backup)
        return True

    except Exception:
        return False


# ============================================================
# STYLES & TEMPLATES
# ============================================================

BASE_STYLE = r"""
<style>
:root {
    --bg-main: #0b0f19;
    --bg-card: #111827;
    --bg-card-hover: #1f293d;
    --sidebar-bg: #0d1322;
    --border-color: #1e293b;
    --border-highlight: #334155;
    --primary: #3b82f6;
    --primary-hover: #2563eb;
    --primary-light: rgba(59, 130, 246, 0.12);
    --text-main: #f3f4f6;
    --text-muted: #9ca3af;
    --text-subtle: #6b7280;
    --success: #10b981;
    --success-bg: rgba(16, 185, 129, 0.12);
    --danger: #ef4444;
    --danger-bg: rgba(239, 68, 68, 0.12);
    --warning: #f59e0b;
    --warning-bg: rgba(245, 158, 11, 0.12);
    --radius-sm: 6px;
    --radius-md: 10px;
    --radius-lg: 16px;
    --shadow-sm: 0 1px 3px rgba(0,0,0,0.3);
    --shadow-md: 0 4px 12px rgba(0,0,0,0.4);
    --shadow-glow: 0 0 20px rgba(59, 130, 246, 0.15);
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: var(--bg-main);
    color: var(--text-main);
    font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
}

/* Sidebar Styling */
.sidebar {
    position: fixed;
    left: 0;
    top: 0;
    bottom: 0;
    width: 250px;
    background: var(--sidebar-bg);
    border-right: 1px solid var(--border-color);
    padding: 24px 16px;
    display: flex;
    flex-direction: column;
    z-index: 50;
}

.logo-container {
    padding: 0 8px 24px;
    border-bottom: 1px solid var(--border-color);
    margin-bottom: 16px;
}

.logo-badge {
    display: inline-flex;
    align-items: center;
    gap: 10px;
}

.logo-icon {
    width: 36px;
    height: 36px;
    background: #111827;
    border: 1px solid var(--border-highlight);
    border-radius: var(--radius-md);
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
    flex-shrink: 0;
}

.logo-icon img {
    width: 100%;
    height: 100%;
    object-fit: contain;
    display: block;
}

.logo-title {
    font-size: 20px;
    font-weight: 800;
    letter-spacing: -0.5px;
    color: #ffffff;
}

.logo-sub {
    font-size: 11px;
    color: var(--text-subtle);
    font-weight: 500;
    margin-top: 2px;
}

.nav-scroll {
    flex: 1;
    overflow-y: auto;
    padding-right: 4px;
}

.nav-scroll::-webkit-scrollbar {
    width: 4px;
}

.nav-scroll::-webkit-scrollbar-thumb {
    background: var(--border-color);
    border-radius: 4px;
}

.section-label {
    color: var(--text-subtle);
    font-size: 10px;
    font-weight: 700;
    padding: 16px 10px 8px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}

.nav {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

.nav a {
    display: flex;
    align-items: center;
    gap: 12px;
    color: var(--text-muted);
    text-decoration: none;
    padding: 10px 12px;
    border-radius: var(--radius-sm);
    font-size: 13.5px;
    font-weight: 500;
    transition: all 0.15s ease-in-out;
}

.nav a svg {
    width: 18px;
    height: 18px;
    opacity: 0.7;
    transition: opacity 0.15s;
}

.nav a:hover {
    background: rgba(255, 255, 255, 0.05);
    color: #ffffff;
}

.nav a:hover svg {
    opacity: 1;
}

.nav a.active {
    background: var(--primary-light);
    color: var(--primary);
    font-weight: 600;
}

.nav a.active svg {
    opacity: 1;
    stroke: var(--primary);
}

.user-profile {
    padding-top: 16px;
    border-top: 1px solid var(--border-color);
    margin-top: auto;
}

.user-info {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px;
    margin-bottom: 8px;
}

.avatar {
    width: 32px;
    height: 32px;
    background: #334155;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    font-size: 13px;
    color: #ffffff;
}

.user-details {
    overflow: hidden;
}

.user-name {
    font-size: 13px;
    font-weight: 600;
    color: #fff;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.user-role {
    font-size: 11px;
    color: var(--text-subtle);
    text-transform: capitalize;
}

/* Main Content Area */
.main {
    margin-left: 250px;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

.header {
    background: rgba(17, 24, 39, 0.8);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border-color);
    padding: 20px 32px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: sticky;
    top: 0;
    z-index: 40;
}

.header h1 {
    margin: 0;
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -0.3px;
}

.subtitle {
    color: var(--text-muted);
    font-size: 13px;
    margin-top: 3px;
}

.hostname-pill {
    background: #1e293b;
    border: 1px solid var(--border-highlight);
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 12px;
    color: var(--text-muted);
}

.hostname-pill strong {
    color: #fff;
}

.content {
    padding: 28px 32px;
    flex: 1;
}

/* Cards & Layout */
.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 20px;
    margin-bottom: 24px;
}

.card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: 22px;
    box-shadow: var(--shadow-sm);
    transition: border-color 0.15s ease, transform 0.15s ease;
}

.card:hover {
    border-color: var(--border-highlight);
}

.card-title {
    color: var(--text-muted);
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.card-value {
    font-size: 30px;
    font-weight: 800;
    letter-spacing: -1px;
}

/* Table Component */
.table-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    overflow: hidden;
    margin-bottom: 24px;
    box-shadow: var(--shadow-sm);
}

.table-header {
    padding: 18px 24px;
    border-bottom: 1px solid var(--border-color);
    font-weight: 700;
    font-size: 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

table {
    width: 100%;
    border-collapse: collapse;
    text-align: left;
}

th {
    color: var(--text-subtle);
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    padding: 14px 20px;
    background: rgba(0, 0, 0, 0.2);
    border-bottom: 1px solid var(--border-color);
}

td {
    padding: 14px 20px;
    border-bottom: 1px solid var(--border-color);
    font-size: 13.5px;
    color: #e5e7eb;
}

tr:last-child td {
    border-bottom: none;
}

tr:hover td {
    background: var(--bg-card-hover);
}

/* Status Badges */
.badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
}

.badge-success {
    background: var(--success-bg);
    color: var(--success);
}

.badge-danger {
    background: var(--danger-bg);
    color: var(--danger);
}

.badge-warning {
    background: var(--warning-bg);
    color: var(--warning);
}

.badge-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: currentColor;
}

.badge-dot.pulse {
    box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
    animation: pulse 1.8s infinite;
}

@keyframes pulse {
    0% {
        transform: scale(0.95);
        box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
    }

    70% {
        transform: scale(1);
        box-shadow: 0 0 0 6px rgba(16, 185, 129, 0);
    }

    100% {
        transform: scale(0.95);
        box-shadow: 0 0 0 0 rgba(16, 185, 129, 0);
    }
}

/* UI Elements */
.button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    border: 1px solid var(--border-highlight);
    border-radius: var(--radius-sm);
    padding: 8px 14px;
    background: #1e293b;
    color: #ffffff;
    text-decoration: none;
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
    transition: all 0.15s ease;
}

.button:hover {
    background: #334155;
    border-color: #475569;
}

.button.primary {
    background: var(--primary);
    border-color: var(--primary);
}

.button.primary:hover {
    background: var(--primary-hover);
}

.button.danger {
    background: #dc2626;
    border-color: #dc2626;
}

.button.danger:hover {
    background: #b91c1c;
}

.button.warning {
    background: #d97706;
    border-color: #d97706;
}

input,
select {
    width: 100%;
    background: #090d16;
    color: #ffffff;
    border: 1px solid var(--border-highlight);
    border-radius: var(--radius-sm);
    padding: 10px 14px;
    margin-top: 6px;
    margin-bottom: 18px;
    font-size: 14px;
    outline: none;
    transition: border-color 0.15s ease;
}

input:focus,
select:focus {
    border-color: var(--primary);
    box-shadow: 0 0 0 3px var(--primary-light);
}

label {
    color: var(--text-muted);
    font-size: 13px;
    font-weight: 500;
}

.form {
    max-width: 650px;
}

.empty {
    padding: 40px;
    text-align: center;
    color: var(--text-subtle);
    font-size: 14px;
}

/* Alerts */
.warning-box {
    background: var(--warning-bg);
    border: 1px solid rgba(245, 158, 11, 0.3);
    color: #fcd34d;
    padding: 14px 18px;
    border-radius: var(--radius-md);
    margin-bottom: 20px;
    font-size: 13.5px;
}

.info-box {
    background: var(--primary-light);
    border: 1px solid rgba(59, 130, 246, 0.3);
    color: #93c5fd;
    padding: 14px 18px;
    border-radius: var(--radius-md);
    margin-bottom: 20px;
    font-size: 13.5px;
}

.log-viewer {
    background: #050811;
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    padding: 18px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
    font-family: "JetBrains Mono", "Fira Code", "Consolas", monospace;
    font-size: 12px;
    line-height: 1.6;
    color: #cbd5e1;
    max-height: 650px;
}

.toolbar {
    padding: 16px 20px;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}

@media(max-width:850px) {
    .sidebar {
        width: 70px;
        padding: 16px 8px;
    }

    .logo-title,
    .logo-sub,
    .section-label,
    .user-details,
    .nav a span {
        display: none;
    }

    .logo-container {
        padding: 0 0 16px;
        text-align: center;
    }

    .logo-badge {
        justify-content: center;
    }

    .nav a {
        justify-content: center;
        padding: 12px;
    }

    .main {
        margin-left: 70px;
    }

    .header {
        padding: 16px 20px;
    }

    .content {
        padding: 20px;
    }
}
</style>
"""


def nav_html(active):
    return f"""
<div class="sidebar">
<div class="logo-container">
    <div class="logo-badge">
        <div class="logo-icon">
            <img src="/logo.png" alt="TPbx Logo">
        </div>
        <div>
            <div class="logo-title">{PBX_NAME}</div>
            <div class="logo-sub">Asterisk PBX Frontend</div>
        </div>
    </div>
</div>

<div class="nav-scroll">

    <div class="section-label">Monitoring</div>

    <div class="nav">

        <a class="{ 'active' if active == 'dashboard' else '' }" href="/">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="3" width="7" height="9"></rect>
                <rect x="14" y="3" width="7" height="5"></rect>
                <rect x="14" y="12" width="7" height="9"></rect>
                <rect x="3" y="16" width="7" height="5"></rect>
            </svg>
            <span>Dashboard</span>
        </a>

        <a class="{ 'active' if active == 'calls' else '' }" href="/calls">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M15 0C7 0 1 6 1 14h2a12 12 0 0 1 12-12V0z"></path>
                <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path>
            </svg>
            <span>Active Calls</span>
        </a>

        <a class="{ 'active' if active == 'history' else '' }" href="/history">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <polyline points="12 6 12 12 16 14"></polyline>
            </svg>
            <span>Call History</span>
        </a>

        <a class="{ 'active' if active == 'logs' else '' }" href="/logs">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                <polyline points="14 2 14 8 20 8"></polyline>
                <line x1="16" y1="13" x2="8" y2="13"></line>
                <line x1="16" y1="17" x2="8" y2="17"></line>
                <polyline points="10 9 9 9 8 9"></polyline>
            </svg>
            <span>System Logs</span>
        </a>

    </div>

    <div class="section-label">Configuration</div>

    <div class="nav">

        <a class="{ 'active' if active == 'extensions' else '' }" href="/extensions">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                <circle cx="9" cy="7" r="4"></circle>
                <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
                <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
            </svg>
            <span>Extensions</span>
        </a>

        <a class="{ 'active' if active == 'moh' else '' }" href="/moh">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M9 18V5l12-2v13"></path>
                <circle cx="6" cy="18" r="3"></circle>
                <circle cx="18" cy="16" r="3"></circle>
            </svg>
            <span>Hold Music</span>
        </a>

    </div>

    <div class="section-label">Management</div>

    <div class="nav">

        <a class="{ 'active' if active == 'settings' else '' }" href="/settings">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="3"></circle>
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
            </svg>
            <span>Interface Settings</span>
        </a>

        <a class="{ 'active' if active == 'system' else '' }" href="/system">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                <line x1="6" y1="6" x2="6.01" y2="6"></line>
                <line x1="6" y1="18" x2="6.01" y2="18"></line>
            </svg>
            <span>Asterisk Engine</span>
        </a>

        <a class="{ 'active' if active == 'backups' else '' }" href="/backups">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path>
                <polyline points="17 21 17 13 7 13 7 21"></polyline>
                <polyline points="7 3 7 8 15 8"></polyline>
            </svg>
            <span>Backups</span>
        </a>

        {{% if is_admin %}}

        <a class="{ 'active' if active == 'accounts' else '' }" href="/accounts">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                <circle cx="8.5" cy="7" r="4"></circle>
                <line x1="20" y1="8" x2="20" y2="14"></line>
                <line x1="23" y1="11" x2="17" y2="11"></line>
            </svg>
            <span>Accounts</span>
        </a>

        {{% endif %}}

    </div>
</div>

<div class="user-profile">

    <div class="user-info">

        <div class="avatar">
            {{{{ current_username[:1].upper() }}}}
        </div>

        <div class="user-details">

            <div class="user-name">
                {{{{ current_username }}}}
            </div>

            <div class="user-role">
                {{{{ current_user.role if current_user else 'viewer' }}}}
            </div>

        </div>

    </div>

    <form method="post" action="/logout" style="margin:0;">

        <input
            type="hidden"
            name="csrf_token"
            value="{{{{ csrf_token }}}}"
        >

        <button
            class="button danger"
            type="submit"
            style="width:100%; font-size:12px; padding:6px 10px;"
        >
            Sign Out
        </button>

    </form>

</div>
</div>
"""


LOGIN_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>TPbx — Sign In</title>

<link
    rel="icon"
    href="/favicon.png"
>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;
    font-family: Inter, system-ui, -apple-system, sans-serif;
    background: #060913;
    color: #e5e7eb;
    display: flex;
    align-items: center;
    justify-content: center;

    background-image:
        linear-gradient(
            rgba(6, 9, 19, 0.35),
            rgba(6, 9, 19, 0.55)
        ),
        url('/login.png');

    background-size: cover;
    background-position: center;
    background-repeat: no-repeat;
}

.login-card {
    width: min(
        420px,
        calc(100% - 32px)
    );

    background: rgba(
        15,
        23,
        42,
        0.90
    );

    border: 1px solid rgba(
        255,
        255,
        255,
        0.1
    );

    box-shadow:
        0 25px 50px -12px
        rgba(0, 0, 0, 0.5);

    border-radius: 16px;
    padding: 36px;
    backdrop-filter: blur(16px);
}

.brand {
    text-align: center;
    margin-bottom: 30px;
}

.brand-icon {
    width: 72px;
    height: 72px;

    background: rgba(
        15,
        23,
        42,
        0.65
    );

    border: 1px solid rgba(
        255,
        255,
        255,
        0.12
    );

    border-radius: 16px;

    display: inline-flex;
    align-items: center;
    justify-content: center;

    margin-bottom: 14px;

    overflow: hidden;

    box-shadow:
        0 0 25px
        rgba(59, 130, 246, 0.25);
}

.brand-icon img {
    width: 100%;
    height: 100%;
    object-fit: contain;
    display: block;
}

.brand h1 {
    margin: 0;
    font-size: 26px;
    font-weight: 800;
    letter-spacing: -0.5px;
    color: #fff;
}

.brand p {
    margin: 6px 0 0;
    color: #94a3b8;
    font-size: 13px;
}

label {
    display: block;
    color: #cbd5e1;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 6px;
}

input {
    width: 100%;
    padding: 12px 14px;
    margin-bottom: 20px;
    border-radius: 8px;
    border: 1px solid #334155;
    background: #090d16;
    color: white;
    font-size: 14px;
    outline: none;
    transition: all 0.15s;
}

input:focus {
    border-color: #3b82f6;
    box-shadow:
        0 0 0 3px
        rgba(59, 130, 246, 0.2);
}

button {
    width: 100%;
    border: 0;
    border-radius: 8px;
    padding: 12px;
    background: #2563eb;
    color: white;
    font-weight: 600;
    font-size: 14px;
    cursor: pointer;
    transition: background 0.15s;
}

button:hover {
    background: #1d4ed8;
}

.error {
    background: rgba(
        220,
        38,
        38,
        0.15
    );

    border: 1px solid rgba(
        220,
        38,
        38,
        0.3
    );

    color: #fca5a5;
    padding: 12px;
    border-radius: 8px;
    margin-bottom: 20px;
    font-size: 13px;
}

.hint {
    margin-top: 20px;
    text-align: center;
    color: #64748b;
    font-size: 12px;
}

</style>

</head>

<body>

<div class="login-card">

    <div class="brand">

        <div class="brand-icon">

            <img
                src="/logo.png"
                alt="TPbx Logo"
            >

        </div>

        <h1>TPbx</h1>

        <p>
            Sign in to PBX Web Portal
        </p>

    </div>

    {% if error %}

    <div class="error">
        {{ error }}
    </div>

    {% endif %}

    <form
        method="post"
        action="/login"
    >

        <input
            type="hidden"
            name="csrf_token"
            value="{{ csrf_token }}"
        >

        <input
            type="hidden"
            name="next"
            value="{{ next_url }}"
        >

        <label>
            Username
        </label>

        <input
            name="username"
            autocomplete="username"
            autofocus
            required
            placeholder="Enter username"
        >

        <label>
            Password
        </label>

        <input
            name="password"
            type="password"
            autocomplete="current-password"
            required
            placeholder="Enter password"
        >

        <button type="submit">
            Sign In
        </button>

    </form>

    <div class="hint">
        Protected PBX Management Interface
    </div>

</div>

</body>

</html>
"""


ACCESS_DENIED_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1"
>

<title>
    Access Denied
</title>

""" + BASE_STYLE + r"""

</head>

<body>

""" + nav_html("") + r"""

<div class="main">

    <div class="header">

        <div>

            <h1>
                Access Denied
            </h1>

            <div class="subtitle">
                Your account permissions do not allow access.
            </div>

        </div>

        <div class="hostname-pill">
            PBX:
            <strong>
                {{ hostname }}
            </strong>
        </div>

    </div>

    <div class="content">

        <div class="card">

            <h2>
                Permission Required
            </h2>

            <p>
                This page requires:
                <strong>
                    {{ permission }}
                </strong>
            </p>

            <a
                class="button primary"
                href="/"
            >
                Return to Dashboard
            </a>

        </div>

    </div>

</div>

</body>

</html>
"""


ACCOUNTS_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>
    Accounts
</title>

<link
    rel="icon"
    href="/favicon.png"
>

""" + BASE_STYLE + r"""

</head>

<body>

""" + nav_html("accounts") + r"""

<div class="main">

<div class="header">

<div>

<h1>
    Account Management
</h1>

<div class="subtitle">
    Manage interface users and access roles
</div>

</div>

<div class="hostname-pill">
    PBX:
    <strong>
        {{ hostname }}
    </strong>
</div>

</div>

<div class="content">

{% if message %}

<div class="info-box">
    {{ message }}
</div>

{% endif %}

{% if error %}

<div class="warning-box">
    {{ error }}
</div>

{% endif %}

<div class="card form">

<h2>
    Create Account
</h2>

<form
    method="post"
    action="/accounts"
>

<input
    type="hidden"
    name="csrf_token"
    value="{{ csrf_token }}"
>

<label>
    Username
</label>

<input
    name="username"
    required
    pattern="[A-Za-z0-9_.-]{3,32}"
>

<label>
    Initial Password
</label>

<input
    name="password"
    type="password"
    minlength="8"
    required
>

<label>
    Role Level
</label>

<select
    name="role"
>

<option value="viewer">
    Viewer — Dashboard, calls, history
</option>

<option value="operator">
    Operator — Monitoring and PBX settings
</option>

<option value="admin">
    Administrator — Full administrative access
</option>

</select>

<button
    class="button primary"
    type="submit"
>
    Create User Account
</button>

</form>

</div>

<div class="table-card">

<div class="table-header">
    System Accounts
</div>

<table>

<thead>

<tr>

<th>
    Username
</th>

<th>
    Role
</th>

<th>
    Permissions
</th>

<th>
    Created
</th>

<th>
    Actions
</th>

</tr>

</thead>

<tbody>

{% for user in users %}

<tr>

<td>

<strong>
    {{ user.username }}
</strong>

{% if user.username == current_username %}

<span style="color:var(--text-subtle)">
    (you)
</span>

{% endif %}

</td>

<td>

<span class="badge badge-warning">
    {{ user.role|capitalize }}
</span>

</td>

<td>

{% if user.role == 'admin' %}

<span class="badge badge-success">
    Full Access
</span>

{% else %}

{{ user.permissions|join(', ') }}

{% endif %}

</td>

<td>
    {{ user.created_at }}
</td>

<td>

{% if user.username != 'admin' and user.username != current_username %}

<form
    method="post"
    action="/accounts/delete/{{ user.username }}"
    style="display:inline"
>

<input
    type="hidden"
    name="csrf_token"
    value="{{ csrf_token }}"
>

<button
    class="button danger"
    type="submit"
    onclick="return confirm('Delete this account?')"
>
    Delete
</button>

</form>

{% else %}

—

{% endif %}

</td>

</tr>

{% endfor %}

</tbody>

</table>

</div>

</div>

</div>

</body>

</html>
"""


ACCOUNT_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>
    My Account
</title>

<link
    rel="icon"
    href="/favicon.png"
>

""" + BASE_STYLE + r"""

</head>

<body>

""" + nav_html("account") + r"""

<div class="main">

<div class="header">

<div>

<h1>
    My Account
</h1>

<div class="subtitle">
    Account preferences & security
</div>

</div>

<div class="hostname-pill">
    Signed in as:
    <strong>
        {{ current_username }}
    </strong>
</div>

</div>

<div class="content">

<div class="card form">

{% if message %}

<div class="info-box">
    {{ message }}
</div>

{% endif %}

{% if error %}

<div class="warning-box">
    {{ error }}
</div>

{% endif %}

<h2>
    Profile Overview
</h2>

<p>
    Username:
    <strong>
        {{ current_username }}
    </strong>
</p>

<p>
    Role:
    <strong>
        {{ user.role|capitalize }}
    </strong>
</p>

<hr
    style="border-color:var(--border-color); margin:20px 0;"
>

<h2>
    Change Password
</h2>

<form
    method="post"
    action="/account"
>

<input
    type="hidden"
    name="csrf_token"
    value="{{ csrf_token }}"
>

<label>
    Current Password
</label>

<input
    name="current_password"
    type="password"
    autocomplete="current-password"
    required
>

<label>
    New Password
</label>

<input
    name="new_password"
    type="password"
    minlength="8"
    autocomplete="new-password"
    required
>

<label>
    Confirm New Password
</label>

<input
    name="confirm_password"
    type="password"
    minlength="8"
    autocomplete="new-password"
    required
>

<button
    class="button primary"
    type="submit"
>
    Update Password
</button>

</form>

</div>

</div>

</div>

</body>

</html>
"""


DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<link
    rel="icon"
    href="/favicon.png"
>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>
    TPbx Dashboard
</title>

""" + BASE_STYLE + r"""

</head>

<body>

""" + nav_html("dashboard") + r"""

<div class="main">

<div class="header">

<div>

<h1>
    PBX Overview
</h1>

<div class="subtitle">
    Real-time status monitoring
</div>

</div>

<div class="hostname-pill">
    PBX Node:
    <strong>
        {{ hostname }}
    </strong>
</div>

</div>

<div class="content">

<div class="cards">

<div class="card">

<div class="card-title">
    Engine Status
</div>

<div
    id="asterisk"
    class="card-value"
>
    Checking...
</div>

</div>

<div class="card">

<div class="card-title">
    Configured Extensions
</div>

<div
    id="extension-count"
    class="card-value"
>
    0
</div>

</div>

<div class="card">

<div class="card-title">
    Active Calls
</div>

<div
    id="call-count"
    class="card-value"
>
    0
</div>

</div>

</div>

<div class="table-card">

<div class="table-header">
    Active Calls
</div>

<div id="calls">
    <div class="empty">
        Loading calls...
    </div>
</div>

</div>

<div class="table-card">

<div class="table-header">
    Extension Status
</div>

<table>

<thead>

<tr>

<th>
    Extension
</th>

<th>
    Name
</th>

<th>
    Device
</th>

<th>
    Registration
</th>

<th>
    IP Address
</th>

<th>
    Action
</th>

</tr>

</thead>

<tbody
    id="extensions"
></tbody>

</table>

</div>

</div>

</div>

<script>

async function refresh() {

    try {

        const response =
            await fetch(
                "/api/status",
                {
                    cache: "no-store"
                }
            );

        const data =
            await response.json();

        const ast =
            document.getElementById(
                "asterisk"
            );

        if (data.asterisk.online) {

            ast.innerHTML =
                '<span class="badge badge-success">' +
                '<span class="badge-dot pulse"></span>' +
                ' Online' +
                '</span>';

        } else {

            ast.innerHTML =
                '<span class="badge badge-danger">' +
                '<span class="badge-dot"></span>' +
                ' Offline' +
                '</span>';

        }

        document.getElementById(
            "extension-count"
        ).textContent =
            data.extensions.length;

        document.getElementById(
            "call-count"
        ).textContent =
            data.active_calls.length;

        renderExtensions(
            data.extensions
        );

        renderCalls(
            data.active_calls
        );

    } catch (e) {

        console.error(e);

    }

}


function renderExtensions(
    extensions
) {

    const table =
        document.getElementById(
            "extensions"
        );

    if (!extensions.length) {

        table.innerHTML =
            `<tr>
                <td colspan="6" class="empty">
                    No extensions found.
                </td>
            </tr>`;

        return;

    }

    table.innerHTML =
        extensions.map(
            e => `

<tr>

<td>
    <strong>
        ${e.extension}
    </strong>
</td>

<td>
    ${e.name}
</td>

<td>
    ${e.device_type}
</td>

<td>

${
    e.registered
    ?
    '<span class="badge badge-success">' +
    '<span class="badge-dot pulse"></span>' +
    ' Registered</span>'
    :
    '<span class="badge badge-danger">' +
    '<span class="badge-dot"></span>' +
    ' Offline</span>'
}

</td>

<td>
    ${e.ip || "—"}
</td>

<td>

${
    e.web_url
    ?
    `<a
        class="button"
        href="${e.web_url}"
        target="_blank"
    >
        🌐 Web UI
    </a>`
    :
    "—"
}

</td>

</tr>

`
        ).join("");

}


function renderCalls(
    calls
) {

    const box =
        document.getElementById(
            "calls"
        );

    if (!calls.length) {

        box.innerHTML =
            `<div class="empty">
                No active calls currently in progress.
            </div>`;

        return;

    }

    box.innerHTML =
        `<table>

<thead>

<tr>

<th>
    From
</th>

<th>
    To
</th>

<th>
    State
</th>

<th>
    Channels
</th>

</tr>

</thead>

<tbody>

${
    calls.map(
        c => `
<tr>

<td>
    ${c.from}
</td>

<td>
    ${c.to}
</td>

<td>

<span class="badge badge-success">
    ${c.state}
</span>

</td>

<td>
    ${c.channels}
</td>

</tr>
`
    ).join("")
}

</tbody>

</table>`;

}


refresh();

setInterval(
    refresh,
    2500
);

</script>

</body>

</html>
"""


EXTENSIONS_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<link
    rel="icon"
    href="/favicon.png"
>

<title>
    Extensions
</title>

""" + BASE_STYLE + r"""

</head>

<body>

""" + nav_html("extensions") + r"""

<div class="main">

<div class="header">

<div>

<h1>
    Extensions
</h1>

<div class="subtitle">
    Manage PJSIP extensions
</div>

</div>

<div class="hostname-pill">
    PBX:
    <strong>
        {{ hostname }}
    </strong>
</div>

</div>

<div class="content">

<div
    class="card"
    style="margin-bottom:20px; display:flex; justify-shadow:space-between; align-items:center;"
>

<div>

<h3 style="margin:0 0 4px 0;">
    Extension Directory
</h3>

<p
    style="margin:0; color:var(--text-subtle); font-size:13px;"
>
    Provisioned extensions and device mapping
</p>

</div>

<a
    href="/extensions/add"
    class="button primary"
>
    + Add Extension
</a>

</div>

{% if password_error %}

<div class="warning-box">
    Password Error:
    <pre>{{ password_error }}</pre>
</div>

{% endif %}

<div class="table-card">

<table>

<thead>

<tr>

<th>
    Ext
</th>

<th>
    Name
</th>

<th>
    Device
</th>

<th>
    Status
</th>

<th>
    IP Address
</th>

<th>
    Web UI
</th>

<th>
    Password
</th>

<th>
    Actions
</th>

</tr>

</thead>

<tbody>

{% for e in extensions %}

<tr>

<td>
    <strong>
        {{ e.extension }}
    </strong>
</td>

<td>
    {{ e.name }}
</td>

<td>
    {{ e.device_type }}
</td>

<td>

{% if e.registered %}

<span class="badge badge-success">

<span class="badge-dot pulse"></span>

Registered

</span>

{% else %}

<span class="badge badge-danger">

<span class="badge-dot"></span>

Offline

</span>

{% endif %}

</td>

<td>
    {{ e.ip or "—" }}
</td>

<td>

{% if e.web_url %}

<a
    class="button"
    href="{{ e.web_url }}"
    target="_blank"
>
    Web UI
</a>

{% else %}

—

{% endif %}

</td>

<td>

{% if e.password %}

<code
    style="background:rgba(0,0,0,0.3); padding:3px 8px; border-radius:4px;"
>
    {{ e.password }}
</code>

{% else %}

—

{% endif %}

</td>

<td>

<a
    class="button"
    href="/extensions/edit/{{ e.extension }}"
>
    Edit
</a>

<a
    class="button danger"
    href="/extensions/delete/{{ e.extension }}"
    onclick="return confirm('Delete extension {{ e.extension }}?')"
>
    Delete
</a>

</td>

</tr>

{% else %}

<tr>

<td
    colspan="8"
    class="empty"
>
    No extensions configured yet.
</td>

</tr>

{% endfor %}

</tbody>

</table>

</div>

</div>

</div>

</body>

</html>
"""


EXTENSION_FORM = r"""
<!DOCTYPE html>
<html>

<head>

<link
    rel="icon"
    href="/favicon.png"
>

<title>
    {{ title }}
</title>

""" + BASE_STYLE + r"""

</head>

<body>

<div
    class="main"
    style="margin-left:0"
>

<div class="header">

<h1>
    {{ title }}
</h1>

</div>

<div class="content">

<div class="card form">

{% if mode == "add" %}

<form
    method="post"
    action="/extensions/add"
>

<input
    type="hidden"
    name="csrf_token"
    value="{{ csrf_token }}"
>

<label>
    Extension Number
</label>

<input
    name="extension"
    required
    pattern="[0-9]+"
    placeholder="e.g. 201"
>

<label>
    SIP Secret Password
</label>

<input
    name="password"
    type="password"
    required
    placeholder="SIP Auth Password"
>

<label>
    Display Name
</label>

<input
    name="display_name"
    placeholder="e.g. Office Desk Phone"
>

<label>
    Device Type
</label>

<select name="device_type">

<option>
    IP Phone
</option>

<option>
    ATA
</option>

<option>
    Softphone
</option>

</select>

<button
    class="button primary"
    type="submit"
>
    Create Extension
</button>

<a
    class="button"
    href="/extensions"
>
    Cancel
</a>

</form>

{% else %}

<form
    method="post"
    action="/extensions/edit/{{ extension }}"
>

<input
    type="hidden"
    name="csrf_token"
    value="{{ csrf_token }}"
>

<label>
    Extension
</label>

<input
    value="{{ extension }}"
    disabled
>

<label>
    Display Name
</label>

<input
    name="display_name"
    value="{{ display_name }}"
>

<label>
    Device Type
</label>

<select
    name="device_type"
>

<option
    {% if device_type == "IP Phone" %}
    selected
    {% endif %}
>
    IP Phone
</option>

<option
    {% if device_type == "ATA" %}
    selected
    {% endif %}
>
    ATA
</option>

<option
    {% if device_type == "Softphone" %}
    selected
    {% endif %}
>
    Softphone
</option>

</select>

<button
    class="button primary"
    type="submit"
>
    Save Changes
</button>

<a
    class="button"
    href="/extensions"
>
    Cancel
</a>

</form>

{% endif %}

</div>

</div>

</div>

</body>

</html>
"""


LOGS_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<link
    rel="icon"
    href="/favicon.png"
>

<title>
    System Logs
</title>

""" + BASE_STYLE + r"""

</head>

<body>

""" + nav_html("logs") + r"""

<div class="main">

<div class="header">

<div>

<h1>
    System Logs
</h1>

<div class="subtitle">
    Asterisk service console logs
</div>

</div>

<div class="hostname-pill">
    PBX:
    <strong>
        {{ hostname }}
    </strong>
</div>

</div>

<div class="content">

<div class="table-card">

<div class="toolbar">

<button
    class="button primary"
    onclick="refreshLogs()"
>
    ↻ Refresh
</button>

<button
    class="button warning"
    onclick="restartAsterisk()"
>
    ↻ Restart Asterisk
</button>

<button
    class="button danger"
    onclick="clearLogs()"
>
    🗑 Rotate Logs
</button>

</div>

<div style="padding:20px">

<div
    id="log-status"
    class="subtitle"
>
    Loading log contents...
</div>

<br>

<pre
    id="logs"
    class="log-viewer"
></pre>

</div>

</div>

</div>

</div>

<script>

async function refreshLogs() {

    try {

        const response =
            await fetch(
                "/api/logs",
                {
                    cache: "no-store"
                }
            );

        const data =
            await response.json();

        document.getElementById(
            "logs"
        ).textContent =
            data.logs;

        document.getElementById(
            "log-status"
        ).textContent =
            "Updated: "
            + new Date().toLocaleTimeString();

    } catch (e) {

        document.getElementById(
            "log-status"
        ).textContent =
            "Could not load logs.";

    }

}


async function restartAsterisk() {

    if (
        !confirm(
            "Restart Asterisk service? Active calls will drop."
        )
    ) {
        return;
    }

    try {

        const response =
            await fetch(
                "/api/asterisk/restart",
                {
                    method: "POST"
                }
            );

        const data =
            await response.json();

        document.getElementById(
            "log-status"
        ).textContent =
            data.message;

        setTimeout(
            refreshLogs,
            3000
        );

    } catch (e) {

        document.getElementById(
            "log-status"
        ).textContent =
            "Restart failed.";

    }

}


async function clearLogs() {

    if (
        !confirm(
            "Rotate Asterisk log files?"
        )
    ) {
        return;
    }

    try {

        const response =
            await fetch(
                "/api/logs/clear",
                {
                    method: "POST"
                }
            );

        const data =
            await response.json();

        document.getElementById(
            "log-status"
        ).textContent =
            data.message;

        setTimeout(
            refreshLogs,
            1000
        );

    } catch (e) {

        document.getElementById(
            "log-status"
        ).textContent =
            "Log rotate failed.";

    }

}


refreshLogs();

setInterval(
    refreshLogs,
    5000
);

</script>

</body>

</html>
"""


HISTORY_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<link
    rel="icon"
    href="/favicon.png"
>

<title>
    Call History
</title>

""" + BASE_STYLE + r"""

</head>

<body>

""" + nav_html("history") + r"""

<div class="main">

<div class="header">

<div>

<h1>
    Call History
</h1>

<div class="subtitle">
    Search Call Detail Records (CDR)
</div>

</div>

<div class="hostname-pill">
    PBX:
    <strong>
        {{ hostname }}
    </strong>
</div>

</div>

<div class="content">

<div class="table-card">

<div
    style="padding:20px; display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)) gap:12px;"
>

<div>

<label>
    From
</label>

<input
    id="from"
    placeholder="Caller ID"
>

</div>

<div>

<label>
    To
</label>

<input
    id="to"
    placeholder="Destination"
>

</div>

<div>

<label>
    Date
</label>

<input
    id="date"
    type="date"
>

</div>

<div
    style="display:flex; align-items:flex-end; margin-bottom:18px;"
>

<button
    class="button primary"
    style="width:100%"
    onclick="searchHistory()"
>
    Filter Records
</button>

</div>

</div>

<div id="results">

<div class="empty">
    Loading call history records...
</div>

</div>

</div>

</div>

</div>

<script>

let calls = [];

async function loadHistory() {

    const response =
        await fetch(
            "/api/history"
        );

    calls =
        await response.json();

    render(calls);

}


function searchHistory() {

    const from =
        document
            .getElementById("from")
            .value
            .trim();

    const to =
        document
            .getElementById("to")
            .value
            .trim();

    const date =
        document
            .getElementById("date")
            .value;

    const filtered =
        calls.filter(
            call => {

                if (
                    from
                    && !call.source.includes(
                        from
                    )
                ) {
                    return false;
                }

                if (
                    to
                    && !call.destination.includes(
                        to
                    )
                ) {
                    return false;
                }

                if (
                    date
                    && !call.start.startsWith(
                        date
                    )
                ) {
                    return false;
                }

                return true;

            }
        );

    render(filtered);

}


function render(data) {

    const results =
        document.getElementById(
            "results"
        );

    if (!data.length) {

        results.innerHTML =
            `<div class="empty">
                No records matching query.
            </div>`;

        return;

    }

    results.innerHTML =
        `<table>

<thead>

<tr>

<th>
    Date / Time
</th>

<th>
    From
</th>

<th>
    To
</th>

<th>
    Duration
</th>

<th>
    Status
</th>

<th>
    Recording
</th>

</tr>

</thead>

<tbody>

${
    data.map(
        call => `
<tr>

<td>
    ${call.start}
</td>

<td>
    <strong>
        ${call.source}
    </strong>
</td>

<td>
    <strong>
        ${call.destination}
    </strong>
</td>

<td>
    ${call.duration || "—"}s
</td>

<td>

<span
    class="badge ${
        call.disposition === "ANSWERED"
        ? "badge-success"
        : "badge-danger"
    }"
>
    ${call.disposition}
</span>

</td>

<td>

${
    call.recording
    ?
    `<a
        class="button"
        href="/recording?file=${encodeURIComponent(call.recording)}"
    >
        ▶ Play
    </a>

    <a
        class="button"
        href="/recording?file=${encodeURIComponent(call.recording)}&download=1"
    >
        ⬇
    </a>`
    :
    "—"
}

</td>

</tr>
`
    ).join("")
}

</tbody>

</table>`;

}


loadHistory();

</script>

</body>

</html>
"""


BACKUPS_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<link
    rel="icon"
    href="/favicon.png"
>

<title>
    Backups
</title>

""" + BASE_STYLE + r"""

</head>

<body>

""" + nav_html("backups") + r"""

<div class="main">

<div class="header">

<div>

<h1>
    Configuration Backups
</h1>

<div class="subtitle">
    Snapshot and restore PBX states
</div>

</div>

<div class="hostname-pill">
    PBX:
    <strong>
        {{ hostname }}
    </strong>
</div>

</div>

<div class="content">

<div class="warning-box">

Restoring a backup overwrites the active configuration.
An automatic snapshot is created prior to restore.

</div>

<div
    class="card"
    style="margin-bottom:20px;"
>

<a
    class="button primary"
    href="/backup/create"
>
    💾 Create Snapshot Backup
</a>

</div>

<div class="table-card">

<div class="table-header">
    Available Backups
</div>

<table>

<thead>

<tr>

<th>
    Backup ID
</th>

<th>
    Created Date
</th>

<th>
    Actions
</th>

</tr>

</thead>

<tbody>

{% for backup in backups %}

<tr>

<td>

<strong>
    {{ backup.name }}
</strong>

</td>

<td>
    {{ backup.display_time }}
</td>

<td>

<a
    class="button primary"
    href="/backup/load/{{ backup.name }}"
    onclick="return confirm('Restore snapshot?')"
>
    Restore Snapshot
</a>

<a
    class="button danger"
    href="/backup/delete/{{ backup.name }}"
    onclick="return confirm('Delete snapshot permanently?')"
>
    Delete
</a>

</td>

</tr>

{% else %}

<tr>

<td
    colspan="3"
    class="empty"
>
    No backup snapshots recorded.
</td>

</tr>

{% endfor %}

</tbody>

</table>

</div>

</div>

</div>

</body>

</html>
"""


MOH_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<link
    rel="icon"
    href="/favicon.png"
>

<title>
    Hold Music
</title>

""" + BASE_STYLE + r"""

</head>

<body>

""" + nav_html("moh") + r"""

<div class="main">

<div class="header">

<div>

<h1>
    Music On Hold
</h1>

<div class="subtitle">
    Manage audio tracks for hold music
</div>

</div>

<div class="hostname-pill">
    PBX:
    <strong>
        {{ hostname }}
    </strong>
</div>

</div>

<div class="content">

{% if message %}

<div class="info-box">
    {{ message }}
</div>

{% endif %}

{% if error %}

<div class="warning-box">
    <pre>{{ error }}</pre>
</div>

{% endif %}

<div class="card form">

<h2>
    Upload Audio File
</h2>

<p
    style="color:var(--text-subtle); font-size:13px;"
>
    Uploaded audio files are automatically resampled
    to mono PCM WAV at 44.1 kHz.
</p>

<form
    method="post"
    action="/moh/upload"
    enctype="multipart/form-data"
>

<input
    type="hidden"
    name="csrf_token"
    value="{{ csrf_token }}"
>

<label>
    Select Music Files
</label>

<input
    type="file"
    name="files"
    multiple
    required
    accept="audio/*"
>

<label
    style="display:flex; align-items:center; gap:8px; cursor:pointer;"
>

<input
    type="checkbox"
    name="make_default"
    value="1"
    style="width:auto; margin:0;"
    {% if moh_default %}
    checked
    {% endif %}
>

Set uploaded music as default hold class

</label>

<br>

<button
    class="button primary"
    type="submit"
>
    Upload & Convert
</button>

</form>

</div>

<div class="table-card">

<div class="table-header">
    Audio Library
</div>

<table>

<thead>

<tr>

<th>
    File Name
</th>

<th>
    Size
</th>

<th>
    Modified
</th>

<th>
    Actions
</th>

</tr>

</thead>

<tbody>

{% for item in files %}

<tr>

<td>
    <strong>
        {{ item.name }}
    </strong>
</td>

<td>
    {{ item.size|filesizeformat }}
</td>

<td>
    {{ item.modified }}
</td>

<td>

<a
    class="button"
    href="/moh/file?name={{ item.name|urlencode }}"
    target="_blank"
>
    ▶ Listen
</a>

<a
    class="button danger"
    href="/moh/delete/{{ item.name }}"
    onclick="return confirm('Delete audio file?')"
>
    Delete
</a>

</td>

</tr>

{% else %}

<tr>

<td
    colspan="4"
    class="empty"
>
    No hold music uploaded yet.
</td>

</tr>

{% endfor %}

</tbody>

</table>

</div>

</div>

</div>

</body>

</html>
"""


SETTINGS_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<link
    rel="icon"
    href="/favicon.png"
>

<title>
    Settings
</title>

""" + BASE_STYLE + r"""

</head>

<body>

""" + nav_html("settings") + r"""

<div class="main">

<div class="header">

<div>

<h1>
    Interface Settings
</h1>

<div class="subtitle">
    Recording preferences & system defaults
</div>

</div>

<div class="hostname-pill">
    PBX:
    <strong>
        {{ hostname }}
    </strong>
</div>

</div>

<div class="content">

<div class="card form">

<form method="post">

<input
    type="hidden"
    name="csrf_token"
    value="{{ csrf_token }}"
>

<h2>
    Call Recording Settings
</h2>

<label
    style="display:flex; align-items:center; gap:8px; cursor:pointer;"
>

<input
    type="checkbox"
    name="recording_enabled"
    value="1"
    style="width:auto; margin:0;"
    {% if recording_enabled %}
    checked
    {% endif %}
>

Enable Automatic Call Recording

</label>

<br>

<label>
    Recording Audio Format
</label>

<select
    name="recording_format"
>

<option
    value="wav"
    {% if recording_format == "wav" %}
    selected
    {% endif %}
>
    WAV (Uncompressed)
</option>

<option
    value="gsm"
    {% if recording_format == "gsm" %}
    selected
    {% endif %}
>
    GSM (Compressed)
</option>

</select>

<label>
    Retention Duration (Days)
</label>

<input
    type="number"
    name="recording_retention"
    value="{{ recording_retention }}"
    min="1"
>

<hr
    style="border-color:var(--border-color); margin:20px 0;"
>

<h2>
    Music On Hold Options
</h2>

<label
    style="display:flex; align-items:center; gap:8px; cursor:pointer;"
>

<input
    type="checkbox"
    name="moh_default"
    value="1"
    style="width:auto; margin:0;"
    {% if moh_default %}
    checked
    {% endif %}
>

Set Web UI music as default Asterisk hold music

</label>

<br>

<button
    class="button primary"
    type="submit"
>
    Save Settings
</button>

</form>

</div>

</div>

</div>

</body>

</html>
"""


SYSTEM_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<link
    rel="icon"
    href="/favicon.png"
>

<title>
    Asterisk Engine
</title>

""" + BASE_STYLE + r"""

</head>

<body>

""" + nav_html("system") + r"""

<div class="main">

<div class="header">

<div>

<h1>
    Asterisk Engine
</h1>

<div class="subtitle">
    Core Telephony Service Controls
</div>

</div>

<div class="hostname-pill">
    PBX Host:
    <strong>
        {{ hostname }}
    </strong>
</div>

</div>

<div class="content">

<div class="cards">

<div class="card">

<div class="card-title">
    Host Server
</div>

<div
    class="card-value"
    style="font-size:20px;"
>
    {{ hostname }}
</div>

</div>

<div class="card">

<div class="card-title">
    Engine Status
</div>

<div class="card-value">

{% if online %}

<span class="badge badge-success">

<span class="badge-dot pulse"></span>

Running

</span>

{% else %}

<span class="badge badge-danger">

<span class="badge-dot"></span>

Stopped

</span>

{% endif %}

</div>

</div>

</div>

<div class="card">

<h2>
    Service Controls
</h2>

<p
    style="color:var(--text-subtle); font-size:13px;"
>
    Restarting the Asterisk daemon will disconnect any ongoing calls.
</p>

<form
    method="post"
    action="/asterisk/restart"
>

<input
    type="hidden"
    name="csrf_token"
    value="{{ csrf_token }}"
>

<button
    class="button danger"
    type="submit"
    onclick="return confirm('Restart Asterisk system service?')"
>
    Restart Asterisk Engine
</button>

</form>

<br>

<a
    class="button"
    href="/logs"
>
    View Service Logs
</a>

</div>

</div>

</div>

</body>

</html>
"""


# ============================================================
# ROUTES
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"],
)
def login():
    if current_user():
        return redirect("/")

    error = ""

    next_url = request.args.get(
        "next",
        "/",
    )

    if (
        not next_url.startswith("/")
        or next_url.startswith("//")
    ):
        next_url = "/"

    if request.method == "POST":

        next_url = request.form.get(
            "next",
            "/",
        )

        if (
            not next_url.startswith("/")
            or next_url.startswith("//")
        ):
            next_url = "/"

        supplied = request.form.get(
            "csrf_token",
            "",
        )

        expected = session.get(
            "login_csrf_token"
        )

        if not expected:
            expected = secrets.token_urlsafe(32)
            session["login_csrf_token"] = expected

        if (
            not supplied
            or not secrets.compare_digest(
                expected,
                supplied,
            )
        ):
            session["login_csrf_token"] = (
                secrets.token_urlsafe(32)
            )

            return render_template_string(
                LOGIN_HTML,
                error=(
                    "Your login form expired. "
                    "Please try again."
                ),
                next_url=next_url,
                csrf_token=session[
                    "login_csrf_token"
                ],
            ), 400

        username = request.form.get(
            "username",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        client_ip = (
            request.remote_addr
            or "unknown"
        )

        now = time.time()

        failures = [
            t
            for t in LOGIN_FAILURES.get(
                client_ip,
                [],
            )
            if now - t < LOGIN_FAILURE_WINDOW
        ]

        if len(failures) >= LOGIN_FAILURE_LIMIT:

            error = (
                "Too many failed login attempts. "
                "Please wait a few minutes and try again."
            )

        else:

            user = get_user(
                username
            )

            if (
                user
                and check_password_hash(
                    user["password_hash"],
                    password,
                )
            ):

                LOGIN_FAILURES.pop(
                    client_ip,
                    None,
                )

                session.clear()

                session["username"] = (
                    user["username"]
                )

                session["csrf_token"] = (
                    secrets.token_urlsafe(32)
                )

                session.permanent = True

                return redirect(
                    next_url
                )

            failures.append(now)

            LOGIN_FAILURES[client_ip] = (
                failures
            )

            error = (
                "Invalid username or password."
            )

    token = session.get(
        "login_csrf_token"
    )

    if not token:
        token = secrets.token_urlsafe(32)

        session[
            "login_csrf_token"
        ] = token

    return render_template_string(
        LOGIN_HTML,
        error=error,
        next_url=next_url,
        csrf_token=token,
    )


@app.route(
    "/logout",
    methods=["POST"],
)
def logout():
    session.clear()
    return redirect("/login")


# ============================================================
# BRANDING ROUTES
# ============================================================

def _serve_branding_file(path):
    """
    Serve one of the fixed TPbx branding files.
    """
    if os.path.isfile(path):
        return send_file(path)

    return "", 404


@app.route("/fav.png")
@app.route("/favicon")
@app.route("/favicon.png")
def fav_png():
    return _serve_branding_file(
        BRANDING_FAVICON
    )


@app.route("/logo.png")
def logo_png():
    return _serve_branding_file(
        BRANDING_LOGO
    )


@app.route("/login.png")
@app.route("/login-background")
def login_png():
    return _serve_branding_file(
        BRANDING_LOGIN
    )


# ============================================================
# ACCOUNT ROUTES
# ============================================================

@app.route(
    "/account",
    methods=["GET", "POST"],
)
def account():
    user = current_user()

    error = ""
    message = ""

    if request.method == "POST":

        current_password = request.form.get(
            "current_password",
            "",
        )

        new_password = request.form.get(
            "new_password",
            "",
        )

        confirm_password = request.form.get(
            "confirm_password",
            "",
        )

        if not check_password_hash(
            user["password_hash"],
            current_password,
        ):

            error = (
                "Your current password is incorrect."
            )

        elif len(new_password) < 8:

            error = (
                "New password must be at least 8 characters long."
            )

        elif new_password != confirm_password:

            error = (
                "The new passwords do not match."
            )

        else:

            save_user(
                user["username"],
                password=new_password,
                role=user["role"],
                permissions=user["permissions"],
            )

            message = (
                "Password changed successfully."
            )

            user = current_user()

    return render_template_string(
        ACCOUNT_HTML,
        hostname=hostname(),
        user=user,
        error=error,
        message=message,
    )


@app.route(
    "/accounts",
    methods=["GET", "POST"],
)
def accounts():
    if request.method == "POST":

        ok, message = create_user(
            request.form.get(
                "username",
                "",
            ),
            request.form.get(
                "password",
                "",
            ),
            request.form.get(
                "role",
                "viewer",
            ),
        )

        if not ok:

            return render_template_string(
                ACCOUNTS_HTML,
                hostname=hostname(),
                users=list_users(),
                error=message,
                message="",
            )

        return redirect(
            "/accounts?message=Account+created"
        )

    return render_template_string(
        ACCOUNTS_HTML,
        hostname=hostname(),
        users=list_users(),
        error="",
        message=request.args.get(
            "message",
            "",
        ),
    )


@app.route(
    "/accounts/delete/<username>",
    methods=["POST"],
)
def accounts_delete(username):

    ok, message = delete_user(
        username
    )

    if not ok:
        return message, 400

    return redirect(
        "/accounts?message=Account+deleted"
    )


# ============================================================
# DASHBOARD ROUTES
# ============================================================

@app.route("/")
def index():
    return render_template_string(
        DASHBOARD_HTML,
        hostname=hostname(),
    )


@app.route("/api/status")
def api_status():

    ensure_asterisk_running()

    extension_data, error = (
        get_extension_data()
    )

    return jsonify({
        "hostname": hostname(),

        "asterisk": {
            "online": asterisk_online(),
        },

        "extensions": extension_data,

        "active_calls": get_active_calls(),

        "recording": (
            get_setting(
                "recording_enabled",
                "0",
            ) == "1"
        ),
    })


# ============================================================
# EXTENSION ROUTES
# ============================================================

@app.route("/extensions")
def extensions():

    extension_data, password_error = (
        get_extension_data()
    )

    return render_template_string(
        EXTENSIONS_HTML,
        hostname=hostname(),
        extensions=extension_data,
        password_error=password_error,
    )


@app.route(
    "/extensions/add",
    methods=["GET", "POST"],
)
def add_extension():

    if request.method == "GET":

        return render_template_string(
            EXTENSION_FORM,
            title="Add Extension",
            mode="add",
            extension="",
            display_name="",
            device_type="IP Phone",
        )

    extension = request.form.get(
        "extension",
        "",
    ).strip()

    password = request.form.get(
        "password",
        "",
    )

    display_name = request.form.get(
        "display_name",
        "",
    ).strip()

    device_type = request.form.get(
        "device_type",
        "IP Phone",
    )

    if not extension.isdigit():
        return (
            "Extension must contain only numbers.",
            400,
        )

    if not password:
        return (
            "A SIP password is required.",
            400,
        )

    existing, error = (
        get_all_extensions()
    )

    if error and not existing:
        return (
            "Could not get extensions:\n\n"
            + error,
            500,
        )

    if any(
        item["extension"] == extension
        for item in existing
    ):
        return (
            "That extension already exists.",
            400,
        )

    backup = create_backup()

    if not backup:
        return (
            "Could not create backup.",
            500,
        )

    ok, output = (
        add_extension_via_ext(
            extension,
            password,
        )
    )

    if not ok:
        return (
            "ext ADD failed:\n\n"
            + output,
            500,
        )

    conn = db()

    conn.execute(
        """
        INSERT INTO extension_settings
        (extension, display_name, device_type)
        VALUES (?, ?, ?)
        ON CONFLICT(extension)
        DO UPDATE SET
            display_name=excluded.display_name,
            device_type=excluded.device_type
        """,
        (
            extension,
            display_name or extension,
            device_type,
        ),
    )

    conn.commit()
    conn.close()

    return redirect(
        "/extensions"
    )


@app.route(
    "/extensions/edit/<extension>",
    methods=["GET", "POST"],
)
def edit_extension(extension):

    conn = db()

    row = conn.execute(
        """
        SELECT *
        FROM extension_settings
        WHERE extension=?
        """,
        (extension,),
    ).fetchone()

    conn.close()

    if request.method == "GET":

        return render_template_string(
            EXTENSION_FORM,
            title=(
                f"Edit Extension {extension}"
            ),
            mode="edit",
            extension=extension,
            display_name=(
                row["display_name"]
                if row
                else extension
            ),
            device_type=(
                row["device_type"]
                if row
                else ATA_EXTENSIONS.get(
                    extension,
                    "IP Phone",
                )
            ),
        )

    display_name = request.form.get(
        "display_name",
        "",
    ).strip()

    device_type = request.form.get(
        "device_type",
        "IP Phone",
    )

    conn = db()

    conn.execute(
        """
        INSERT INTO extension_settings
        (extension, display_name, device_type)
        VALUES (?, ?, ?)
        ON CONFLICT(extension)
        DO UPDATE SET
            display_name=excluded.display_name,
            device_type=excluded.device_type
        """,
        (
            extension,
            display_name or extension,
            device_type,
        ),
    )

    conn.commit()
    conn.close()

    return redirect(
        "/extensions"
    )


@app.route(
    "/extensions/delete/<extension>"
)
def delete_extension(extension):

    backup = create_backup()

    if not backup:
        return (
            "Could not create backup.",
            500,
        )

    ok, output = (
        remove_extension_via_ext(
            extension
        )
    )

    if not ok:
        return (
            "ext RM failed:\n\n"
            + output,
            500,
        )

    conn = db()

    conn.execute(
        "DELETE FROM extension_settings WHERE extension=?",
        (extension,),
    )

    conn.commit()
    conn.close()

    return redirect(
        "/extensions"
    )


# ============================================================
# CALLS, HISTORY & RECORDINGS
# ============================================================

@app.route("/calls")
def calls():

    return render_template_string(
        r"""
<!DOCTYPE html>
<html>

<head>

<link
    rel="icon"
    href="/favicon.png"
>

<title>
    Active Calls
</title>

""" + BASE_STYLE + r"""

<meta
    http-equiv="refresh"
    content="3"
>

</head>

<body>

""" + nav_html("calls") + r"""

<div class="main">

<div class="header">

<div>

<h1>
    Active Calls
</h1>

<div class="subtitle">
    Currently active telephony channels
</div>

</div>

<div class="hostname-pill">
    PBX:
    <strong>
        {{ hostname }}
    </strong>
</div>

</div>

<div class="content">

<div class="table-card">

<div class="table-header">
    Active Calls
</div>

{% if calls %}

<table>

<thead>

<tr>

<th>
    From
</th>

<th>
    To
</th>

<th>
    State
</th>

<th>
    Channels
</th>

<th>
    Linked ID
</th>

</tr>

</thead>

<tbody>

{% for call in calls %}

<tr>

<td>

<strong>
    {{ call.from }}
</strong>

</td>

<td>

<strong>
    {{ call.to }}
</strong>

</td>

<td>

<span
    class="badge badge-success"
>
    {{ call.state }}
</span>

</td>

<td>
    {{ call.channels }}
</td>

<td>

<code>
    {{ call.linked_id }}
</code>

</td>

</tr>

{% endfor %}

</tbody>

</table>

{% else %}

<div class="empty">
    No active calls in progress.
</div>

{% endif %}

</div>

</div>

</div>

</body>

</html>
        """,
        hostname=hostname(),
        calls=get_active_calls(),
    )


@app.route("/history")
def history():
    return render_template_string(
        HISTORY_HTML,
        hostname=hostname(),
    )


@app.route("/api/history")
def api_history():
    return jsonify(
        get_call_history()
    )


@app.route("/recording")
def get_recording():

    file_path = request.args.get(
        "file",
        "",
    )

    download = (
        request.args.get(
            "download",
            "0",
        )
        == "1"
    )

    if not file_path:
        return (
            "File path required.",
            400,
        )

    real_path = os.path.realpath(
        file_path
    )

    real_rec_dir = os.path.realpath(
        RECORDING_DIR
    )

    if (
        not real_path.startswith(
            real_rec_dir + os.sep
        )
        and real_path != real_rec_dir
    ):
        return (
            "Access denied.",
            403,
        )

    if not os.path.isfile(
        real_path
    ):
        return (
            "Recording file not found.",
            404,
        )

    return send_file(
        real_path,
        as_attachment=download,
    )


# ============================================================
# HOLD MUSIC ROUTES
# ============================================================

@app.route("/moh")
def moh():

    return render_template_string(
        MOH_HTML,
        hostname=hostname(),
        files=moh_files(),
        moh_class=MOH_CLASS,
        moh_dir=MOH_DIR,
        moh_default=(
            get_setting(
                "moh_default",
                "1",
            )
            == "1"
        ),
        message=request.args.get(
            "message",
            "",
        ),
        error=request.args.get(
            "error",
            "",
        ),
    )


@app.route(
    "/moh/upload",
    methods=["POST"],
)
def moh_upload():

    files = request.files.getlist(
        "files"
    )

    make_default = (
        request.form.get(
            "make_default"
        )
        == "1"
    )

    set_setting(
        "moh_default",
        "1"
        if make_default
        else "0",
    )

    count, errors = (
        upload_moh_files(files)
    )

    error_str = "\n".join(
        errors
    ) if errors else ""

    message = (
        f"Successfully uploaded and converted {count} file(s)."
        if count
        else ""
    )

    return redirect(
        f"/moh?message={message}&error={error_str}"
    )


@app.route(
    "/moh/delete/<name>"
)
def moh_delete(name):

    ok, error = delete_moh_file(
        name
    )

    if not ok:
        return redirect(
            f"/moh?error={error}"
        )

    return redirect(
        "/moh?message=File+deleted"
    )


@app.route("/moh/file")
def moh_file():

    name = request.args.get(
        "name",
        "",
    )

    safe = secure_filename(
        name
    )

    if not safe or safe != name:
        return (
            "Invalid file name.",
            400,
        )

    path = os.path.realpath(
        os.path.join(
            MOH_DIR,
            safe,
        )
    )

    if (
        not path.startswith(
            os.path.realpath(MOH_DIR)
            + os.sep
        )
        or not os.path.isfile(path)
    ):
        return (
            "File not found.",
            404,
        )

    return send_file(
        path
    )


# ============================================================
# SYSTEM & LOGS ROUTES
# ============================================================

def get_asterisk_logs(
    lines=LOG_LINES
):
    try:
        lines = max(
            1,
            min(
                int(lines),
                5000,
            ),
        )

    except Exception:
        lines = LOG_LINES

    try:
        result = subprocess.run(
            [
                "sudo",
                "-n",
                "/usr/bin/journalctl",
                "-u",
                ASTERISK_SERVICE,
                "-n",
                str(lines),
                "--no-pager",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

        if result.returncode == 0:
            return result.stdout

    except Exception:
        pass

    for log_file in (
        "/var/log/asterisk/full",
        "/var/log/asterisk/messages",
        "/var/log/asterisk/asterisk.log",
    ):
        if not os.path.isfile(
            log_file
        ):
            continue

        try:
            result = subprocess.run(
                [
                    "sudo",
                    "-n",
                    "tail",
                    "-n",
                    str(lines),
                    log_file,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                return result.stdout

        except Exception:
            pass

    return "No logs could be read."


def clear_asterisk_logs():
    """
    Rotates Asterisk journal logs and
    truncates Asterisk log files.
    """

    try:
        subprocess.run(
            [
                "sudo",
                "-n",
                "/usr/bin/journalctl",
                "--rotate",
            ],
            capture_output=True,
            timeout=10,
        )

        subprocess.run(
            [
                "sudo",
                "-n",
                "/usr/bin/journalctl",
                "--vacuum-time=1s",
            ],
            capture_output=True,
            timeout=10,
        )

        for log_path in (
            "/var/log/asterisk/full",
            "/var/log/asterisk/messages",
        ):
            if os.path.isfile(
                log_path
            ):
                subprocess.run(
                    [
                        "sudo",
                        "-n",
                        "truncate",
                        "-s",
                        "0",
                        log_path,
                    ],
                    timeout=5,
                )

        return (
            True,
            "Logs rotated successfully.",
        )

    except Exception as exc:
        return (
            False,
            f"Failed to rotate logs: {exc}",
        )


@app.route("/logs")
def logs():
    return render_template_string(
        LOGS_HTML,
        hostname=hostname(),
    )


@app.route("/api/logs")
def api_logs():
    return jsonify({
        "logs": get_asterisk_logs(
            LOG_LINES
        )
    })


@app.route(
    "/api/logs/clear",
    methods=["POST"],
)
def api_logs_clear():

    success, message = (
        clear_asterisk_logs()
    )

    return jsonify({
        "success": success,
        "message": message,
    })


@app.route("/system")
def system_page():
    return render_template_string(
        SYSTEM_HTML,
        hostname=hostname(),
        online=asterisk_online(),
    )


@app.route(
    "/asterisk/restart",
    methods=["POST"],
)
@app.route(
    "/api/asterisk/restart",
    methods=["POST"],
)
def asterisk_restart():

    success, output = (
        restart_asterisk()
    )

    if request.path.startswith(
        "/api/"
    ):
        return jsonify({
            "success": success,
            "message": (
                "Asterisk restarted successfully."
                if success
                else output
            ),
        })

    return redirect(
        "/system"
    )


@app.route(
    "/settings",
    methods=["GET", "POST"],
)
def settings():

    if request.method == "POST":

        recording_enabled = (
            "1"
            if request.form.get(
                "recording_enabled"
            ) == "1"
            else "0"
        )

        recording_format = (
            request.form.get(
                "recording_format",
                "wav",
            )
        )

        recording_retention = (
            request.form.get(
                "recording_retention",
                "30",
            )
        )

        moh_default = (
            "1"
            if request.form.get(
                "moh_default"
            ) == "1"
            else "0"
        )

        set_setting(
            "recording_enabled",
            recording_enabled,
        )

        set_setting(
            "recording_format",
            recording_format,
        )

        set_setting(
            "recording_retention",
            recording_retention,
        )

        set_setting(
            "moh_default",
            moh_default,
        )

        set_moh_default(
            moh_default == "1"
        )

        return redirect(
            "/settings"
        )

    return render_template_string(
        SETTINGS_HTML,
        hostname=hostname(),
        recording_enabled=(
            get_setting(
                "recording_enabled",
                "0",
            )
            == "1"
        ),
        recording_format=get_setting(
            "recording_format",
            "wav",
        ),
        recording_retention=get_setting(
            "recording_retention",
            "30",
        ),
        moh_default=(
            get_setting(
                "moh_default",
                "1",
            )
            == "1"
        ),
    )


# ============================================================
# BACKUPS ROUTES
# ============================================================

@app.route("/backups")
def backups():

    return render_template_string(
        BACKUPS_HTML,
        hostname=hostname(),
        backups=list_backups(),
    )


@app.route("/backup/create")
def backup_create():

    path = create_backup()

    if not path:
        return (
            "Failed to create backup.",
            500,
        )

    return redirect(
        "/backups"
    )


@app.route(
    "/backup/load/<name>"
)
def backup_load(name):

    ok, message = (
        restore_backup(name)
    )

    if not ok:
        return (
            message,
            500,
        )

    return redirect(
        "/backups"
    )


@app.route(
    "/backup/delete/<name>"
)
def backup_delete(name):

    delete_backup(name)

    return redirect(
        "/backups"
    )


# ============================================================
# MAIN ENTRY POINT
# ============================================================

if __name__ == "__main__":

    init_db()

    ensure_secret_key()

    remember_existing_moh_default()

    ensure_moh_directories()

    write_moh_config(
        make_default=(
            get_setting(
                "moh_default",
                "1",
            )
            == "1"
        )
    )

    ensure_asterisk_running()

    ensure_upd_running()

    app.run(
        host=HOST,
        port=PORT,
        debug=False,
    )