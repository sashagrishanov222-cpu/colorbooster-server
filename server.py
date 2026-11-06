import os
import json
import html
import hmac
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from http.cookies import SimpleCookie

import psycopg

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8765"))
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
LICENSE_SECRET = os.environ.get("LICENSE_SECRET", "")
SESSIONS = set()


def now():
    return datetime.now(timezone.utc)


def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    return psycopg.connect(DATABASE_URL)


def password_hash(password):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        b"ColorBooster-2026",
        120000
    ).hex()


def hwid_digest(hwid):
    return hashlib.sha256(hwid.strip().encode()).hexdigest()


def make_purchase_code():
    return "CB-PURCHASE-" + secrets.token_hex(4).upper()


def make_license(email, expires_at):
    if not LICENSE_SECRET:
        raise RuntimeError("LICENSE_SECRET is not configured")

    expiry = 0xFFFFFFFF if expires_at is None else int(expires_at.timestamp())
    payload = f"{email.lower()}|{expiry}"

    signature = hmac.new(
        LICENSE_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()[:16].upper()

    return f"CB-{expiry:08X}-{signature}"


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                hwid TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                expires_at TIMESTAMPTZ,
                activation_key TEXT,
                first_seen TIMESTAMPTZ DEFAULT NOW(),
                last_seen TIMESTAMPTZ
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS purchase_codes (
                id BIGSERIAL PRIMARY KEY,
                code TEXT UNIQUE NOT NULL,
                duration_days INTEGER DEFAULT 30,
                used BOOLEAN DEFAULT FALSE,
                used_by TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                used_at TIMESTAMPTZ
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS banned_devices (
                id BIGSERIAL PRIMARY KEY,
                hwid TEXT NOT NULL,
                hwid_hash TEXT UNIQUE NOT NULL,
                user_email TEXT,
                reason TEXT DEFAULT '',
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)


def page(title, body):
    return (
        "<!DOCTYPE html><html lang='ru'><head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<style>"
        "body{background:#0b1020;color:#eee;font-family:Arial;margin:30px}"
        ".panel{background:#172139;padding:20px;border-radius:12px;margin:15px 0}"
        "input,select{padding:10px;margin:5px;background:#101a30;color:white;border:1px solid #405070;border-radius:6px}"
        "button,.btn{padding:10px 14px;background:#3978e8;color:white;border:0;border-radius:6px;cursor:pointer;text-decoration:none}"
        ".danger{background:#bd354b}table{width:100%;border-collapse:collapse;overflow:auto}"
        "td,th{padding:9px;border-bottom:1px solid #35415b;text-align:left}"
        "a{color:#8bb8ff}form{display:inline-block;margin:3px}"
        "</style></head><body>"
        "<h2>ColorBooster</h2>"
        + body +
        "</body></html>"
    )


class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(fmt % args)

    def send_html(self, content, status=200, headers=None):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))

        if headers:
            for key, value in headers.items():
                self.send_header(key, value)

        self.end_headers()
        self.wfile.write(data)

    def send_json(self, obj, status=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, url, headers=None):
        self.send_response(303)
        self.send_header("Location", url)

        if headers:
            for key, value in headers.items():
                self.send_header(key, value)

        self.end_headers()

    def read_body(self):
        length = min(int(self.headers.get("Content-Length", "0")), 100000)
        raw = self.rfile.read(length).decode("utf-8", "replace")

        if "application/json" in self.headers.get("Content-Type", ""):
            try:
                return json.loads(raw)
            except Exception:
                return {}

        return {
            key: values[0]
            for key, values in parse_qs(raw).items()
        }

    def is_admin(self):
        cookie = SimpleCookie()

        try:
            cookie.load(self.headers.get("Cookie", ""))
            return cookie["cb_admin"].value in SESSIONS
        except Exception:
            return False

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/health":
            return self.send_json({"ok": True})

        if path == "/":
            return self.send_html(page(
                "ColorBooster",
                "<div class='panel'><h1>ColorBooster API работает</h1>"
                "<a href='/admin'>Админ-панель</a></div>"
            ))

        if path == "/admin/login":
            return self.send_html(page(
                "Вход",
                "<div class='panel'><h1>Вход администратора</h1>"
                "<form method='post' action='/admin/login'>"
                "<input name='username' placeholder='Логин' required>"
                "<input name='password' type='password' placeholder='Пароль' required>"
                "<button>Войти</button></form></div>"
            ))

        if path.startswith("/admin") and not self.is_admin():
            return self.redirect("/admin/login")

        if path == "/admin":
            with db() as conn:
                users = conn.execute(
                    "SELECT id,email,hwid,status,expires_at FROM users ORDER BY id DESC"
                ).fetchall()

                banned = conn.execute(
                    "SELECT id,hwid,user_email,reason FROM banned_devices ORDER BY id DESC"
                ).fetchall()

                codes = conn.execute(
                    "SELECT id,code,duration_days,used FROM purchase_codes ORDER BY id DESC"
                ).fetchall()

            rows = ""

            for uid, email, hwid, status, expiry in users:
                rows += (
                    "<tr>"
                    f"<td>{uid}</td>"
                    f"<td>{html.escape(email)}</td>"
                    f"<td>{html.escape(hwid or 'Нет')}</td>"
                    f"<td>{html.escape(status)}</td>"
                    f"<td>{html.escape(str(expiry or 'Навсегда'))}</td>"
                    "<td>"
                    f"<form method='post' action='/admin/toggle'><input type='hidden' name='id' value='{uid}'><button>Статус</button></form>"
                    f"<form method='post' action='/admin/reset-hwid'><input type='hidden' name='id' value='{uid}'><button>Сбросить HWID</button></form>"
                    f"<form method='post' action='/admin/ban-hwid'><input type='hidden' name='id' value='{uid}'><button class='danger'>Бан HWID</button></form>"
                    "</td></tr>"
                )

            banned_rows = ""

            for bid, hwid, email, reason in banned:
                banned_rows += (
                    "<tr>"
                    f"<td>{html.escape(hwid)}</td>"
                    f"<td>{html.escape(email or '')}</td>"
                    f"<td>{html.escape(reason or '')}</td>"
                    "<td>"
                    f"<form method='post' action='/admin/unban-hwid'><input type='hidden' name='id' value='{bid}'><button>Разбанить</button></form>"
                    "</td></tr>"
                )

            code_rows = ""

            for cid, code, days, used in codes:
                code_rows += (
                    "<tr>"
                    f"<td>{html.escape(code)}</td>"
                    f"<td>{days}</td>"
                    f"<td>{'Да' if used else 'Нет'}</td>"
                    f"<td><form method='post' action='/admin/delete-purchase'><input type='hidden' name='id' value='{cid}'><button class='danger'>Удалить</button></form></td>"
                    "</tr>"
                )

            body = (
                "<div class='panel'><h1>Админ-панель</h1>"
                "<form method='post' action='/admin/logout'><button>Выйти</button></form>"
                "<h2>Пользователи</h2>"
                "<table><tr><th>ID</th><th>Email</th><th>HWID</th><th>Статус</th><th>Срок</th><th>Действия</th></tr>"
                + rows +
                "</table></div>"
                "<div class='panel'><h2>Заблокированные устройства</h2>"
                "<table><tr><th>HWID</th><th>Email</th><th>Причина</th><th></th></tr>"
                + banned_rows +
                "</table></div>"
                "<div class='panel'><h2>Коды покупки</h2>"
                "<form method='post' action='/admin/create-purchase'>"
                "<select name='duration_days'>"
                "<option value='7'>7 дней</option>"
                "<option value='14'>14 дней</option>"
                "<option value='30' selected>30 дней</option>"
                "<option value='0'>Навсегда</option>"
                "</select><button>Создать код</button></form>"
                "<table><tr><th>Код</th><th>Дней</th><th>Использован</th><th></th></tr>"
                + code_rows +
                "</table></div>"
            )

            return self.send_html(page("Админка", body))

        return self.send_html(page("404", "<h1>Страница не найдена</h1>"), 404)

    def do_POST(self):
        path = urlparse(self.path).path
        data = self.read_body()

        if path == "/api/login":
            email = str(data.get("email", "")).strip().lower()
            password = str(data.get("password", ""))
            hwid = str(data.get("hwid", "")).strip()

            if not email or not password or not hwid:
                return self.send_json({"ok": False, "error": "missing_fields"}, 400)

            with db() as conn:
                banned = conn.execute(
                    "SELECT 1 FROM banned_devices WHERE hwid_hash=%s",
                    (hwid_digest(hwid),)
                ).fetchone()

                if banned:
                    return self.send_json({"ok": False, "error": "device_banned"}, 403)

                user = conn.execute(
                    "SELECT id,password_hash,hwid,status,expires_at,activation_key FROM users WHERE email=%s",
                    (email,)
                ).fetchone()

                if not user or not hmac.compare_digest(
                    user[1], password_hash(password)
                ):
                    return self.send_json({"ok": False, "error": "invalid_credentials"}, 401)

                uid, saved_hwid, status, expiry, license_key = (
                    user[0], user[2], user[3], user[4], user[5]
                )

                if status != "active":
                    return self.send_json({"ok": False, "error": "account_blocked"}, 403)

                if expiry and expiry <= now():
                    return self.send_json({"ok": False, "error": "license_expired"}, 403)

                if saved_hwid and saved_hwid != hwid:
                    return self.send_json({"ok": False, "error": "hwid_mismatch"}, 403)

                conn.execute(
                    "UPDATE users SET hwid=COALESCE(hwid,%s),last_seen=NOW() WHERE id=%s",
                    (hwid, uid)
                )

            return self.send_json({
                "ok": True,
                "license": license_key or "",
                "expires_at": expiry.isoformat() if expiry else None
            })

        if path == "/admin/login":
            username = str(data.get("username", ""))
            password = str(data.get("password", ""))

            if (
                username == ADMIN_USER
                and ADMIN_PASSWORD
                and hmac.compare_digest(password, ADMIN_PASSWORD)
            ):
                token = secrets.token_urlsafe(32)
                SESSIONS.add(token)

                return self.redirect(
                    "/admin",
                    {"Set-Cookie": f"cb_admin={token}; Path=/; HttpOnly; Secure; SameSite=Lax"}
                )

            return self.send_html(page("Ошибка", "<h1>Неверный логин или пароль</h1>"), 401)

        if path.startswith("/admin/") and not self.is_admin():
            return self.send_html(page("Ошибка", "<h1>Требуется вход</h1>"), 401)

        def form_int(name):
            try:
                return int(data.get(name, 0))
            except (ValueError, TypeError):
                return 0

        if path == "/admin/logout":
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie", ""))

            try:
                SESSIONS.discard(cookie["cb_admin"].value)
            except Exception:
                pass

            return self.redirect(
                "/admin/login",
                {"Set-Cookie": "cb_admin=; Path=/; Max-Age=0; HttpOnly; Secure"}
            )

        if path == "/admin/create-purchase":
            days = form_int("duration_days")

            if days not in (0, 7, 14, 30):
                return self.send_html(page("Ошибка", "<h1>Неверный срок</h1>"), 400)

            code = make_purchase_code()

            with db() as conn:
                conn.execute(
                    "INSERT INTO purchase_codes(code,duration_days) VALUES(%s,%s)",
                    (code, days)
                )

            return self.send_html(page(
                "Код создан",
                f"<div class='panel'><h1>Код создан</h1><h2>{html.escape(code)}</h2><a href='/admin'>Назад</a></div>"
            ))

        if path == "/admin/delete-purchase":
            with db() as conn:
                conn.execute(
                    "DELETE FROM purchase_codes WHERE id=%s",
                    (form_int("id"),)
                )
            return self.redirect("/admin")

        if path == "/admin/toggle":
            with db() as conn:
                conn.execute("""
                    UPDATE users SET status =
                    CASE WHEN status='blocked' THEN 'active' ELSE 'blocked' END
                    WHERE id=%s
                """, (form_int("id"),))
            return self.redirect("/admin")

        if path == "/admin/reset-hwid":
            with db() as conn:
                conn.execute(
                    "UPDATE users SET hwid=NULL WHERE id=%s",
                    (form_int("id"),)
                )
            return self.redirect("/admin")

        if path == "/admin/ban-hwid":
            with db() as conn:
                user = conn.execute(
                    "SELECT email,hwid FROM users WHERE id=%s",
                    (form_int("id"),)
                ).fetchone()

                if user and user[1]:
                    conn.execute("""
                        INSERT INTO banned_devices(hwid,hwid_hash,user_email,reason)
                        VALUES(%s,%s,%s,%s)
                        ON CONFLICT(hwid_hash) DO UPDATE SET
                        user_email=EXCLUDED.user_email,
                        reason=EXCLUDED.reason
                    """, (
                        user[1],
                        hwid_digest(user[1]),
                        user[0],
                        "Заблокировано администратором"
                    ))

            return self.redirect("/admin")

        if path == "/admin/unban-hwid":
            with db() as conn:
                conn.execute(
                    "DELETE FROM banned_devices WHERE id=%s",
                    (form_int("id"),)
                )
            return self.redirect("/admin")

        return self.send_json({"ok": False, "error": "not_found"}, 404)


if __name__ == "__main__":
    if not ADMIN_PASSWORD:
        raise RuntimeError("Set ADMIN_PASSWORD in Render Environment")

    init_db()

    print(f"ColorBooster server listening on {HOST}:{PORT}")

    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.serve_forever()
