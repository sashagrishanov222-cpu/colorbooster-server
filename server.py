import os
import json
import sqlite3
import hashlib
import secrets
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from pathlib import Path

# Render передаёт PORT автоматически.
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8765"))

DB = Path(__file__).with_name("colorbooster.db")

# Для теста. Перед реальным использованием обязательно поменяй.
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "1234")

SESSIONS = set()


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row

    c.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            hwid TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cols = {
        r["name"]
        for r in c.execute("PRAGMA table_info(users)").fetchall()
    }

    if "status" not in cols:
        c.execute(
            "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'"
        )

    c.commit()
    return c


def password_hash(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def page(title, body):
    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background:#101216;
    color:#eee;
    margin:0;
}}
.box {{
    max-width:1100px;
    margin:40px auto;
    background:#1b1e24;
    padding:28px;
    border-radius:14px;
    box-shadow:0 10px 35px #0006;
}}
h1 {{ margin-top:0; }}
input {{
    box-sizing:border-box;
    padding:10px;
    border-radius:7px;
    border:1px solid #444;
    background:#111;
    color:#fff;
}}
input.full {{
    width:100%;
    margin:7px 0 15px;
}}
button,a.btn {{
    display:inline-block;
    padding:9px 14px;
    border:0;
    border-radius:7px;
    background:#4d7cff;
    color:white;
    text-decoration:none;
    cursor:pointer;
}}
button.danger {{ background:#b63b3b; }}
button.gray {{ background:#555; }}
table {{
    width:100%;
    border-collapse:collapse;
    margin-top:18px;
}}
td,th {{
    padding:9px;
    border-bottom:1px solid #383c44;
    text-align:left;
    vertical-align:top;
}}
code {{ word-break:break-all; }}
.badge {{
    padding:4px 8px;
    border-radius:12px;
    background:#285d39;
}}
.blocked {{ background:#7b2e2e; }}
.actions {{
    display:flex;
    gap:6px;
    flex-wrap:wrap;
}}
.actions form {{ display:inline; }}
.muted {{ color:#aaa; }}
</style>
</head>
<body>
<div class="box">{body}</div>
</body>
</html>"""


def is_admin(handler):
    cookie = handler.headers.get("Cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("cb_admin="):
            token = part.split("=", 1)[1]
            return token in SESSIONS
    return False


class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(fmt % args)

    def send_html(self, content, status=200, extra_headers=None):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))

        if extra_headers:
            for key, value in extra_headers:
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

    def read_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def read_json(self):
        return json.loads(self.read_body().decode("utf-8"))

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            self.send_html(page(
                "ColorBooster",
                """
                <h1>ColorBooster</h1>
                <p>Сервер регистрации и авторизации.</p>
                <p>
                    <a class="btn" href="/register">Регистрация</a>
                    <a class="btn" href="/admin">Админ-панель</a>
                </p>
                """
            ))
            return

        if path == "/register":
            self.send_html(page(
                "Регистрация",
                """
                <h1>Регистрация</h1>
                <form method="post" action="/register">
                    <label>Почта</label>
                    <input class="full" name="email" type="email" required>

                    <label>Пароль</label>
                    <input class="full" name="password"
                           type="password" minlength="6" required>

                    <button>Зарегистрироваться</button>
                </form>
                <p><a href="/">Назад</a></p>
                """
            ))
            return

        if path == "/admin/login":
            self.send_html(page(
                "Вход в админ-панель",
                """
                <h1>Админ-панель</h1>
                <form method="post" action="/admin/login">
                    <label>Логин</label>
                    <input class="full" name="user" required>

                    <label>Пароль</label>
                    <input class="full" name="password"
                           type="password" required>

                    <button>Войти</button>
                </form>
                """
            ))
            return

        if path == "/admin/logout":
            token = ""
            for part in self.headers.get("Cookie", "").split(";"):
                part = part.strip()
                if part.startswith("cb_admin="):
                    token = part.split("=", 1)[1]

            SESSIONS.discard(token)

            self.send_html(
                page(
                    "Выход",
                    '<h1>Вы вышли</h1><a class="btn" href="/">На главную</a>'
                ),
                extra_headers=[
                    ("Set-Cookie", "cb_admin=; Max-Age=0; Path=/")
                ]
            )
            return

        if path == "/admin":
            if not is_admin(self):
                self.send_html(
                    page(
                        "Админ-панель",
                        '<h1>Требуется вход</h1>'
                        '<a class="btn" href="/admin/login">Войти</a>'
                    ),
                    401
                )
                return

            self.render_admin()
            return

        self.send_response(404)
        self.end_headers()

    def render_admin(self):
        c = db()
        rows = c.execute(
            """
            SELECT id,email,hwid,status,first_seen,last_seen
            FROM users
            ORDER BY id DESC
            """
        ).fetchall()
        c.close()

        trs = ""

        for row in rows:
            blocked = row["status"] == "blocked"

            status = (
                '<span class="badge blocked">Заблокирован</span>'
                if blocked
                else '<span class="badge">Активен</span>'
            )

            hwid = html.escape(row["hwid"] or "не привязан")
            toggle_text = "Разблокировать" if blocked else "Заблокировать"
            toggle_class = "" if blocked else "danger"

            trs += f"""
            <tr>
                <td>{row["id"]}</td>
                <td>{html.escape(row["email"])}</td>
                <td><code>{hwid}</code></td>
                <td>{status}</td>
                <td>{row["first_seen"]}</td>
                <td>{row["last_seen"]}</td>
                <td>
                    <div class="actions">
                        <form method="post" action="/admin/toggle">
                            <input type="hidden" name="id"
                                   value="{row["id"]}">
                            <button class="{toggle_class}">
                                {toggle_text}
                            </button>
                        </form>

                        <form method="post" action="/admin/reset-hwid">
                            <input type="hidden" name="id"
                                   value="{row["id"]}">
                            <button class="gray">
                                Сбросить HWID
                            </button>
                        </form>
                    </div>

                    <form method="post"
                          action="/admin/set-hwid"
                          style="margin-top:7px">
                        <input type="hidden" name="id"
                               value="{row["id"]}">
                        <input name="hwid"
                               placeholder="Новый HWID">
                        <button>Установить HWID</button>
                    </form>
                </td>
            </tr>
            """

        if not trs:
            trs = """
            <tr>
                <td colspan="7">Пользователей пока нет.</td>
            </tr>
            """

        body = f"""
        <h1>Админ-панель ColorBooster</h1>

        <p>
            Пользователей: <b>{len(rows)}</b>
            &nbsp;
            <a class="btn" href="/admin/logout">Выйти</a>
        </p>

        <table>
            <tr>
                <th>ID</th>
                <th>Почта</th>
                <th>HWID</th>
                <th>Статус</th>
                <th>Первый запуск</th>
                <th>Последний запуск</th>
                <th>Управление</th>
            </tr>
            {trs}
        </table>

        <p class="muted">
            Сброс HWID отвязывает аккаунт.
            При следующем успешном входе текущий компьютер будет привязан.
        </p>
        """

        self.send_html(page("Админ-панель", body))

    def do_POST(self):
        path = urlparse(self.path).path

        # API входа ColorBooster.
        if path == "/api/login":
            try:
                data = self.read_json()
            except Exception:
                return self.send_json(
                    {"error": "Некорректный JSON"},
                    400
                )

            email = str(data.get("email", "")).strip().lower()
            password = str(data.get("password", ""))
            hwid = str(data.get("hwid", "")).strip()

            if not email or not password or not hwid:
                return self.send_json(
                    {"error": "Не хватает данных"},
                    400
                )

            c = db()
            row = c.execute(
                "SELECT * FROM users WHERE email=?",
                (email,)
            ).fetchone()

            if (
                not row
                or not secrets.compare_digest(
                    row["password_hash"],
                    password_hash(password)
                )
            ):
                c.close()
                return self.send_json(
                    {"error": "Неверная почта или пароль"},
                    401
                )

            if row["status"] == "blocked":
                c.close()
                return self.send_json(
                    {"error": "Аккаунт заблокирован администратором"},
                    403
                )

            # Если HWID уже есть, другой компьютер не допускаем.
            if row["hwid"]:
                if not secrets.compare_digest(row["hwid"], hwid):
                    c.close()
                    return self.send_json(
                        {
                            "error":
                            "HWID этого компьютера не совпадает "
                            "с привязанным HWID"
                        },
                        403
                    )

            c.execute(
                """
                UPDATE users
                SET hwid=?, last_seen=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (hwid, row["id"])
            )

            c.commit()
            c.close()

            return self.send_json(
                {"ok": True, "hwid": hwid}
            )

        # Регистрация через сайт.
        if path == "/register":
            query = parse_qs(
                self.read_body().decode("utf-8")
            )

            email = query.get("email", [""])[0].strip().lower()
            password = query.get("password", [""])[0]

            if not email or "@" not in email:
                return self.send_html(
                    page(
                        "Ошибка",
                        '<h1>Введите корректную почту</h1>'
                        '<a href="/register">Назад</a>'
                    ),
                    400
                )

            if len(password) < 6:
                return self.send_html(
                    page(
                        "Ошибка",
                        '<h1>Пароль должен быть не короче 6 символов</h1>'
                        '<a href="/register">Назад</a>'
                    ),
                    400
                )

            try:
                c = db()
                c.execute(
                    """
                    INSERT INTO users(email,password_hash)
                    VALUES(?,?)
                    """,
                    (email, password_hash(password))
                )
                c.commit()
                c.close()

            except sqlite3.IntegrityError:
                return self.send_html(
                    page(
                        "Ошибка",
                        '<h1>Эта почта уже зарегистрирована</h1>'
                        '<a href="/register">Назад</a>'
                    ),
                    409
                )

            self.send_html(
                page(
                    "Готово",
                    """
                    <h1>Регистрация завершена</h1>
                    <p>
                        Теперь можно войти в ColorBooster
                        с этой почтой и паролем.
                    </p>
                    <a class="btn" href="/admin">
                        Открыть админку
                    </a>
                    """
                )
            )
            return

        # Вход администратора.
        if path == "/admin/login":
            query = parse_qs(
                self.read_body().decode("utf-8")
            )

            submitted_user = query.get("user", [""])[0].strip()
            submitted_password = query.get("password", [""])[0].strip()

            if (
                not secrets.compare_digest(
                    submitted_user,
                    ADMIN_USER
                )
                or not secrets.compare_digest(
                    submitted_password,
                    ADMIN_PASSWORD
                )
            ):
                return self.send_html(
                    page(
                        "Ошибка",
                        '<h1>Неверный логин или пароль</h1>'
                        '<a href="/admin/login">Назад</a>'
                    ),
                    401
                )

            token = secrets.token_urlsafe(32)
            SESSIONS.add(token)

            self.send_response(303)
            self.send_header("Location", "/admin")
            self.send_header(
                "Set-Cookie",
                f"cb_admin={token}; HttpOnly; Path=/; SameSite=Lax"
            )
            self.end_headers()
            return

        # Все остальные admin POST требуют авторизации.
        if path.startswith("/admin/") and not is_admin(self):
            return self.send_html(
                page(
                    "Ошибка",
                    '<h1>Сначала войдите в админ-панель</h1>'
                    '<a href="/admin/login">Войти</a>'
                ),
                401
            )

        if path in (
            "/admin/toggle",
            "/admin/reset-hwid",
            "/admin/set-hwid"
        ):
            query = parse_qs(
                self.read_body().decode("utf-8")
            )

            try:
                user_id = int(query.get("id", ["0"])[0])
            except ValueError:
                user_id = 0

            c = db()
            row = c.execute(
                "SELECT * FROM users WHERE id=?",
                (user_id,)
            ).fetchone()

            if not row:
                c.close()
                return self.send_html(
                    page(
                        "Ошибка",
                        '<h1>Пользователь не найден</h1>'
                        '<a href="/admin">Назад</a>'
                    ),
                    404
                )

            if path == "/admin/toggle":
                new_status = (
                    "blocked"
                    if row["status"] != "blocked"
                    else "active"
                )
                c.execute(
                    "UPDATE users SET status=? WHERE id=?",
                    (new_status, user_id)
                )

            elif path == "/admin/reset-hwid":
                c.execute(
                    "UPDATE users SET hwid=NULL WHERE id=?",
                    (user_id,)
                )

            else:
                new_hwid = query.get("hwid", [""])[0].strip()

                if not new_hwid:
                    c.close()
                    return self.send_html(
                        page(
                            "Ошибка",
                            '<h1>HWID не введён</h1>'
                            '<a href="/admin">Назад</a>'
                        ),
                        400
                    )

                c.execute(
                    "UPDATE users SET hwid=? WHERE id=?",
                    (new_hwid, user_id)
                )

            c.commit()
            c.close()

            self.send_response(303)
            self.send_header("Location", "/admin")
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    db().close()

    print(f"ColorBooster server: {HOST}:{PORT}")
    print("Register: /register")
    print("Admin: /admin")

    ThreadingHTTPServer(
        (HOST, PORT),
        Handler
    ).serve_forever()
