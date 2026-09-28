import os
import html
import json
import secrets
import hashlib
import base64

from datetime import datetime, timezone, timedelta, date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import psycopg


HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8765"))

DATABASE_URL = os.environ.get("DATABASE_URL", "")

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "change-me")

# ============================================
# НАСТРОЙКИ ЛИЦЕНЗИЙ
# ============================================

# Срок автоматически выдаваемой лицензии.
# 365 = 1 год.
LICENSE_DAYS = 365

# ДОЛЖЕН СОВПАДАТЬ С main.cpp
LICENSE_SECRET = "CB_INTERNAL_2026_SECRET_7F3A91"

SESSIONS = set()


# ============================================
# DATABASE
# ============================================

def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")

    return psycopg.connect(DATABASE_URL)


def init_db():
    with db() as c:

        c.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id BIGSERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                hwid TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                expires_at TIMESTAMPTZ,
                activation_key TEXT,
                first_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        c.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
        """)

        c.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ
        """)

        c.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS activation_key TEXT
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS activation_keys(
                id BIGSERIAL PRIMARY KEY,
                key TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMPTZ,
                max_uses INTEGER NOT NULL DEFAULT 1,
                uses INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)


# ============================================
# PASSWORD
# ============================================

def ph(password):
    data = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        b"ColorBooster-2026",
        120000
    )

    return base64.b64encode(data).decode()


# ============================================
# DATE
# ============================================

def dt(value):
    value = (value or "").strip()

    if not value:
        return None

    try:
        return datetime.strptime(
            value,
            "%Y-%m-%dT%H:%M"
        ).replace(tzinfo=timezone.utc)

    except ValueError:
        return None


def fmt(value):

    if value is None:
        return "—"

    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M UTC")

    return str(value)


# ============================================
# LICENSE GENERATOR
# ============================================

def current_days_since_2020():

    today = date.today()
    base = date(2020, 1, 1)

    return (today - base).days


def make_license(days=LICENSE_DAYS):

    expiry_days = current_days_since_2020() + days

    # Именно 8 HEX символов, как ожидает main.cpp
    expiry_hex = f"{expiry_days:08X}"

    # 16 случайных HEX символов
    random_part = secrets.token_hex(8).upper()

    payload = expiry_hex + random_part

    # ДОЛЖНО совпадать с main.cpp:
    # SHA256(LICENSE_SECRET + expiryHex + random)
    digest = hashlib.sha256(
        (LICENSE_SECRET + payload).encode("utf-8")
    ).hexdigest().upper()

    check = digest[:8]

    return f"CB-{expiry_hex}-{random_part}-{check}"


# ============================================
# HTML
# ============================================

def page(title, body):

    return f"""<!doctype html>
<html lang="ru">

<head>

<meta charset="utf-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>{html.escape(title)}</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    font-family: Arial, sans-serif;
    background: #101216;
    color: #eee;
    margin: 0;
}}

.box {{
    max-width: 1250px;
    margin: 40px auto;
    background: #1b1e24;
    padding: 28px;
    border-radius: 14px;
}}

.card {{
    background: #15181d;
    border: 1px solid #30343c;
    border-radius: 12px;
    padding: 20px;
    margin: 18px 0;
}}

input {{
    box-sizing: border-box;
    padding: 10px;
    border-radius: 7px;
    border: 1px solid #444;
    background: #111;
    color: #fff;
}}

.full {{
    width: 100%;
    margin: 7px 0 15px;
}}

button,
.btn {{
    display: inline-block;
    padding: 10px 15px;
    border: 0;
    border-radius: 7px;
    background: #4d7cff;
    color: #fff;
    text-decoration: none;
    cursor: pointer;
}}

.green {{
    background: #287a45;
}}

.danger {{
    background: #b63b3b;
}}

.gray {{
    background: #555;
}}

.license {{
    display: block;
    background: #0d0f13;
    border: 1px solid #4d7cff;
    padding: 18px;
    border-radius: 10px;
    font-size: 20px;
    font-family: Consolas, monospace;
    word-break: break-all;
    color: #fff;
    margin: 15px 0;
}}

.muted {{
    color: #aaa;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 18px;
}}

td,
th {{
    padding: 8px;
    border-bottom: 1px solid #383c44;
    text-align: left;
    vertical-align: top;
}}

code {{
    word-break: break-all;
}}

.badge {{
    padding: 4px 8px;
    border-radius: 12px;
    background: #285d39;
}}

.blocked {{
    background: #7b2e2e;
}}

.expired {{
    background: #765b25;
}}

.actions {{
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
}}

</style>

</head>

<body>

<div class="box">

{body}

</div>

</body>

</html>"""


# ============================================
# ADMIN SESSION
# ============================================

def admin(request):

    return any(
        x.strip().startswith("cb_admin=")
        and x.strip().split("=", 1)[1] in SESSIONS

        for x in request.headers.get(
            "Cookie",
            ""
        ).split(";")
    )


def redirect_admin(handler):

    handler.send_response(303)
    handler.send_header("Location", "/admin")
    handler.end_headers()


# ============================================
# HTTP SERVER
# ============================================

class H(BaseHTTPRequestHandler):

    def log_message(self, fmt_string, *args):
        print(fmt_string % args)

    def html(self, text, status=200, headers=()):

        data = text.encode()

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(data))
        )

        for key, value in headers:
            self.send_header(key, value)

        self.end_headers()

        self.wfile.write(data)


    def js(self, data, status=200):

        body = json.dumps(
            data,
            ensure_ascii=False
        ).encode()

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(body))
        )

        self.end_headers()

        self.wfile.write(body)


    def body(self):

        return self.rfile.read(
            int(
                self.headers.get(
                    "Content-Length",
                    "0"
                )
            )
        )


    # ========================================
    # GET
    # ========================================

    def do_GET(self):

        p = urlparse(self.path).path
        q = parse_qs(
            urlparse(self.path).query
        )


        # HOME
        if p == "/":

            return self.html(
                page(
                    "ColorBooster",
                    """
                    <h1>ColorBooster</h1>

                    <p>
                    Сервер регистрации и лицензий.
                    </p>

                    <a class="btn"
                       href="/register">
                       Регистрация
                    </a>

                    <a class="btn gray"
                       href="/admin">
                       Админ-панель
                    </a>
                    """
                )
            )


        # REGISTER
        if p == "/register":

            return self.html(
                page(
                    "Регистрация",
                    """
                    <h1>Регистрация ColorBooster</h1>

                    <div class="card">

                    <form method="post"
                          action="/register">

                    <label>Почта</label>

                    <input
                        class="full"
                        name="email"
                        type="email"
                        required
                        placeholder="example@gmail.com">

                    <label>Пароль</label>

                    <input
                        class="full"
                        name="password"
                        type="password"
                        minlength="6"
                        required
                        placeholder="Минимум 6 символов">

                    <button class="green">
                        Зарегистрироваться
                    </button>

                    </form>

                    <p class="muted">
                    После регистрации лицензионный ключ
                    будет создан автоматически.
                    </p>

                    </div>
                    """
                )
            )


        # ADMIN LOGIN
        if p == "/admin/login":

            return self.html(
                page(
                    "Админ-панель",
                    """
                    <h1>Админ-панель</h1>

                    <form method="post"
                          action="/admin/login">

                    <label>Логин</label>

                    <input
                        class="full"
                        name="user"
                        required>

                    <label>Пароль</label>

                    <input
                        class="full"
                        name="password"
                        type="password"
                        required>

                    <button>
                        Войти
                    </button>

                    </form>
                    """
                )
            )


        # ADMIN LOGOUT
        if p == "/admin/logout":

            token = ""

            for x in self.headers.get(
                "Cookie",
                ""
            ).split(";"):

                if x.strip().startswith("cb_admin="):

                    token = x.strip().split(
                        "=",
                        1
                    )[1]

            SESSIONS.discard(token)

            return self.html(
                page(
                    "Выход",
                    "<h1>Вы вышли</h1>"
                ),
                headers=[
                    (
                        "Set-Cookie",
                        "cb_admin=; Max-Age=0; Path=/"
                    )
                ]
            )


        # ADMIN
        if p == "/admin":

            if not admin(self):

                return self.html(
                    page(
                        "Админ",
                        """
                        <h1>Требуется вход</h1>

                        <a class="btn"
                           href="/admin/login">
                           Войти
                        </a>
                        """
                    ),
                    401
                )

            return self.render(
                q.get("q", [""])[0].strip()
            )


        self.send_response(404)
        self.end_headers()


    # ========================================
    # ADMIN PAGE
    # ========================================

    def render(self, search=""):

        with db() as c:

            if search:

                like = "%" + search.lower() + "%"

                users = c.execute(
                    """
                    SELECT
                        id,
                        email,
                        hwid,
                        status,
                        expires_at,
                        activation_key,
                        first_seen,
                        last_seen
                    FROM users
                    WHERE
                        LOWER(email) LIKE %s
                        OR LOWER(COALESCE(hwid,'')) LIKE %s
                    ORDER BY id DESC
                    """,
                    (like, like)
                ).fetchall()

            else:

                users = c.execute(
                    """
                    SELECT
                        id,
                        email,
                        hwid,
                        status,
                        expires_at,
                        activation_key,
                        first_seen,
                        last_seen
                    FROM users
                    ORDER BY id DESC
                    """
                ).fetchall()


            keys = c.execute(
                """
                SELECT
                    id,
                    key,
                    expires_at,
                    max_uses,
                    uses,
                    created_at
                FROM activation_keys
                ORDER BY id DESC
                """
            ).fetchall()


        now = datetime.now(timezone.utc)

        rows = ""


        for r in users:

            expired = (
                r[4] is not None
                and r[4] <= now
            )


            if r[3] == "blocked":

                badge = (
                    '<span class="badge blocked">'
                    'Заблокирован'
                    '</span>'
                )

            elif expired:

                badge = (
                    '<span class="badge expired">'
                    'Истёк'
                    '</span>'
                )

            else:

                badge = (
                    '<span class="badge">'
                    'Активен'
                    '</span>'
                )


            toggle_text = (
                "Разблокировать"
                if r[3] == "blocked"
                else "Заблокировать"
            )

            toggle_class = (
                ""
                if r[3] == "blocked"
                else "danger"
            )


            rows += f"""
            <tr>

            <td>{r[0]}</td>

            <td>
                {html.escape(r[1])}
            </td>

            <td>
                <code>
                {html.escape(r[2] or "не привязан")}
                </code>
            </td>

            <td>
                {badge}
            </td>

            <td>
                {html.escape(fmt(r[4]))}
            </td>

            <td>
                <code>
                {html.escape(r[5] or "—")}
                </code>
            </td>

            <td>
                {html.escape(fmt(r[6]))}
            </td>

            <td>
                {html.escape(fmt(r[7]))}
            </td>

            <td>

            <div class="actions">

            <form method="post"
                  action="/admin/toggle">

            <input
                type="hidden"
                name="id"
                value="{r[0]}">

            <button class="{toggle_class}">
                {toggle_text}
            </button>

            </form>


            <form method="post"
                  action="/admin/reset-hwid">

            <input
                type="hidden"
                name="id"
                value="{r[0]}">

            <button class="gray">
                Сбросить HWID
            </button>

            </form>


            <form method="post"
                  action="/admin/delete"
                  onsubmit="return confirm('Удалить пользователя?')">

            <input
                type="hidden"
                name="id"
                value="{r[0]}">

            <button class="danger">
                Удалить
            </button>

            </form>

            </div>


            <form method="post"
                  action="/admin/set-expiry"
                  style="margin-top:7px">

            <input
                type="hidden"
                name="id"
                value="{r[0]}">

            <input
                name="expires_at"
                type="datetime-local">

            <button>
                Установить срок
            </button>

            </form>


            <form method="post"
                  action="/admin/set-hwid"
                  style="margin-top:7px">

            <input
                type="hidden"
                name="id"
                value="{r[0]}">

            <input
                name="hwid"
                placeholder="Новый HWID">

            <button>
                Установить HWID
            </button>

            </form>

            </td>

            </tr>
            """


        if not rows:

            rows = """
            <tr>
                <td colspan="9">
                    Пользователей не найдено.
                </td>
            </tr>
            """


        key_rows = ""


        for k in keys:

            key_rows += f"""
            <tr>

            <td>{k[0]}</td>

            <td>
                <code>
                {html.escape(k[1])}
                </code>
            </td>

            <td>
                {html.escape(fmt(k[2]))}
            </td>

            <td>{k[3]}</td>

            <td>{k[4]}</td>

            <td>
                {html.escape(fmt(k[5]))}
            </td>

            <td>

            <form method="post"
                  action="/admin/delete-key"
                  onsubmit="return confirm('Удалить ключ?')">

            <input
                type="hidden"
                name="id"
                value="{k[0]}">

            <button class="danger">
                Удалить
            </button>

            </form>

            </td>

            </tr>
            """


        if not key_rows:

            key_rows = """
            <tr>
                <td colspan="7">
                    Ключей пока нет.
                </td>
            </tr>
            """


        body = f"""

        <h1>Админ-панель ColorBooster</h1>

        <p>
        Пользователей:
        <b>{len(users)}</b>

        |

        Ключей:
        <b>{len(keys)}</b>

        <a class="btn"
           href="/admin">
           Обновить
        </a>

        <a class="btn gray"
           href="/admin/logout">
           Выйти
        </a>
        </p>


        <div class="card">

        <h2>Поиск</h2>

        <form method="get"
              action="/admin">

        <input
            name="q"
            value="{html.escape(search)}"
            placeholder="Почта или HWID">

        <button>
            Найти
        </button>

        <a class="btn gray"
           href="/admin">
           Сбросить
        </a>

        </form>

        </div>


        <div class="card">

        <h2>Создать дополнительный ключ</h2>

        <form method="post"
              action="/admin/create-key">

        <input
            name="expires_at"
            type="datetime-local">

        <input
            name="max_uses"
            type="number"
            min="1"
            value="1">

        <button class="green">
            Создать ключ
        </button>

        </form>

        <p class="muted">
        При обычной регистрации ключ создаётся автоматически.
        </p>

        </div>


        <h2>Пользователи</h2>

        <table>

        <tr>

        <th>ID</th>
        <th>Почта</th>
        <th>HWID</th>
        <th>Статус</th>
        <th>Срок</th>
        <th>Ключ</th>
        <th>Первый</th>
        <th>Последний</th>
        <th>Управление</th>

        </tr>

        {rows}

        </table>


        <hr>


        <h2>Ключи активации</h2>

        <table>

        <tr>

        <th>ID</th>
        <th>Ключ</th>
        <th>Срок</th>
        <th>Макс.</th>
        <th>Исп.</th>
        <th>Создан</th>
        <th>Управление</th>

        </tr>

        {key_rows}

        </table>

        """


        return self.html(
            page(
                "Админ-панель",
                body
            )
        )


    # ========================================
    # POST
    # ========================================

    def do_POST(self):

        p = urlparse(self.path).path


        # ====================================
        # APP LOGIN
        # ====================================

        if p == "/api/login":

            try:

                data = json.loads(
                    self.body().decode()
                )

            except Exception:

                return self.js(
                    {
                        "error":
                        "Некорректный JSON"
                    },
                    400
                )


            email = str(
                data.get("email", "")
            ).strip().lower()

            password = str(
                data.get("password", "")
            )

            hwid = str(
                data.get("hwid", "")
            ).strip()


            if not email or not password or not hwid:

                return self.js(
                    {
                        "error":
                        "Не хватает данных"
                    },
                    400
                )


            with db() as c:

                user = c.execute(
                    """
                    SELECT
                        id,
                        password_hash,
                        hwid,
                        status,
                        expires_at
                    FROM users
                    WHERE email=%s
                    """,
                    (email,)
                ).fetchone()


                if (
                    not user
                    or not secrets.compare_digest(
                        user[1],
                        ph(password)
                    )
                ):

                    return self.js(
                        {
                            "error":
                            "Неверная почта или пароль"
                        },
                        401
                    )


                if user[3] == "blocked":

                    return self.js(
                        {
                            "error":
                            "Аккаунт заблокирован администратором"
                        },
                        403
                    )


                if (
                    user[4] is not None
                    and user[4] <= datetime.now(timezone.utc)
                ):

                    return self.js(
                        {
                            "error":
                            "Срок действия лицензии истёк"
                        },
                        403
                    )


                if (
                    user[2]
                    and not secrets.compare_digest(
                        user[2],
                        hwid
                    )
                ):

                    return self.js(
                        {
                            "error":
                            "HWID этого аккаунта привязан к другому компьютеру"
                        },
                        403
                    )


                c.execute(
                    """
                    UPDATE users
                    SET
                        hwid=%s,
                        last_seen=CURRENT_TIMESTAMP
                    WHERE id=%s
                    """,
                    (
                        hwid,
                        user[0]
                    )
                )


            return self.js(
                {
                    "ok": True,
                    "hwid": hwid
                }
            )


        # ====================================
        # REGISTRATION
        # ====================================

        q = parse_qs(
            self.body().decode()
        )


        if p == "/register":

            email = q.get(
                "email",
                [""]
            )[0].strip().lower()

            password = q.get(
                "password",
                [""]
            )[0]


            if not email or "@" not in email:

                return self.html(
                    page(
                        "Ошибка",
                        "<h1>Некорректная почта</h1>"
                    ),
                    400
                )


            if len(password) < 6:

                return self.html(
                    page(
                        "Ошибка",
                        "<h1>Пароль должен быть не короче 6 символов</h1>"
                    ),
                    400
                )


            # --------------------------------
            # СОЗДАЁМ КЛЮЧ АВТОМАТИЧЕСКИ
            # --------------------------------

            license_key = make_license(
                LICENSE_DAYS
            )

            expires_at = (
                datetime.now(timezone.utc)
                + timedelta(days=LICENSE_DAYS)
            )


            try:

                with db() as c:

                    # Проверяем почту
                    existing = c.execute(
                        """
                        SELECT id
                        FROM users
                        WHERE email=%s
                        """,
                        (email,)
                    ).fetchone()


                    if existing:

                        return self.html(
                            page(
                                "Ошибка",
                                """
                                <h1>
                                Эта почта уже зарегистрирована
                                </h1>

                                <a class="btn"
                                   href="/register">
                                   Назад
                                </a>
                                """
                            ),
                            409
                        )


                    # Создаём пользователя
                    c.execute(
                        """
                        INSERT INTO users(
                            email,
                            password_hash,
                            activation_key,
                            expires_at
                        )
                        VALUES(%s,%s,%s,%s)
                        """,
                        (
                            email,
                            ph(password),
                            license_key,
                            expires_at
                        )
                    )


            except Exception as e:

                print(
                    "Registration error:",
                    repr(e)
                )

                return self.html(
                    page(
                        "Ошибка",
                        """
                        <h1>
                        Не удалось завершить регистрацию
                        </h1>

                        <p>
                        Попробуйте ещё раз.
                        </p>
                        """
                    ),
                    500
                )


            # --------------------------------
            # ПОКАЗЫВАЕМ КЛЮЧ
            # --------------------------------

            return self.html(
                page(
                    "Регистрация завершена",
                    f"""
                    <h1>
                    Регистрация завершена
                    </h1>

                    <div class="card">

                    <p>
                    Аккаунт успешно создан.
                    </p>

                    <p>
                    Твой лицензионный ключ:
                    </p>

                    <div class="license">
                    {html.escape(license_key)}
                    </div>

                    <p class="muted">
                    Срок действия:
                    {html.escape(fmt(expires_at))}
                    </p>

                    <p>
                    Скопируй этот ключ и введи его
                    в ColorBooster.
                    </p>

                    </div>

                    <a class="btn"
                       href="/">
                       На главную
                    </a>
                    """
                )
            )


        # ====================================
        # ADMIN LOGIN
        # ====================================

        if p == "/admin/login":

            user = q.get(
                "user",
                [""]
            )[0].strip()

            password = q.get(
                "password",
                [""]
            )[0].strip()


            if (
                not secrets.compare_digest(
                    user,
                    ADMIN_USER
                )
                or
                not secrets.compare_digest(
                    password,
                    ADMIN_PASSWORD
                )
            ):

                return self.html(
                    page(
                        "Ошибка",
                        "<h1>Неверный логин или пароль</h1>"
                    ),
                    401
                )


            token = secrets.token_urlsafe(32)

            SESSIONS.add(token)

            self.send_response(303)

            self.send_header(
                "Location",
                "/admin"
            )

            self.send_header(
                "Set-Cookie",
                f"cb_admin={token}; "
                "HttpOnly; "
                "Path=/; "
                "SameSite=Lax"
            )

            self.end_headers()

            return


        # ====================================
        # ADMIN ACTIONS
        # ====================================

        if p.startswith("/admin/") and not admin(self):

            return self.html(
                page(
                    "Ошибка",
                    "<h1>Сначала войдите</h1>"
                ),
                401
            )


        try:

            user_id = int(
                q.get(
                    "id",
                    ["0"]
                )[0]
            )

        except Exception:

            user_id = 0


        with db() as c:

            if p == "/admin/toggle":

                c.execute(
                    """
                    UPDATE users
                    SET status =
                        CASE
                        WHEN status='blocked'
                        THEN 'active'
                        ELSE 'blocked'
                        END
                    WHERE id=%s
                    """,
                    (user_id,)
                )


            elif p == "/admin/reset-hwid":

                c.execute(
                    """
                    UPDATE users
                    SET hwid=NULL
                    WHERE id=%s
                    """,
                    (user_id,)
                )


            elif p == "/admin/set-hwid":

                hwid = q.get(
                    "hwid",
                    [""]
                )[0].strip()


                if not hwid:

                    return self.html(
                        page(
                            "Ошибка",
                            "<h1>HWID не введён</h1>"
                        ),
                        400
                    )


                c.execute(
                    """
                    UPDATE users
                    SET hwid=%s
                    WHERE id=%s
                    """,
                    (
                        hwid,
                        user_id
                    )
                )


            elif p == "/admin/set-expiry":

                c.execute(
                    """
                    UPDATE users
                    SET expires_at=%s
                    WHERE id=%s
                    """,
                    (
                        dt(
                            q.get(
                                "expires_at",
                                [""]
                            )[0]
                        ),
                        user_id
                    )
                )


            elif p == "/admin/delete":

                c.execute(
                    """
                    DELETE FROM users
                    WHERE id=%s
                    """,
                    (user_id,)
                )


            elif p == "/admin/create-key":

                try:

                    uses = max(
                        1,
                        min(
                            int(
                                q.get(
                                    "max_uses",
                                    ["1"]
                                )[0]
                            ),
                            100000
                        )
                    )

                except Exception:

                    uses = 1


                # Дополнительный ключ
                new_key = make_license(
                    LICENSE_DAYS
                )


                c.execute(
                    """
                    INSERT INTO activation_keys(
                        key,
                        expires_at,
                        max_uses
                    )
                    VALUES(%s,%s,%s)
                    """,
                    (
                        new_key,
                        dt(
                            q.get(
                                "expires_at",
                                [""]
                            )[0]
                        ),
                        uses
                    )
                )


            elif p == "/admin/delete-key":

                c.execute(
                    """
                    DELETE FROM activation_keys
                    WHERE id=%s
                    """,
                    (user_id,)
                )


            else:

                self.send_response(404)
                self.end_headers()
                return


        redirect_admin(self)


# ============================================
# START
# ============================================

if __name__ == "__main__":

    init_db()

    print(
        f"Listening on {HOST}:{PORT}"
    )

    ThreadingHTTPServer(
        (HOST, PORT),
        H
    ).serve_forever()
