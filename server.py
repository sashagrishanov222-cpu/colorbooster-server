import os
import html
import json
import secrets
import hashlib

from datetime import datetime, timezone, timedelta, date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import psycopg


# ============================================================
# CONFIG
# ============================================================

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8765"))

DATABASE_URL = os.environ.get("DATABASE_URL", "")

ADMIN_USER = os.environ.get(
    "ADMIN_USER",
    "admin"
)

ADMIN_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD",
    "change-me"
)


# ============================================================
# COLORBOOSTER LICENSE SETTINGS
# ============================================================

LICENSE_SECRET = (
    "CB_INTERNAL_2026_SECRET_7F3A91"
)

PURCHASE_PREFIX = "CB-PURCHASE"

SESSIONS = set()


# ============================================================
# DATABASE
# ============================================================

def db():

    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not configured"
        )

    return psycopg.connect(
        DATABASE_URL
    )


def init_db():

    with db() as c:

        # USERS
        c.execute("""
            CREATE TABLE IF NOT EXISTS users(

                id BIGSERIAL PRIMARY KEY,

                email TEXT UNIQUE NOT NULL,

                password_hash TEXT NOT NULL,

                hwid TEXT,

                status TEXT NOT NULL
                    DEFAULT 'active',

                expires_at TIMESTAMPTZ,

                activation_key TEXT,

                first_seen TIMESTAMPTZ
                    NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                last_seen TIMESTAMPTZ
                    NOT NULL
                    DEFAULT CURRENT_TIMESTAMP

            )
        """)


        # Compatibility with old database
        c.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS status
            TEXT NOT NULL DEFAULT 'active'
        """)

        c.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS expires_at
            TIMESTAMPTZ
        """)

        c.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS activation_key
            TEXT
        """)


        # OLD ACTIVATION KEYS
        c.execute("""
            CREATE TABLE IF NOT EXISTS activation_keys(

                id BIGSERIAL PRIMARY KEY,

                key TEXT UNIQUE NOT NULL,

                expires_at TIMESTAMPTZ,

                max_uses INTEGER NOT NULL
                    DEFAULT 1,

                uses INTEGER NOT NULL
                    DEFAULT 0,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP

            )
        """)


        # PURCHASE CODES
        c.execute("""
            CREATE TABLE IF NOT EXISTS purchase_codes(

                id BIGSERIAL PRIMARY KEY,

                code TEXT UNIQUE NOT NULL,

                duration_days INTEGER NOT NULL,

                used BOOLEAN NOT NULL
                    DEFAULT FALSE,

                used_by TEXT,

                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                used_at TIMESTAMPTZ

            )
        """)


# ============================================================
# PASSWORD HASH
# ============================================================

def ph(password):

    data = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        b"ColorBooster-2026",
        120000
    )

    return data.hex()


# ============================================================
# DATE HELPERS
# ============================================================

def parse_datetime(value):

    value = (value or "").strip()

    if not value:
        return None

    try:

        return datetime.strptime(
            value,
            "%Y-%m-%dT%H:%M"
        ).replace(
            tzinfo=timezone.utc
        )

    except ValueError:

        return None


def fmt(value):

    if value is None:
        return "—"

    if hasattr(value, "strftime"):

        return value.strftime(
            "%Y-%m-%d %H:%M UTC"
        )

    return str(value)


def days_since_2020():

    return (
        date.today()
        - date(2020, 1, 1)
    ).days


# ============================================================
# COLORBOOSTER LICENSE GENERATOR
# ============================================================

def make_license(duration_days):

    # 0 = forever
    if duration_days == 0:

        expiry = 0xFFFFFFFF

    else:

        expiry = (
            days_since_2020()
            + duration_days
        )


    expiry_hex = (
        f"{expiry & 0xFFFFFFFF:08X}"
    )


    # 16 HEX characters
    random_part = (
        secrets.token_hex(8)
        .upper()
    )


    payload = (
        expiry_hex
        + random_part
    )


    digest = hashlib.sha256(
        (
            LICENSE_SECRET
            + payload
        ).encode("utf-8")
    ).hexdigest().upper()


    check = digest[:8]


    # EXACT FORMAT USED BY COLORBOOSTER:
    #
    # CB-XXXXXXXX-XXXXXXXXXXXXXXXX-XXXXXXXX

    return (
        "CB-"
        + expiry_hex
        + "-"
        + random_part
        + "-"
        + check
    )


# ============================================================
# PURCHASE CODE GENERATOR
# ============================================================

def make_purchase_code():

    alphabet = (
        "ABCDEFGHJKLMNPQRSTUVWXYZ"
        "23456789"
    )


    part1 = "".join(
        secrets.choice(alphabet)
        for _ in range(4)
    )


    part2 = "".join(
        secrets.choice(alphabet)
        for _ in range(4)
    )


    return (
        f"{PURCHASE_PREFIX}-"
        f"{part1}-{part2}"
    )


# ============================================================
# HTML
# ============================================================

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

    margin: 0;

    background:
        #0d0f13;

    color: #eeeeee;

    font-family:
        Arial,
        sans-serif;

}}

.box {{

    max-width: 1300px;

    margin: 40px auto;

    padding: 28px;

    background: #181b21;

    border-radius: 16px;

}}

.card {{

    background: #111318;

    border: 1px solid #2d3139;

    border-radius: 12px;

    padding: 20px;

    margin: 18px 0;

}}

input,
select {{

    padding: 11px;

    border-radius: 7px;

    border: 1px solid #444;

    background: #0d0f13;

    color: white;

}}

.full {{

    width: 100%;

    margin: 7px 0 15px;

}}

button,
.btn {{

    display: inline-block;

    padding: 10px 16px;

    border: none;

    border-radius: 7px;

    background: #4d7cff;

    color: white;

    cursor: pointer;

    text-decoration: none;

}}

.green {{
    background: #287a45;
}}

.danger {{
    background: #a63838;
}}

.gray {{
    background: #555;
}}

.purchase {{

    font-family: Consolas, monospace;

    font-size: 20px;

    background: #090b0f;

    border: 1px solid #4d7cff;

    padding: 16px;

    border-radius: 9px;

    word-break: break-all;

}}

.license {{

    font-family: Consolas, monospace;

    font-size: 20px;

    background: #090b0f;

    border: 1px solid #50d890;

    padding: 16px;

    border-radius: 9px;

    word-break: break-all;

}}

.muted {{
    color: #999;
}}

table {{

    width: 100%;

    border-collapse: collapse;

    margin-top: 15px;

}}

th,
td {{

    padding: 9px;

    border-bottom:
        1px solid #30343b;

    text-align: left;

    vertical-align: top;

}}

code {{

    word-break: break-all;

}}

.badge {{

    display: inline-block;

    padding: 4px 8px;

    border-radius: 12px;

    background: #28633d;

}}

.badge.red {{
    background: #7b3030;
}}

.badge.yellow {{
    background: #765d27;
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


# ============================================================
# ADMIN AUTH
# ============================================================

def is_admin(handler):

    cookie = handler.headers.get(
        "Cookie",
        ""
    )

    for item in cookie.split(";"):

        item = item.strip()

        if item.startswith("cb_admin="):

            token = item.split(
                "=",
                1
            )[1]

            if token in SESSIONS:
                return True

    return False


# ============================================================
# HTTP HANDLER
# ============================================================

class Handler(BaseHTTPRequestHandler):


    def log_message(
        self,
        fmt_string,
        *args
    ):

        print(
            fmt_string % args
        )


    # ========================================================
    # RESPONSE HTML
    # ========================================================

    def send_html(
        self,
        text,
        status=200,
        headers=()
    ):

        data = text.encode(
            "utf-8"
        )


        self.send_response(
            status
        )


        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )


        self.send_header(
            "Content-Length",
            str(len(data))
        )


        for key, value in headers:

            self.send_header(
                key,
                value
            )


        self.end_headers()


        self.wfile.write(
            data
        )


    # ========================================================
    # JSON
    # ========================================================

    def send_json(
        self,
        data,
        status=200
    ):

        body = json.dumps(
            data,
            ensure_ascii=False
        ).encode(
            "utf-8"
        )


        self.send_response(
            status
        )


        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )


        self.send_header(
            "Content-Length",
            str(len(body))
        )


        self.end_headers()


        self.wfile.write(
            body
        )


    # ========================================================
    # READ BODY
    # ========================================================

    def read_body(self):

        length = int(
            self.headers.get(
                "Content-Length",
                "0"
            )
        )


        return self.rfile.read(
            length
        )


    # ========================================================
    # REDIRECT
    # ========================================================

    def redirect(self, location):

        self.send_response(
            303
        )

        self.send_header(
            "Location",
            location
        )

        self.end_headers()


    # ========================================================
    # GET
    # ========================================================

    def do_GET(self):

        parsed = urlparse(
            self.path
        )

        path = parsed.path

        query = parse_qs(
            parsed.query
        )


        # ----------------------------------------------------
        # HOME
        # ----------------------------------------------------

        if path == "/":

            return self.send_html(
                page(
                    "ColorBooster",
                    """
                    <h1>
                    ColorBooster
                    </h1>

                    <p>
                    Система регистрации
                    и лицензий.
                    </p>

                    <a class="btn"
                       href="/register">
                       Получить ключ
                    </a>

                    <a class="btn gray"
                       href="/admin">
                       Админ-панель
                    </a>
                    """
                )
            )


        # ----------------------------------------------------
        # REGISTER
        # ----------------------------------------------------

        if path == "/register":

            return self.send_html(
                page(
                    "Регистрация",
                    """
                    <h1>
                    Регистрация ColorBooster
                    </h1>

                    <div class="card">

                    <form method="post"
                          action="/register">

                    <label>
                    Email
                    </label>

                    <input
                        class="full"
                        name="email"
                        type="email"
                        required
                        placeholder="you@example.com">

                    <label>
                    Пароль
                    </label>

                    <input
                        class="full"
                        name="password"
                        type="password"
                        minlength="6"
                        required
                        placeholder="Минимум 6 символов">

                    <label>
                    Код покупки
                    </label>

                    <input
                        class="full"
                        name="purchase_code"
                        required
                        placeholder="CB-PURCHASE-XXXX-XXXX">

                    <button class="green">
                    Зарегистрироваться
                    </button>

                    </form>

                    <p class="muted">

                    Код покупки выдаётся
                    после приобретения ColorBooster.

                    </p>

                    </div>
                    """
                )
            )


        # ----------------------------------------------------
        # ADMIN LOGIN
        # ----------------------------------------------------

        if path == "/admin/login":

            return self.send_html(
                page(
                    "Админ-панель",
                    """
                    <h1>
                    Админ-панель
                    </h1>

                    <form method="post"
                          action="/admin/login">

                    <label>
                    Логин
                    </label>

                    <input
                        class="full"
                        name="user"
                        required>

                    <label>
                    Пароль
                    </label>

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


        # ----------------------------------------------------
        # ADMIN LOGOUT
        # ----------------------------------------------------

        if path == "/admin/logout":

            token = ""

            cookie = self.headers.get(
                "Cookie",
                ""
            )

            for item in cookie.split(";"):

                item = item.strip()

                if item.startswith(
                    "cb_admin="
                ):

                    token = item.split(
                        "=",
                        1
                    )[1]


            SESSIONS.discard(
                token
            )


            return self.send_html(
                page(
                    "Выход",
                    """
                    <h1>
                    Вы вышли из админ-панели
                    </h1>
                    """
                ),
                headers=[
                    (
                        "Set-Cookie",
                        "cb_admin=;"
                        " Max-Age=0;"
                        " Path=/"
                    )
                ]
            )


        # ----------------------------------------------------
        # ADMIN
        # ----------------------------------------------------

        if path == "/admin":

            if not is_admin(self):

                return self.send_html(
                    page(
                        "Вход",
                        """
                        <h1>
                        Требуется авторизация
                        </h1>

                        <a class="btn"
                           href="/admin/login">
                           Войти
                        </a>
                        """
                    ),
                    401
                )


            search = query.get(
                "q",
                [""]
            )[0].strip()


            return self.render_admin(
                search
            )


        # ----------------------------------------------------
        # 404
        # ----------------------------------------------------

        self.send_response(
            404
        )

        self.end_headers()


    # ========================================================
    # ADMIN PAGE
    # ========================================================

    def render_admin(
        self,
        search=""
    ):

        now = datetime.now(
            timezone.utc
        )


        # ----------------------------------------------------
        # USERS
        # ----------------------------------------------------

        with db() as c:

            if search:

                like = (
                    "%"
                    + search.lower()
                    + "%"
                )


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
                        LOWER(email)
                        LIKE %s
                        OR
                        LOWER(
                            COALESCE(hwid,'')
                        )
                        LIKE %s
                    ORDER BY id DESC
                    """,
                    (
                        like,
                        like
                    )
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


            purchase_codes = c.execute(
                """
                SELECT
                    id,
                    code,
                    duration_days,
                    used,
                    used_by,
                    created_at,
                    used_at
                FROM purchase_codes
                ORDER BY id DESC
                """
            ).fetchall()


            old_keys = c.execute(
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


        # ----------------------------------------------------
        # USER ROWS
        # ----------------------------------------------------

        user_rows = ""


        for u in users:

            expired = (
                u[4] is not None
                and u[4] <= now
            )


            if u[3] == "blocked":

                status = """
                <span class="badge red">
                Заблокирован
                </span>
                """

                toggle_text = (
                    "Разблокировать"
                )

                toggle_class = ""


            elif expired:

                status = """
                <span class="badge yellow">
                Истёк
                </span>
                """

                toggle_text = (
                    "Заблокировать"
                )

                toggle_class = (
                    "danger"
                )


            else:

                status = """
                <span class="badge">
                Активен
                </span>
                """

                toggle_text = (
                    "Заблокировать"
                )

                toggle_class = (
                    "danger"
                )


            user_rows += f"""

            <tr>

            <td>
            {u[0]}
            </td>

            <td>
            {html.escape(u[1])}
            </td>

            <td>
            <code>
            {html.escape(
                u[2] or "не привязан"
            )}
            </code>
            </td>

            <td>
            {status}
            </td>

            <td>
            {html.escape(
                fmt(u[4])
            )}
            </td>

            <td>
            <code>
            {html.escape(
                u[5] or "—"
            )}
            </code>
            </td>

            <td>

            <div class="actions">

            <form method="post"
                  action="/admin/toggle">

            <input
                type="hidden"
                name="id"
                value="{u[0]}">

            <button
                class="{toggle_class}">

                {toggle_text}

            </button>

            </form>


            <form method="post"
                  action="/admin/reset-hwid">

            <input
                type="hidden"
                name="id"
                value="{u[0]}">

            <button class="gray">
                Сбросить HWID
            </button>

            </form>


            <form method="post"
                  action="/admin/delete"
                  onsubmit="
                  return confirm(
                  'Удалить пользователя?'
                  );">

            <input
                type="hidden"
                name="id"
                value="{u[0]}">

            <button class="danger">
                Удалить
            </button>

            </form>

            </div>


            <form method="post"
                  action="/admin/set-expiry"
                  style="margin-top:8px">

            <input
                type="hidden"
                name="id"
                value="{u[0]}">

            <input
                name="expires_at"
                type="datetime-local">

            <button>
                Установить срок
            </button>

            </form>


            <form method="post"
                  action="/admin/set-hwid"
                  style="margin-top:8px">

            <input
                type="hidden"
                name="id"
                value="{u[0]}">

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


        if not user_rows:

            user_rows = """
            <tr>
            <td colspan="7">
            Пользователей нет.
            </td>
            </tr>
            """


        # ----------------------------------------------------
        # PURCHASE CODE ROWS
        # ----------------------------------------------------

        purchase_rows = ""


        for p in purchase_codes:

            duration = p[2]


            if duration == 0:

                duration_text = (
                    "Навсегда"
                )

            elif duration == 7:

                duration_text = (
                    "1 неделя"
                )

            elif duration == 14:

                duration_text = (
                    "2 недели"
                )

            elif duration == 30:

                duration_text = (
                    "1 месяц"
                )

            else:

                duration_text = (
                    f"{duration} дней"
                )


            if p[3]:

                status = """
                <span class="badge red">
                Использован
                </span>
                """

            else:

                status = """
                <span class="badge">
                Не использован
                </span>
                """


            purchase_rows += f"""

            <tr>

            <td>
            {p[0]}
            </td>

            <td>
            <code>
            {html.escape(p[1])}
            </code>
            </td>

            <td>
            {html.escape(duration_text)}
            </td>

            <td>
            {status}
            </td>

            <td>
            {html.escape(p[4] or "—")}
            </td>

            <td>
            {html.escape(fmt(p[5]))}
            </td>

            <td>
            {html.escape(fmt(p[6]))}
            </td>

            <td>

            <form method="post"
                  action="/admin/delete-purchase"
                  onsubmit="
                  return confirm(
                  'Удалить код покупки?'
                  );">

            <input
                type="hidden"
                name="id"
                value="{p[0]}">

            <button class="danger">
                Удалить
            </button>

            </form>

            </td>

            </tr>

            """


        if not purchase_rows:

            purchase_rows = """
            <tr>
            <td colspan="8">
            Кодів покупок пока нет.
            </td>
            </tr>
            """


        # ----------------------------------------------------
        # OLD ACTIVATION KEYS
        # ----------------------------------------------------

        key_rows = ""


        for k in old_keys:

            key_rows += f"""

            <tr>

            <td>
            {k[0]}
            </td>

            <td>
            <code>
            {html.escape(k[1])}
            </code>
            </td>

            <td>
            {html.escape(fmt(k[2]))}
            </td>

            <td>
            {k[3]}
            </td>

            <td>
            {k[4]}
            </td>

            <td>
            {html.escape(fmt(k[5]))}
            </td>

            </tr>

            """


        # ----------------------------------------------------
        # PAGE
        # ----------------------------------------------------

        body = f"""

        <h1>
        ColorBooster — админ-панель
        </h1>


        <p>

        Пользователей:
        <b>{len(users)}</b>

        |

        Кодов покупок:
        <b>{len(purchase_codes)}</b>

        <a class="btn"
           href="/admin">
           Обновить
        </a>

        <a class="btn gray"
           href="/admin/logout">
           Выйти
        </a>

        </p>


        <!-- SEARCH -->

        <div class="card">

        <h2>
        Поиск пользователя
        </h2>

        <form method="get"
              action="/admin">

        <input
            name="q"
            value="{html.escape(search)}"
            placeholder="Email или HWID">

        <button>
        Найти
        </button>

        <a class="btn gray"
           href="/admin">
           Сбросить
        </a>

        </form>

        </div>


        <!-- PURCHASE CREATOR -->

        <div class="card">

        <h2>
        Создать код покупки
        </h2>

        <p class="muted">
        Один код покупки можно использовать
        только один раз.
        </p>

        <form method="post"
              action="/admin/create-purchase">

        <select
            name="duration_days"
            required>

            <option value="7">
            1 неделя
            </option>

            <option value="14">
            2 недели
            </option>

            <option value="30">
            1 месяц
            </option>

            <option value="0">
            Навсегда
            </option>

        </select>

        <button class="green">
        Создать код покупки
        </button>

        </form>

        </div>


        <!-- PURCHASE CODES -->

        <h2>
        Коды покупок
        </h2>

        <table>

        <tr>

        <th>ID</th>
        <th>Код</th>
        <th>Срок</th>
        <th>Статус</th>
        <th>Пользователь</th>
        <th>Создан</th>
        <th>Использован</th>
        <th></th>

        </tr>

        {purchase_rows}

        </table>


        <hr>


        <!-- USERS -->

        <h2>
        Пользователи
        </h2>

        <table>

        <tr>

        <th>ID</th>
        <th>Email</th>
        <th>HWID</th>
        <th>Статус</th>
        <th>Срок</th>
        <th>Лицензия</th>
        <th>Управление</th>

        </tr>

        {user_rows}

        </table>


        <hr>


        <!-- OLD KEYS -->

        <h2>
        Старые ключи активации
        </h2>

        <table>

        <tr>

        <th>ID</th>
        <th>Ключ</th>
        <th>Срок</th>
        <th>Макс.</th>
        <th>Исп.</th>
        <th>Создан</th>

        </tr>

        {key_rows}

        </table>

        """


        return self.send_html(
            page(
                "Админ-панель",
                body
            )
        )


    # ========================================================
    # POST
    # ========================================================

    def do_POST(self):

        parsed = urlparse(
            self.path
        )

        path = parsed.path


        # ====================================================
        # API LOGIN
        # ====================================================

        if path == "/api/login":

            try:

                data = json.loads(
                    self.read_body()
                    .decode("utf-8")
                )

            except Exception:

                return self.send_json(
                    {
                        "error":
                        "Некорректный JSON"
                    },
                    400
                )


            email = str(
                data.get(
                    "email",
                    ""
                )
            ).strip().lower()


            password = str(
                data.get(
                    "password",
                    ""
                )
            )


            hwid = str(
                data.get(
                    "hwid",
                    ""
                )
            ).strip()


            if (
                not email
                or not password
                or not hwid
            ):

                return self.send_json(
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


                if not user:

                    return self.send_json(
                        {
                            "error":
                            "Неверная почта или пароль"
                        },
                        401
                    )


                if not secrets.compare_digest(
                    user[1],
                    ph(password)
                ):

                    return self.send_json(
                        {
                            "error":
                            "Неверная почта или пароль"
                        },
                        401
                    )


                if user[3] == "blocked":

                    return self.send_json(
                        {
                            "error":
                            "Аккаунт заблокирован"
                        },
                        403
                    )


                if (
                    user[4] is not None
                    and user[4]
                    <= datetime.now(
                        timezone.utc
                    )
                ):

                    return self.send_json(
                        {
                            "error":
                            "Срок лицензии истёк"
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

                    return self.send_json(
                        {
                            "error":
                            "HWID привязан к другому компьютеру"
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


            return self.send_json(
                {
                    "ok": True
                }
            )


        # ====================================================
        # FORM DATA
        # ====================================================

        try:

            body = self.read_body().decode(
                "utf-8"
            )

            q = parse_qs(
                body
            )

        except Exception:

            return self.send_html(
                page(
                    "Ошибка",
                    "<h1>Ошибка данных</h1>"
                ),
                400
            )


        # ====================================================
        # REGISTER
        # ====================================================

        if path == "/register":

            email = q.get(
                "email",
                [""]
            )[0].strip().lower()


            password = q.get(
                "password",
                [""]
            )[0]


            purchase_code = q.get(
                "purchase_code",
                [""]
            )[0].strip().upper()


            if (
                not email
                or "@"
                not in email
            ):

                return self.send_html(
                    page(
                        "Ошибка",
                        """
                        <h1>
                        Некорректный email
                        </h1>

                        <a class="btn"
                           href="/register">
                           Назад
                        </a>
                        """
                    ),
                    400
                )


            if len(password) < 6:

                return self.send_html(
                    page(
                        "Ошибка",
                        """
                        <h1>
                        Пароль должен содержать
                        минимум 6 символов
                        </h1>

                        <a class="btn"
                           href="/register">
                           Назад
                        </a>
                        """
                    ),
                    400
                )


            if not purchase_code:

                return self.send_html(
                    page(
                        "Ошибка",
                        """
                        <h1>
                        Введите код покупки
                        </h1>

                        <a class="btn"
                           href="/register">
                           Назад
                        </a>
                        """
                    ),
                    400
                )


            with db() as c:

                # --------------------------------------------
                # CHECK EMAIL
                # --------------------------------------------

                existing = c.execute(
                    """
                    SELECT id
                    FROM users
                    WHERE email=%s
                    """,
                    (email,)
                ).fetchone()


                if existing:

                    return self.send_html(
                        page(
                            "Ошибка",
                            """
                            <h1>
                            Этот email уже зарегистрирован
                            </h1>

                            <a class="btn"
                               href="/register">
                               Назад
                            </a>
                            """
                        ),
                        409
                    )


                # --------------------------------------------
                # CHECK PURCHASE CODE
                # --------------------------------------------

                purchase = c.execute(
                    """
                    SELECT
                        id,
                        duration_days,
                        used
                    FROM purchase_codes
                    WHERE code=%s
                    FOR UPDATE
                    """,
                    (
                        purchase_code,
                    )
                ).fetchone()


                if not purchase:

                    return self.send_html(
                        page(
                            "Ошибка",
                            """
                            <h1>
                            Неверный код покупки
                            </h1>

                            <p>
                            Проверьте код и попробуйте
                            ещё раз.
                            </p>

                            <a class="btn"
                               href="/register">
                               Назад
                            </a>
                            """
                        ),
                        400
                    )


                if purchase[2]:

                    return self.send_html(
                        page(
                            "Ошибка",
                            """
                            <h1>
                            Этот код покупки уже использован
                            </h1>

                            <p>
                            Один код покупки можно
                            использовать только один раз.
                            </p>

                            <a class="btn"
                               href="/register">
                               Назад
                            </a>
                            """
                        ),
                        400
                    )


                # --------------------------------------------
                # LICENSE DURATION
                # --------------------------------------------

                duration_days = purchase[1]


                if duration_days == 0:

                    # 0 = forever
                    expires_at = (
                        datetime(
                            9999,
                            12,
                            31,
                            tzinfo=timezone.utc
                        )
                    )

                else:

                    expires_at = (
                        datetime.now(
                            timezone.utc
                        )
                        +
                        timedelta(
                            days=duration_days
                        )
                    )


                # --------------------------------------------
                # GENERATE LICENSE
                # --------------------------------------------

                license_key = make_license(
                    duration_days
                )


                # --------------------------------------------
                # CREATE USER
                # --------------------------------------------

                c.execute(
                    """
                    INSERT INTO users(
                        email,
                        password_hash,
                        activation_key,
                        expires_at
                    )
                    VALUES(
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    """,
                    (
                        email,
                        ph(password),
                        license_key,
                        expires_at
                    )
                )


                # --------------------------------------------
                # MARK PURCHASE CODE USED
                # --------------------------------------------

                c.execute(
                    """
                    UPDATE purchase_codes
                    SET
                        used=TRUE,
                        used_by=%s,
                        used_at=CURRENT_TIMESTAMP
                    WHERE id=%s
                    """,
                    (
                        email,
                        purchase[0]
                    )
                )


            # --------------------------------------------
            # SUCCESS PAGE
            # --------------------------------------------

            if duration_days == 0:

                duration_text = (
                    "Навсегда"
                )

            elif duration_days == 7:

                duration_text = (
                    "1 неделя"
                )

            elif duration_days == 14:

                duration_text = (
                    "2 недели"
                )

            elif duration_days == 30:

                duration_text = (
                    "1 месяц"
                )

            else:

                duration_text = (
                    f"{duration_days} дней"
                )


            return self.send_html(
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
                    Ваша лицензия:
                    </p>

                    <div class="license">
                    {html.escape(
                        license_key
                    )}
                    </div>

                    <p>
                    Срок:
                    <b>
                    {html.escape(
                        duration_text
                    )}
                    </b>
                    </p>

                    <p class="muted">
                    Скопируйте этот ключ
                    и вставьте его в ColorBooster.
                    </p>

                    </div>

                    <a class="btn"
                       href="/">
                       На главную
                    </a>
                    """
                )
            )


        # ====================================================
        # ADMIN LOGIN
        # ====================================================

        if path == "/admin/login":

            user = q.get(
                "user",
                [""]
            )[0].strip()


            password = q.get(
                "password",
                [""]
            )[0]


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

                return self.send_html(
                    page(
                        "Ошибка",
                        """
                        <h1>
                        Неверный логин или пароль
                        </h1>
                        """
                    ),
                    401
                )


            token = secrets.token_urlsafe(
                32
            )

            SESSIONS.add(
                token
            )


            self.send_response(
                303
            )

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


        # ====================================================
        # EVERYTHING BELOW REQUIRES ADMIN
        # ====================================================

        if path.startswith(
            "/admin/"
        ) and not is_admin(self):

            return self.send_html(
                page(
                    "Ошибка",
                    """
                    <h1>
                    Требуется вход в админку
                    </h1>
                    """
                ),
                401
            )


        # ====================================================
        # CREATE PURCHASE CODE
        # ====================================================

        if path == "/admin/create-purchase":

            duration_text = q.get(
                "duration_days",
                ["30"]
            )[0]


            try:

                duration_days = int(
                    duration_text
                )

            except ValueError:

                return self.send_html(
                    page(
                        "Ошибка",
                        """
                        <h1>
                        Некорректный срок
                        </h1>
                        """
                    ),
                    400
                )


            if duration_days not in (
                7,
                14,
                30,
                0
            ):

                return self.send_html(
                    page(
                        "Ошибка",
                        """
                        <h1>
                        Некорректный срок
                        </h1>
                        """
                    ),
                    400
                )


            # Generate unique code
            for _ in range(10):

                code = (
                    make_purchase_code()
                )

                try:

                    with db() as c:

                        c.execute(
                            """
                            INSERT INTO
                            purchase_codes(
                                code,
                                duration_days
                            )
                            VALUES(%s,%s)
                            """,
                            (
                                code,
                                duration_days
                            )
                        )

                    break

                except psycopg.errors.UniqueViolation:

                    continue

            else:

                return self.send_html(
                    page(
                        "Ошибка",
                        """
                        <h1>
                        Не удалось создать код
                        </h1>
                        """
                    ),
                    500
                )


            if duration_days == 0:

                duration_name = (
                    "Навсегда"
                )

            elif duration_days == 7:

                duration_name = (
                    "1 неделя"
                )

            elif duration_days == 14:

                duration_name = (
                    "2 недели"
                )

            else:

                duration_name = (
                    "1 месяц"
                )


            return self.send_html(
                page(
                    "Код покупки",
                    f"""
                    <h1>
                    Код покупки создан
                    </h1>

                    <div class="card">

                    <p>
                    Срок лицензии:
                    <b>
                    {duration_name}
                    </b>
                    </p>

                    <div class="purchase">
                    {html.escape(code)}
                    </div>

                    <p class="muted">
                    Отправь этот код покупателю.
                    Повторно использовать его
                    будет нельзя.
                    </p>

                    </div>

                    <a class="btn"
                       href="/admin">
                       Вернуться в админку
                    </a>
                    """
                )
            )


        # ====================================================
        # DELETE PURCHASE CODE
        # ====================================================

        if path == "/admin/delete-purchase":

            try:

                purchase_id = int(
                    q.get(
                        "id",
                        ["0"]
                    )[0]
                )

            except ValueError:

                purchase_id = 0


            with db() as c:

                c.execute(
                    """
                    DELETE FROM purchase_codes
                    WHERE id=%s
                    """,
                    (
                        purchase_id,
                    )
                )


            return self.redirect(
                "/admin"
            )


        # ====================================================
        # USER ID
        # ====================================================

        try:

            user_id = int(
                q.get(
                    "id",
                    ["0"]
                )[0]
            )

        except ValueError:

            user_id = 0


        # ====================================================
        # TOGGLE USER
        # ====================================================

        if path == "/admin/toggle":

            with db() as c:

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
                    (
                        user_id,
                    )
                )


            return self.redirect(
                "/admin"
            )


        # ====================================================
        # RESET HWID
        # ====================================================

        if path == "/admin/reset-hwid":

            with db() as c:

                c.execute(
                    """
                    UPDATE users
                    SET hwid=NULL
                    WHERE id=%s
                    """,
                    (
                        user_id,
                    )
                )


            return self.redirect(
                "/admin"
            )


        # ====================================================
        # SET HWID
        # ====================================================

        if path == "/admin/set-hwid":

            hwid = q.get(
                "hwid",
                [""]
            )[0].strip()


            with db() as c:

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


            return self.redirect(
                "/admin"
            )


        # ====================================================
        # SET EXPIRY
        # ====================================================

        if path == "/admin/set-expiry":

            expires = parse_datetime(
                q.get(
                    "expires_at",
                    [""]
                )[0]
            )


            with db() as c:

                c.execute(
                    """
                    UPDATE users
                    SET expires_at=%s
                    WHERE id=%s
                    """,
                    (
                        expires,
                        user_id
                    )
                )


            return self.redirect(
                "/admin"
            )


        # ====================================================
        # DELETE USER
        # ====================================================

        if path == "/admin/delete":

            with db() as c:

                c.execute(
                    """
                    DELETE FROM users
                    WHERE id=%s
                    """,
                    (
                        user_id,
                    )
                )


            return self.redirect(
                "/admin"
            )


        # ====================================================
        # UNKNOWN ADMIN ACTION
        # ====================================================

        self.send_response(
            404
        )

        self.end_headers()


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    init_db()

    print(
        f"ColorBooster server listening "
        f"on {HOST}:{PORT}"
    )

    server = ThreadingHTTPServer(
        (
            HOST,
            PORT
        ),
        Handler
    )

    server.serve_forever()
