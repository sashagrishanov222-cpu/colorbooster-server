import os, html, json, secrets, hashlib, base64
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import psycopg

HOST='0.0.0.0'; PORT=int(os.environ.get('PORT','8765'))
DATABASE_URL=os.environ.get('DATABASE_URL','')
ADMIN_USER=os.environ.get('ADMIN_USER','admin')
ADMIN_PASSWORD=os.environ.get('ADMIN_PASSWORD','change-me')
SESSIONS=set()

def db():
    if not DATABASE_URL: raise RuntimeError('DATABASE_URL is not configured')
    return psycopg.connect(DATABASE_URL)

def init_db():
    with db() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS users(
            id BIGSERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,
            hwid TEXT,status TEXT NOT NULL DEFAULT 'active',expires_at TIMESTAMPTZ,
            activation_key TEXT,first_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)''')
        c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'")
        c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ")
        c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS activation_key TEXT")
        c.execute('''CREATE TABLE IF NOT EXISTS activation_keys(
            id BIGSERIAL PRIMARY KEY,key TEXT UNIQUE NOT NULL,expires_at TIMESTAMPTZ,
            max_uses INTEGER NOT NULL DEFAULT 1,uses INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)''')

def ph(p):
    d=hashlib.pbkdf2_hmac('sha256',p.encode(),b'ColorBooster-2026',120000)
    return base64.b64encode(d).decode()

def dt(v):
    v=(v or '').strip()
    if not v: return None
    try: return datetime.strptime(v,'%Y-%m-%dT%H:%M').replace(tzinfo=timezone.utc)
    except ValueError: return None

def fmt(v): return '—' if v is None else v.strftime('%Y-%m-%d %H:%M UTC') if hasattr(v,'strftime') else str(v)

def page(t,b): return f'''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(t)}</title><style>
body{{font-family:Arial;background:#101216;color:#eee;margin:0}}.box{{max-width:1250px;margin:30px auto;background:#1b1e24;padding:28px;border-radius:14px}}input{{box-sizing:border-box;padding:9px;border-radius:7px;border:1px solid #444;background:#111;color:#fff}}.full{{width:100%;margin:7px 0 15px}}button,.btn{{display:inline-block;padding:9px 13px;border:0;border-radius:7px;background:#4d7cff;color:#fff;text-decoration:none;cursor:pointer}}.danger{{background:#b63b3b}}.gray{{background:#555}}.green{{background:#287a45}}table{{width:100%;border-collapse:collapse;margin-top:18px}}td,th{{padding:8px;border-bottom:1px solid #383c44;text-align:left;vertical-align:top}}code{{word-break:break-all}}.badge{{padding:4px 8px;border-radius:12px;background:#285d39}}.blocked{{background:#7b2e2e}}.expired{{background:#765b25}}.actions{{display:flex;gap:6px;flex-wrap:wrap}}.card{{background:#15181d;border:1px solid #30343c;border-radius:10px;padding:15px;margin:15px 0}}.muted{{color:#aaa}}</style><body><div class="box">{b}</div></body></html>'''

def admin(h):
    return any(x.strip().startswith('cb_admin=') and x.strip().split('=',1)[1] in SESSIONS for x in h.headers.get('Cookie','').split(';'))

def keygen():
    a='ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return 'CB-'+'-'.join(''.join(secrets.choice(a) for _ in range(5)) for _ in range(4))

def red(h): h.send_response(303); h.send_header('Location','/admin'); h.end_headers()

class H(BaseHTTPRequestHandler):
    def log_message(self,f,*a): print(f%a)
    def html(self,x,s=200,headers=()):
        d=x.encode(); self.send_response(s); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(d)))
        for k,v in headers:self.send_header(k,v)
        self.end_headers(); self.wfile.write(d)
    def js(self,x,s=200):
        d=json.dumps(x,ensure_ascii=False).encode(); self.send_response(s); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(d))); self.end_headers(); self.wfile.write(d)
    def body(self): return self.rfile.read(int(self.headers.get('Content-Length','0')))
    def do_GET(self):
        p=urlparse(self.path).path; q=parse_qs(urlparse(self.path).query)
        if p=='/': return self.html(page('ColorBooster','<h1>ColorBooster</h1><p>Сервер регистрации и авторизации.</p><a class="btn" href="/register">Регистрация</a> <a class="btn" href="/admin">Админ-панель</a>'))
        if p=='/register': return self.html(page('Регистрация','''<h1>Регистрация</h1><form method="post" action="/register"><label>Почта</label><input class="full" name="email" type="email" required><label>Пароль</label><input class="full" name="password" type="password" minlength="6" required><label>Ключ активации</label><input class="full" name="activation_key" required><button>Зарегистрироваться</button></form><p class="muted">Для регистрации нужен действующий ключ.</p>'''))
        if p=='/admin/login': return self.html(page('Вход','''<h1>Админ-панель</h1><form method="post" action="/admin/login"><label>Логин</label><input class="full" name="user" required><label>Пароль</label><input class="full" name="password" type="password" required><button>Войти</button></form>'''))
        if p=='/admin/logout':
            tok='';
            for x in self.headers.get('Cookie','').split(';'):
                if x.strip().startswith('cb_admin='): tok=x.strip().split('=',1)[1]
            SESSIONS.discard(tok); return self.html(page('Выход','<h1>Вы вышли</h1>'),headers=[('Set-Cookie','cb_admin=; Max-Age=0; Path=/')])
        if p=='/admin':
            if not admin(self): return self.html(page('Админ','<h1>Требуется вход</h1><a class="btn" href="/admin/login">Войти</a>'),401)
            return self.render(q.get('q',[''])[0].strip())
        self.send_response(404); self.end_headers()
    def render(self,search=''):
        with db() as c:
            if search:
                like='%'+search.lower()+'%'; users=c.execute('''SELECT id,email,hwid,status,expires_at,activation_key,first_seen,last_seen FROM users WHERE LOWER(email) LIKE %s OR LOWER(COALESCE(hwid,'')) LIKE %s ORDER BY id DESC''',(like,like)).fetchall()
            else: users=c.execute('SELECT id,email,hwid,status,expires_at,activation_key,first_seen,last_seen FROM users ORDER BY id DESC').fetchall()
            keys=c.execute('SELECT id,key,expires_at,max_uses,uses,created_at FROM activation_keys ORDER BY id DESC').fetchall()
        now=datetime.now(timezone.utc); rows=''
        for r in users:
            expired=r[4] is not None and r[4]<=now; badge='<span class="badge blocked">Заблокирован</span>' if r[3]=='blocked' else '<span class="badge expired">Истёк</span>' if expired else '<span class="badge">Активен</span>'
            tg='Разблокировать' if r[3]=='blocked' else 'Заблокировать'; tc='' if r[3]=='blocked' else 'danger'
            rows+=f'''<tr><td>{r[0]}</td><td>{html.escape(r[1])}</td><td><code>{html.escape(r[2] or 'не привязан')}</code></td><td>{badge}</td><td>{html.escape(fmt(r[4]))}</td><td>{html.escape(r[5] or '—')}</td><td>{html.escape(fmt(r[6]))}</td><td>{html.escape(fmt(r[7]))}</td><td><div class="actions"><form method="post" action="/admin/toggle"><input type="hidden" name="id" value="{r[0]}"><button class="{tc}">{tg}</button></form><form method="post" action="/admin/reset-hwid"><input type="hidden" name="id" value="{r[0]}"><button class="gray">Сбросить HWID</button></form><form method="post" action="/admin/delete" onsubmit="return confirm('Удалить пользователя?')"><input type="hidden" name="id" value="{r[0]}"><button class="danger">Удалить</button></form></div><form method="post" action="/admin/set-expiry" style="margin-top:7px"><input type="hidden" name="id" value="{r[0]}"><input name="expires_at" type="datetime-local"><button>Установить срок</button></form><form method="post" action="/admin/set-hwid" style="margin-top:7px"><input type="hidden" name="id" value="{r[0]}"><input name="hwid" placeholder="Новый HWID"><button>Установить HWID</button></form></td></tr>'''
        if not rows: rows='<tr><td colspan="9">Пользователей не найдено.</td></tr>'
        kr=''.join(f'''<tr><td>{k[0]}</td><td><code>{html.escape(k[1])}</code></td><td>{html.escape(fmt(k[2]))}</td><td>{k[3]}</td><td>{k[4]}</td><td>{html.escape(fmt(k[5]))}</td><td><form method="post" action="/admin/delete-key" onsubmit="return confirm('Удалить ключ?')"><input type="hidden" name="id" value="{k[0]}"><button class="danger">Удалить</button></form></td></tr>''' for k in keys) or '<tr><td colspan="7">Ключей пока нет.</td></tr>'
        b=f'''<h1>Админ-панель ColorBooster</h1><p>Пользователей: <b>{len(users)}</b> | Ключей: <b>{len(keys)}</b> <a class="btn" href="/admin">Обновить</a> <a class="btn gray" href="/admin/logout">Выйти</a></p><div class="card"><h2>Поиск</h2><form method="get" action="/admin"><input name="q" value="{html.escape(search)}" placeholder="Почта или HWID"><button>Найти</button> <a class="btn gray" href="/admin">Сбросить</a></form></div><div class="card"><h2>Создать ключ активации</h2><form method="post" action="/admin/create-key"><input name="expires_at" type="datetime-local"><input name="max_uses" type="number" min="1" value="1"><button class="green">Создать ключ</button></form><p class="muted">Пустой срок = без ограничения по дате.</p></div><h2>Пользователи</h2><table><tr><th>ID</th><th>Почта</th><th>HWID</th><th>Статус</th><th>Срок</th><th>Ключ</th><th>Первый</th><th>Последний</th><th>Управление</th></tr>{rows}</table><hr><h2>Ключи активации</h2><table><tr><th>ID</th><th>Ключ</th><th>Срок</th><th>Макс.</th><th>Исп.</th><th>Создан</th><th>Управление</th></tr>{kr}</table>'''
        return self.html(page('Админ-панель',b))
    def do_POST(self):
        p=urlparse(self.path).path
        if p=='/api/login':
            try:d=json.loads(self.body().decode())
            except Exception:return self.js({'error':'Некорректный JSON'},400)
            e=str(d.get('email','')).strip().lower(); pw=str(d.get('password','')); hw=str(d.get('hwid','')).strip()
            if not e or not pw or not hw:return self.js({'error':'Не хватает данных'},400)
            with db() as c:
                r=c.execute('SELECT id,password_hash,hwid,status,expires_at FROM users WHERE email=%s',(e,)).fetchone()
                if not r or not secrets.compare_digest(r[1],ph(pw)):return self.js({'error':'Неверная почта или пароль'},401)
                if r[3]=='blocked':return self.js({'error':'Аккаунт заблокирован администратором'},403)
                if r[4] is not None and r[4]<=datetime.now(timezone.utc):return self.js({'error':'Срок действия лицензии истёк'},403)
                if r[2] and not secrets.compare_digest(r[2],hw):return self.js({'error':'HWID этого аккаунта привязан к другому компьютеру'},403)
                c.execute('UPDATE users SET hwid=%s,last_seen=CURRENT_TIMESTAMP WHERE id=%s',(hw,r[0]))
            return self.js({'ok':True,'hwid':hw})
        q=parse_qs(self.body().decode())
        if p=='/register':
            e=q.get('email',[''])[0].strip().lower(); pw=q.get('password',[''])[0]; ak=q.get('activation_key',[''])[0].strip().upper()
            if not e or '@' not in e:return self.html(page('Ошибка','<h1>Некорректная почта</h1>'),400)
            if len(pw)<6:return self.html(page('Ошибка','<h1>Пароль должен быть не короче 6 символов</h1>'),400)
            with db() as c:
                k=c.execute('SELECT id,key,expires_at,max_uses,uses FROM activation_keys WHERE key=%s',(ak,)).fetchone()
                if not k:return self.html(page('Ошибка','<h1>Неверный ключ активации</h1>'),400)
                if k[2] is not None and k[2]<=datetime.now(timezone.utc):return self.html(page('Ошибка','<h1>Срок действия ключа истёк</h1>'),400)
                if k[4]>=k[3]:return self.html(page('Ошибка','<h1>Ключ уже использован</h1>'),400)
                if c.execute('SELECT id FROM users WHERE email=%s',(e,)).fetchone():return self.html(page('Ошибка','<h1>Эта почта уже зарегистрирована</h1>'),409)
                c.execute('INSERT INTO users(email,password_hash,activation_key,expires_at) VALUES(%s,%s,%s,%s)',(e,ph(pw),ak,k[2])); c.execute('UPDATE activation_keys SET uses=uses+1 WHERE id=%s',(k[0],))
            return self.html(page('Готово','<h1>Регистрация завершена</h1><p>Теперь можно войти в программу.</p>'))
        if p=='/admin/login':
            u=q.get('user',[''])[0].strip(); pw=q.get('password',[''])[0].strip()
            if not secrets.compare_digest(u,ADMIN_USER) or not secrets.compare_digest(pw,ADMIN_PASSWORD):return self.html(page('Ошибка','<h1>Неверный логин или пароль</h1>'),401)
            tok=secrets.token_urlsafe(32); SESSIONS.add(tok); self.send_response(303); self.send_header('Location','/admin'); self.send_header('Set-Cookie',f'cb_admin={tok}; HttpOnly; Path=/; SameSite=Lax'); self.end_headers(); return
        if p.startswith('/admin/') and not admin(self):return self.html(page('Ошибка','<h1>Сначала войдите</h1>'),401)
        try: uid=int(q.get('id',['0'])[0])
        except: uid=0
        with db() as c:
            if p=='/admin/toggle': c.execute("UPDATE users SET status=CASE WHEN status='blocked' THEN 'active' ELSE 'blocked' END WHERE id=%s",(uid,))
            elif p=='/admin/reset-hwid': c.execute('UPDATE users SET hwid=NULL WHERE id=%s',(uid,))
            elif p=='/admin/set-hwid':
                hw=q.get('hwid',[''])[0].strip()
                if not hw:return self.html(page('Ошибка','<h1>HWID не введён</h1>'),400)
                c.execute('UPDATE users SET hwid=%s WHERE id=%s',(hw,uid))
            elif p=='/admin/set-expiry': c.execute('UPDATE users SET expires_at=%s WHERE id=%s',(dt(q.get('expires_at',[''])[0]),uid))
            elif p=='/admin/delete': c.execute('DELETE FROM users WHERE id=%s',(uid,))
            elif p=='/admin/create-key':
                try: uses=max(1,min(int(q.get('max_uses',['1'])[0]),100000))
                except: uses=1
                c.execute('INSERT INTO activation_keys(key,expires_at,max_uses) VALUES(%s,%s,%s)',(keygen(),dt(q.get('expires_at',[''])[0]),uses))
            elif p=='/admin/delete-key': c.execute('DELETE FROM activation_keys WHERE id=%s',(uid,))
            else:self.send_response(404);self.end_headers();return
        red(self)

if __name__=='__main__':
    init_db(); print(f'Listening on {HOST}:{PORT}'); ThreadingHTTPServer((HOST,PORT),H).serve_forever()
