import os, html, json, secrets, hashlib, base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import psycopg

HOST='0.0.0.0'
PORT=int(os.environ.get('PORT','8765'))
DATABASE_URL=os.environ.get('DATABASE_URL','')
ADMIN_USER=os.environ.get('ADMIN_USER','admin')
ADMIN_PASSWORD=os.environ.get('ADMIN_PASSWORD','1234')
SESSIONS=set()

def db():
    if not DATABASE_URL: raise RuntimeError('DATABASE_URL is not configured')
    return psycopg.connect(DATABASE_URL)

def init_db():
    with db() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS users(
            id BIGSERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,
            hwid TEXT,status TEXT NOT NULL DEFAULT 'active',
            first_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)''')

def ph(p):
    d=hashlib.pbkdf2_hmac('sha256',p.encode(),b'ColorBooster-2026',120000)
    return base64.b64encode(d).decode()

def page(t,b): return f'''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(t)}</title><style>body{{font-family:Arial;background:#101216;color:#eee;margin:0}}.box{{max-width:1100px;margin:40px auto;background:#1b1e24;padding:28px;border-radius:14px}}input{{box-sizing:border-box;padding:10px;border-radius:7px;border:1px solid #444;background:#111;color:#fff}}.full{{width:100%;margin:7px 0 15px}}button,.btn{{display:inline-block;padding:9px 14px;border:0;border-radius:7px;background:#4d7cff;color:#fff;text-decoration:none;cursor:pointer}}table{{width:100%;border-collapse:collapse;margin-top:18px}}td,th{{padding:9px;border-bottom:1px solid #383c44;text-align:left}}code{{word-break:break-all}}</style><body><div class="box">{b}</div></body></html>'''

def admin(h):
    return any(x.strip().startswith('cb_admin=') and x.strip().split('=',1)[1] in SESSIONS for x in h.headers.get('Cookie','').split(';'))

class H(BaseHTTPRequestHandler):
    def log_message(self,f,*a): print(f%a)
    def html(self,x,s=200,headers=()):
        d=x.encode();self.send_response(s);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(d)))
        for k,v in headers:self.send_header(k,v)
        self.end_headers();self.wfile.write(d)
    def js(self,x,s=200):
        d=json.dumps(x,ensure_ascii=False).encode();self.send_response(s);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Content-Length',str(len(d)));self.end_headers();self.wfile.write(d)
    def body(self): return self.rfile.read(int(self.headers.get('Content-Length','0')))
    def do_GET(self):
        p=urlparse(self.path).path
        if p=='/': return self.html(page('ColorBooster','<h1>ColorBooster</h1><p>Сервер работает.</p><a class="btn" href="/register">Регистрация</a> <a class="btn" href="/admin">Админ-панель</a>'))
        if p=='/register': return self.html(page('Регистрация','''<h1>Регистрация</h1><form method="post"><label>Почта</label><input class="full" name="email" type="email" required><label>Пароль</label><input class="full" name="password" type="password" minlength="6" required><button>Зарегистрироваться</button></form>'''))
        if p=='/admin/login': return self.html(page('Админ','''<h1>Админ-панель</h1><form method="post"><label>Логин</label><input class="full" name="user"><label>Пароль</label><input class="full" name="password" type="password"><button>Войти</button></form>'''))
        if p=='/admin':
            if not admin(self): return self.html(page('Админ','<h1>Требуется вход</h1><a class="btn" href="/admin/login">Войти</a>'),401)
            with db() as c: rows=c.execute('SELECT id,email,hwid,status,first_seen,last_seen FROM users ORDER BY id DESC').fetchall()
            tr=''.join(f'<tr><td>{r[0]}</td><td>{html.escape(r[1])}</td><td><code>{html.escape(r[2] or "не привязан")}</code></td><td>{html.escape(r[3])}</td><td>{r[4]}</td><td>{r[5]}</td><td><form method="post" action="/admin/toggle"><input type="hidden" name="id" value="{r[0]}"><button>Статус</button></form><form method="post" action="/admin/reset"><input type="hidden" name="id" value="{r[0]}"><button>Сбросить HWID</button></form></td></tr>' for r in rows)
            return self.html(page('Админ',f'<h1>Пользователи</h1><p>Всего: {len(rows)}</p><table><tr><th>ID</th><th>Почта</th><th>HWID</th><th>Статус</th><th>Первый</th><th>Последний</th><th>Управление</th></tr>{tr}</table>'))
        self.send_response(404);self.end_headers()
    def do_POST(self):
        p=urlparse(self.path).path
        if p=='/api/login':
            try:d=json.loads(self.body().decode())
            except:return self.js({'error':'Некорректный JSON'},400)
            e=str(d.get('email','')).strip().lower();pw=str(d.get('password',''));hw=str(d.get('hwid','')).strip()
            if not e or not pw or not hw:return self.js({'error':'Не хватает данных'},400)
            with db() as c:
                r=c.execute('SELECT id,password_hash,hwid,status FROM users WHERE email=%s',(e,)).fetchone()
                if not r or not secrets.compare_digest(r[1],ph(pw)):return self.js({'error':'Неверная почта или пароль'},401)
                if r[3]=='blocked':return self.js({'error':'Аккаунт заблокирован администратором'},403)
                if r[2] and not secrets.compare_digest(r[2],hw):return self.js({'error':'HWID этого аккаунта привязан к другому компьютеру'},403)
                c.execute('UPDATE users SET hwid=%s,last_seen=CURRENT_TIMESTAMP WHERE id=%s',(hw,r[0]))
            return self.js({'ok':True,'hwid':hw})
        q=parse_qs(self.body().decode())
        if p=='/register':
            e=q.get('email',[''])[0].strip().lower();pw=q.get('password',[''])[0]
            if not e or '@' not in e:return self.html(page('Ошибка','<h1>Некорректная почта</h1>'),400)
            if len(pw)<6:return self.html(page('Ошибка','<h1>Пароль должен быть не короче 6 символов</h1>'),400)
            try:
                with db() as c:c.execute('INSERT INTO users(email,password_hash) VALUES(%s,%s)',(e,ph(pw)))
            except psycopg.errors.UniqueViolation:return self.html(page('Ошибка','<h1>Почта уже зарегистрирована</h1>'),409)
            return self.html(page('Готово','<h1>Регистрация завершена</h1><p>Теперь можно войти в программу.</p>'))
        if p=='/admin/login':
            u=q.get('user',[''])[0];pw=q.get('password',[''])[0]
            if not secrets.compare_digest(u,ADMIN_USER) or not secrets.compare_digest(pw,ADMIN_PASSWORD):return self.html(page('Ошибка','<h1>Неверный логин или пароль</h1>'),401)
            tok=secrets.token_urlsafe(32);SESSIONS.add(tok);self.send_response(303);self.send_header('Location','/admin');self.send_header('Set-Cookie',f'cb_admin={tok}; HttpOnly; Path=/; SameSite=Lax');self.end_headers();return
        if p.startswith('/admin/'):
            if not admin(self):return self.html(page('Ошибка','<h1>Требуется вход</h1>'),401)
            uid=int(q.get('id',['0'])[0])
            with db() as c:
                if p=='/admin/toggle':c.execute("UPDATE users SET status=CASE WHEN status='blocked' THEN 'active' ELSE 'blocked' END WHERE id=%s",(uid,))
                elif p=='/admin/reset':c.execute('UPDATE users SET hwid=NULL WHERE id=%s',(uid,))
            self.send_response(303);self.send_header('Location','/admin');self.end_headers();return
        self.send_response(404);self.end_headers()

if __name__=='__main__':
    init_db();print(f'Listening on {HOST}:{PORT}');ThreadingHTTPServer((HOST,PORT),H).serve_forever()
