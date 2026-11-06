
        # Every admin action below requires a valid session.
        if path.startswith("/admin/") and not is_admin(self):
            return self.send_html(page("Ошибка", '<section class="panel"><h1>Требуется вход</h1><a href="/admin/login">Войти</a></section>'), 401)

        def form_int(name):
            try:
                return int(q.get(name, ["0"])[0])
            except (ValueError, TypeError):
                return 0

        if path == "/admin/create-purchase":
            duration = form_int("duration_days")
            if duration not in (0, 7, 14, 30):
                return self.send_html(page("Ошибка", "<h1>Неверный срок</h1>"), 400)

            for _ in range(10):
                code = make_purchase_code()
                try:
                    with db() as c:
                        c.execute("""
                            INSERT INTO purchase_codes(code,duration_days)
                            VALUES(%s,%s)
                        """, (code, duration))
                    break
                except psycopg.errors.UniqueViolation:
                    continue
            else:
                return self.send_html(page("Ошибка", "<h1>Не удалось создать код</h1>"), 500)

            return self.send_html(page(
                "Код покупки",
                f'<section class="panel"><h1>Код создан</h1><div class="purchase">{html.escape(code)}</div><p>Срок: {"Навсегда" if duration == 0 else str(duration) + " дней"}</p><a class="btn" href="/admin">Назад в админку</a></section>'
            ))

        if path == "/admin/delete-purchase":
            with db() as c:
                c.execute("DELETE FROM purchase_codes WHERE id=%s", (form_int("id"),))
            return self.redirect("/admin")

        if path == "/admin/ban-hwid":
            user_id = form_int("id")
            reason = q.get("reason", ["Заблокировано администратором"])[0].strip()[:300]
            with db() as c:
                user = c.execute("SELECT email,hwid FROM users WHERE id=%s", (user_id,)).fetchone()
                if user and user[1]:
                    hwid = user[1].strip()
                    c.execute("""
                        INSERT INTO banned_devices(hwid,hwid_hash,user_email,reason)
                        VALUES(%s,%s,%s,%s)
                        ON CONFLICT(hwid_hash) DO UPDATE SET
                            user_email=EXCLUDED.user_email,
                            reason=EXCLUDED.reason
                    """, (hwid, hwid_digest(hwid), user[0], reason or "Заблокировано администратором"))
            return self.redirect("/admin")

        if path == "/admin/unban-hwid":
            with db() as c:
                c.execute("DELETE FROM banned_devices WHERE id=%s", (form_int("id"),))
            return self.redirect("/admin")

        user_id = form_int("id")

        if path == "/admin/toggle":
            with db() as c:
                c.execute("""
                    UPDATE users SET status=CASE
                        WHEN status='blocked' THEN 'active' ELSE 'blocked'
                    END WHERE id=%s
                """, (user_id,))
            return self.redirect("/admin")

        if path == "/admin/reset-hwid":
            with db() as c:
                c.execute("UPDATE users SET hwid=NULL WHERE id=%s", (user_id,))
            return self.redirect("/admin")

        if path == "/admin/set-hwid":
            hwid = q.get("hwid", [""])[0].strip()[:512]
            with db() as c:
                c.execute("UPDATE users SET hwid=%s WHERE id=%s", (hwid or None, user_id))
            return self.redirect("/admin")

        if path == "/admin/set-expiry":
            expires = parse_datetime(q.get("expires_at", [""])[0])
            with db() as c:
                c.execute("UPDATE users SET expires_at=%s WHERE id=%s", (expires, user_id))
            return self.redirect("/admin")

        if path == "/admin/delete":
            with db() as c:
                c.execute("DELETE FROM users WHERE id=%s", (user_id,))
            return self.redirect("/admin")

        return self.send_html(page("404", "<section class='panel'><h1>Неизвестное действие</h1></section>"), 404)


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    if not ADMIN_PASSWORD:
        raise RuntimeError("Set ADMIN_PASSWORD in Render Environment")
    init_db()
    print(f"ColorBooster server listening on {HOST}:{PORT}")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.serve_forever()
