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
PURCHASE_PREFIX = "CB-PURCHASE"
SESSIONS = set()

def now():
    return datetime.now(timezone.utc)

def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured in Render Environment")
    return psycopg.connect(DATABASE_URL)

def password_hash(password):
    # Compatible with the earlier ColorBooster backend.
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), b"ColorBooster-2026", 120000
    ).hex()

def hwid_digest(hwid):
    return hashlib.sha256(hwid.strip().encode("utf-8")).hexdigest()

def make_purchase_code():
    return PURCHASE_PREFIX + "-" + secrets.token_hex(4).upper()

def make_license(email, expires_at):
    if not LICENSE_SECRET:
        raise RuntimeError("Set LICENSE_SECRET in Render Environment")
    if expires_at is None:
        expiry = 0xFFFFFFFF
    else:
        expiry = int(expires_at.timestamp())
    payload = f"{email.lower()}|{expiry}"
    signature = hmac.new(
        LICENSE_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
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
                first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen TIMESTAMPTZ
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS purchase_codes (
                id BIGSERIAL PRIMARY KEY,
                code TEXT UNIQUE NOT NULL,
                duration_days INTEGER NOT NULL DEFAULT 30,
                used BOOLEAN NOT NULL DEFAULT FALSE,
                used_by TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                used_at TIMESTAMPTZ
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS banned_devices (
                id BIGSERIAL PRIMARY KEY,
                hwid TEXT NOT NULL,
                hwid_hash TEXT UNIQUE NOT NULL,
                user_email TEXT,
                reason TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)

def page(title, body):
    return """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{}</title><style>
