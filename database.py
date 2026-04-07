"""
SatyaVani — Database Layer (SQLite3 + WAL + FK enforcement)
Enhanced schema with encrypted fields, audit log, lockout table, admin sessions.
"""
import sqlite3, os
from config import Config

def get_db():
    conn = sqlite3.connect(Config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA secure_delete=ON")    # zero-fill deleted pages
    conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
    return conn

def init_db():
    os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
    /* ── Reports — all sensitive text fields AES-256-GCM encrypted ─────── */
    CREATE TABLE IF NOT EXISTS reports (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        token_id        TEXT    UNIQUE NOT NULL,   -- SHA3 hash stored (token_id part)
        title_enc       TEXT    NOT NULL,          -- AES-256-GCM encrypted
        description_enc TEXT    NOT NULL,          -- AES-256-GCM encrypted
        category        TEXT    NOT NULL,          -- NOT encrypted (needed for indexing)
        subcategory_enc TEXT    DEFAULT '',
        province        TEXT    DEFAULT '',        -- NOT encrypted (needed for stats)
        district_enc    TEXT    DEFAULT '',
        urgency         TEXT    DEFAULT 'medium',  -- NOT encrypted (needed for sorting)
        status          TEXT    DEFAULT 'received',
        language        TEXT    DEFAULT 'en',
        created_at      TEXT    NOT NULL,
        updated_at      TEXT    NOT NULL,
        admin_notes_enc TEXT    DEFAULT '',        -- AES-256-GCM encrypted
        views           INTEGER DEFAULT 0,
        is_published    INTEGER DEFAULT 0,
        is_verified     INTEGER DEFAULT 0,
        is_flagged      INTEGER DEFAULT 0,
        content_hash    TEXT    DEFAULT ''         -- SHA3-256 of original plaintext
    );

    /* ── Attachments — files stored encrypted on disk ───────────────────── */
    CREATE TABLE IF NOT EXISTS attachments (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id       INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
        filename_enc    TEXT    NOT NULL,          -- encrypted original filename
        stored_name     TEXT    NOT NULL,          -- random hex .sv file on disk
        file_type       TEXT    NOT NULL,
        file_size       INTEGER NOT NULL,          -- original size
        enc_size        INTEGER DEFAULT 0,         -- encrypted size
        mime_type_enc   TEXT    DEFAULT '',
        sha3_digest     TEXT    DEFAULT '',        -- SHA3-256 of plaintext file
        uploaded_at     TEXT    NOT NULL
    );

    /* ── Status History ─────────────────────────────────────────────────── */
    CREATE TABLE IF NOT EXISTS status_updates (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id   INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
        old_status  TEXT    NOT NULL,
        new_status  TEXT    NOT NULL,
        note_enc    TEXT    DEFAULT '',            -- encrypted note
        updated_at  TEXT    NOT NULL
    );

    /* ── Admin Users ────────────────────────────────────────────────────── */
    CREATE TABLE IF NOT EXISTS admin_users (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        username        TEXT    UNIQUE NOT NULL,
        password_hash   TEXT    NOT NULL,          -- PBKDF2-HMAC-SHA512
        totp_secret     TEXT    DEFAULT '',        -- base32 TOTP secret (if 2FA enrolled)
        totp_enabled    INTEGER DEFAULT 0,
        created_at      TEXT    NOT NULL,
        last_login      TEXT    DEFAULT '',
        force_pw_change INTEGER DEFAULT 0
    );

    /* ── Admin Sessions (server-side session store) ─────────────────────── */
    CREATE TABLE IF NOT EXISTS admin_sessions (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_token   TEXT    UNIQUE NOT NULL,   -- CSPRNG token
        admin_id        INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
        ip_hash         TEXT    NOT NULL,          -- SHA-256(ip) — never raw
        user_agent_hash TEXT    NOT NULL,
        created_at      TEXT    NOT NULL,
        last_active     TEXT    NOT NULL,
        expires_at      TEXT    NOT NULL,
        is_valid        INTEGER DEFAULT 1,
        totp_verified   INTEGER DEFAULT 0          -- 2FA step completed
    );

    /* ── Login Lockout (brute-force protection) ─────────────────────────── */
    CREATE TABLE IF NOT EXISTS login_attempts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_hash     TEXT    NOT NULL,
        username    TEXT    NOT NULL,
        success     INTEGER NOT NULL,
        attempted_at TEXT   NOT NULL
    );

    /* ── Audit Log (tamper-evident chain) ───────────────────────────────── */
    CREATE TABLE IF NOT EXISTS audit_log (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        action              TEXT    NOT NULL,
        description         TEXT    NOT NULL,
        admin_hash          TEXT    NOT NULL,  -- SHA-256(username) — not reversible
        ip_hash             TEXT    NOT NULL,  -- SHA-256(ip) — not reversible
        report_token_hash   TEXT,              -- SHA-256(token) if applicable
        session_hash        TEXT    DEFAULT '',
        extra_json          TEXT    DEFAULT '{}',
        timestamp           TEXT    NOT NULL,
        chain_hash          TEXT    NOT NULL,  -- HMAC-SHA3-256 linking to prev
        prev_hash           TEXT    NOT NULL
    );

    /* ── Rate Limit (persistent, survives restart) ──────────────────────── */
    CREATE TABLE IF NOT EXISTS rate_limit (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_hash     TEXT    NOT NULL,
        action      TEXT    NOT NULL,
        timestamp   TEXT    NOT NULL
    );

    /* ── Site Settings ──────────────────────────────────────────────────── */
    CREATE TABLE IF NOT EXISTS site_settings (
        key     TEXT PRIMARY KEY,
        value   TEXT
    );

    /* ── Indices ─────────────────────────────────────────────────────────── */
    CREATE INDEX IF NOT EXISTS idx_reports_token    ON reports(token_id);
    CREATE INDEX IF NOT EXISTS idx_reports_status   ON reports(status);
    CREATE INDEX IF NOT EXISTS idx_reports_category ON reports(category);
    CREATE INDEX IF NOT EXISTS idx_att_report_id    ON attachments(report_id);
    CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_log(action);
    CREATE INDEX IF NOT EXISTS idx_audit_ts         ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_sessions_token   ON admin_sessions(session_token);
    CREATE INDEX IF NOT EXISTS idx_sessions_admin   ON admin_sessions(admin_id);
    CREATE INDEX IF NOT EXISTS idx_login_ip         ON login_attempts(ip_hash);
    CREATE INDEX IF NOT EXISTS idx_rate_ip          ON rate_limit(ip_hash, action);
    """)

    defaults = {
        'site_active':       '1',
        'submission_open':   '1',
        'announcement':      '',
        'max_failed_logins': '5',
        'lockout_minutes':   '30',
        'session_hours':     '4',
    }
    for k, v in defaults.items():
        c.execute("INSERT OR IGNORE INTO site_settings(key,value) VALUES(?,?)", (k, v))

    conn.commit()
    conn.close()
