"""
SatyaVani — Immutable Audit Log
=================================
Every admin action is recorded with:
  - HMAC-SHA3-256 chain hash (each entry hashes prev_hash + payload)
  - Timestamp (UTC, microsecond precision)
  - Action category, description
  - Hashed admin identity (SHA-256 of username — not stored plaintext)
  - Report token (hashed) if applicable
  - IP fingerprint (SHA-256 of IP — never stored raw)
  - Session token hash

This provides a tamper-evident audit trail: if any entry is modified,
the chain hash will break for all subsequent entries.
"""

import hashlib, hmac, json
from datetime import datetime, timezone
from database import get_db

# ── Action Categories ──────────────────────────────────────────────────────────
class AuditAction:
    # Auth
    ADMIN_LOGIN_OK    = "AUTH:LOGIN_SUCCESS"
    ADMIN_LOGIN_FAIL  = "AUTH:LOGIN_FAILURE"
    ADMIN_LOGOUT      = "AUTH:LOGOUT"
    ADMIN_2FA_OK      = "AUTH:2FA_SUCCESS"
    ADMIN_2FA_FAIL    = "AUTH:2FA_FAILURE"
    SESSION_EXPIRED   = "AUTH:SESSION_EXPIRED"
    LOCKOUT_TRIGGERED = "AUTH:LOCKOUT_TRIGGERED"
    LOCKOUT_CLEARED   = "AUTH:LOCKOUT_CLEARED"
    PW_CHANGED        = "AUTH:PASSWORD_CHANGED"
    TOTP_ENROLLED     = "AUTH:2FA_ENROLLED"

    # Report Management
    REPORT_VIEWED     = "REPORT:VIEWED"
    REPORT_UPDATED    = "REPORT:STATUS_CHANGED"
    REPORT_PUBLISHED  = "REPORT:PUBLISHED"
    REPORT_VERIFIED   = "REPORT:VERIFIED"
    REPORT_FLAGGED    = "REPORT:FLAGGED"
    REPORT_DELETED    = "REPORT:DELETED"
    FILE_DOWNLOADED   = "FILE:DOWNLOADED"
    NOTE_ADDED        = "REPORT:NOTE_ADDED"

    # System
    SETTINGS_CHANGED  = "SYSTEM:SETTINGS_CHANGED"
    EXPORT_TRIGGERED  = "SYSTEM:EXPORT"
    DB_INIT           = "SYSTEM:DB_INIT"


def _get_chain_tip(db) -> str:
    """Get the hash of the most recent audit entry (for chaining)."""
    row = db.execute(
        "SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row['chain_hash'] if row else 'GENESIS:satyavani:v1'


def _compute_chain_hash(prev_hash: str, payload: dict, hmac_key: str) -> str:
    """HMAC-SHA3-256 of (prev_hash + JSON payload), keyed by app secret."""
    msg = (prev_hash + json.dumps(payload, sort_keys=True, ensure_ascii=True)).encode('utf-8')
    return hmac.new(hmac_key.encode(), msg, 'sha3_256').hexdigest()


def _hash_identity(value: str) -> str:
    """One-way SHA-256 of an identity value (username, IP). Not reversible."""
    return hashlib.sha256(f"satyavani:identity:{value}".encode()).hexdigest()[:32]


def log_action(
    action: str,
    description: str,
    admin_username: str = 'system',
    report_token: str = None,
    ip_address: str = None,
    session_id: str = None,
    extra: dict = None,
    hmac_key: str = ''
) -> int:
    """
    Write a tamper-evident audit log entry. Returns the new entry ID.
    
    - admin_username is stored as a one-way hash (SHA-256)
    - ip_address is stored as a one-way hash — never stored raw
    - report_token is stored as a one-way hash
    - chain_hash links this entry to the previous one
    """
    from crypto_engine import now_iso
    db = get_db()

    ts      = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')
    admin_h = _hash_identity(admin_username)
    ip_h    = _hash_identity(ip_address or 'unknown')
    token_h = _hash_identity(report_token) if report_token else None
    sess_h  = hashlib.sha256((session_id or '').encode()).hexdigest()[:16]

    payload = {
        'action':    action,
        'desc':      description,
        'admin':     admin_h,
        'ip':        ip_h,
        'token':     token_h,
        'session':   sess_h,
        'ts':        ts,
        'extra':     extra or {},
    }

    prev_hash  = _get_chain_tip(db)
    chain_hash = _compute_chain_hash(prev_hash, payload, hmac_key or 'default')

    db.execute("""
        INSERT INTO audit_log
            (action, description, admin_hash, ip_hash, report_token_hash,
             session_hash, extra_json, timestamp, chain_hash, prev_hash)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        action, description, admin_h, ip_h, token_h,
        sess_h, json.dumps(extra or {}), ts, chain_hash, prev_hash
    ))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.close()
    return new_id


def verify_audit_chain(hmac_key: str = '') -> dict:
    """
    Verify the entire audit log chain integrity.
    Returns {valid: bool, total: int, broken_at: id | None, message: str}
    """
    db = get_db()
    entries = db.execute(
        "SELECT * FROM audit_log ORDER BY id ASC"
    ).fetchall()
    db.close()

    if not entries:
        return {'valid': True, 'total': 0, 'broken_at': None, 'message': 'Empty log'}

    prev_hash = 'GENESIS:satyavani:v1'
    for e in entries:
        payload = {
            'action':  e['action'],
            'desc':    e['description'],
            'admin':   e['admin_hash'],
            'ip':      e['ip_hash'],
            'token':   e['report_token_hash'],
            'session': e['session_hash'],
            'ts':      e['timestamp'],
            'extra':   json.loads(e['extra_json'] or '{}'),
        }
        expected = _compute_chain_hash(prev_hash, payload, hmac_key or 'default')
        if not hmac.compare_digest(expected, e['chain_hash']):
            return {
                'valid': False, 'total': len(entries),
                'broken_at': e['id'],
                'message': f"Chain broken at entry #{e['id']} — possible tampering detected!"
            }
        prev_hash = e['chain_hash']

    return {
        'valid': True, 'total': len(entries), 'broken_at': None,
        'message': f"All {len(entries)} entries verified. Chain intact."
    }
