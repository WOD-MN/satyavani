"""
सत्यवाणी (SatyaVani) v2 — Hardened Anonymous Whistleblower Platform
=======================================================================
Security model:
  • All report text    → AES-256-GCM encrypted at rest
  • All uploaded files → AES-256-GCM encrypted on disk (per-file key)
  • Admin passwords    → PBKDF2-HMAC-SHA512, 480 000 iterations
  • Tracking tokens    → HMAC-SHA3-256 signed (tamper-proof)
  • Admin sessions     → server-side store, session token in cookie
  • 2FA               → RFC 6238 TOTP (Google Authenticator compatible)
  • Audit log         → HMAC-SHA3-256 chain (tamper-evident)
  • Brute force       → IP lockout after N failures (hashed IPs)
  • IP privacy        → Never stored raw anywhere
  • Rate limiting     → DB-backed, survives restart
  • Security headers  → CSP, HSTS, no-sniff, no-frame, referrer policy
"""

import os, sys, json, io, hashlib, hmac as _hmac
from datetime import datetime, timezone, timedelta
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, send_file, abort, g, make_response)

sys.path.insert(0, os.path.dirname(__file__))
from config  import Config
from database import get_db, init_db
from crypto_engine import (
    derive_master_key, encrypt_field, decrypt_field,
    encrypt_file, decrypt_file, secure_delete,
    hash_password, verify_password,
    generate_signed_token, verify_signed_token,
    generate_totp_secret, generate_totp, verify_totp, totp_provisioning_uri,
    secure_filename_store, is_allowed_extension, get_file_category,
    format_file_size, now_iso, sha3_text, generate_token
)
from audit_log import log_action, AuditAction, verify_audit_chain

# ── App Factory ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)

# ── Master encryption key (derived once at startup) ────────────────────────────
_MASTER_KEY = None
def get_master_key() -> bytes:
    global _MASTER_KEY
    if _MASTER_KEY is None:
        _MASTER_KEY = derive_master_key(app.config['SECRET_KEY'], 'reports:v1')
    return _MASTER_KEY

def get_audit_hmac() -> str:
    return app.config['SECRET_KEY']

# ── Constants ──────────────────────────────────────────────────────────────────
CATEGORIES = {
    'government':  {'label': 'Government & Bureaucracy', 'np': 'सरकार र प्रशासन', 'icon': '🏛️'},
    'police':      {'label': 'Police & Security Forces',  'np': 'प्रहरी र सुरक्षा',  'icon': '🚔'},
    'judiciary':   {'label': 'Judiciary & Courts',        'np': 'न्यायपालिका',        'icon': '⚖️'},
    'elections':   {'label': 'Elections & Political',     'np': 'निर्वाचन',            'icon': '🗳️'},
    'education':   {'label': 'Education Sector',          'np': 'शिक्षा क्षेत्र',     'icon': '🎓'},
    'health':      {'label': 'Health & Medicine',         'np': 'स्वास्थ्य',           'icon': '🏥'},
    'corporate':   {'label': 'Corporate & Business',      'np': 'व्यापार',             'icon': '💼'},
    'land':        {'label': 'Land & Property',           'np': 'जग्गा जमिन',         'icon': '🏘️'},
    'environment': {'label': 'Environment & Resources',   'np': 'वातावरण',             'icon': '🌿'},
    'media':       {'label': 'Media & Press',             'np': 'सञ्चारमाध्यम',        'icon': '📰'},
    'ngo':         {'label': 'NGO / INGO Sector',         'np': 'गैरसरकारी',           'icon': '🤝'},
    'banking':     {'label': 'Banking & Finance',         'np': 'बैंकिङ',              'icon': '🏦'},
    'military':    {'label': 'Military & Defense',        'np': 'सेना',                'icon': '🪖'},
    'other':       {'label': 'Other / Unclassified',      'np': 'अन्य',                'icon': '📁'},
}
PROVINCES = ['Koshi','Madhesh','Bagmati','Gandaki','Lumbini','Karnali','Sudurpashchim','Federal']
STATUS_FLOW = {
    'received':  {'label':'Received',      'color':'#3498db','icon':'📥'},
    'reviewing': {'label':'Under Review',  'color':'#f39c12','icon':'🔍'},
    'verified':  {'label':'Verified',      'color':'#27ae60','icon':'✅'},
    'published': {'label':'Published',     'color':'#8e44ad','icon':'📢'},
    'forwarded': {'label':'Forwarded',     'color':'#e67e22','icon':'➡️'},
    'closed':    {'label':'Closed',        'color':'#7f8c8d','icon':'🔒'},
    'rejected':  {'label':'Rejected',      'color':'#e74c3c','icon':'❌'},
}
URGENCY = {
    'critical':{'label':'Critical / Urgent','color':'#e74c3c'},
    'high':    {'label':'High Priority',    'color':'#e67e22'},
    'medium':  {'label':'Medium Priority',  'color':'#f1c40f'},
    'low':     {'label':'Low / General',    'color':'#27ae60'},
}

# ── Jinja globals ──────────────────────────────────────────────────────────────
app.jinja_env.globals.update(
    categories=CATEGORIES, status_flow=STATUS_FLOW,
    urgency_map=URGENCY, now=lambda: datetime.now(timezone.utc)
)

# ── Security Headers (applied to every response) ──────────────────────────────
@app.after_request
def apply_security_headers(resp):
    for k, v in Config.SECURITY_HEADERS.items():
        resp.headers[k] = v
    resp.headers['Content-Security-Policy'] = Config.CSP
    # Remove server fingerprinting
    resp.headers.pop('Server', None)
    resp.headers.pop('X-Powered-By', None)
    return resp

# ── IP helpers (never log raw IPs) ────────────────────────────────────────────
def _ip():
    """Get client IP from request, preferring X-Forwarded-For if behind proxy."""
    return (request.headers.get('X-Forwarded-For', request.remote_addr) or '').split(',')[0].strip()

def _ip_hash():
    return hashlib.sha256(f"satyavani:ip:{_ip()}".encode()).hexdigest()

def _ua_hash():
    ua = request.headers.get('User-Agent', '')
    return hashlib.sha256(ua.encode()).hexdigest()[:32]

# ── CSRF protection ────────────────────────────────────────────────────────────
def _csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = generate_token(32)
    return session['_csrf']

def _csrf_ok():
    t = request.form.get('csrf_token', '')
    return t and _hmac.compare_digest(t, session.get('_csrf', ''))

app.jinja_env.globals['csrf_token'] = _csrf_token

# ── DB-backed rate limiter ─────────────────────────────────────────────────────
def _rate_check(action: str, limit: int, window_secs: int = 3600) -> bool:
    """Returns True if request is within rate limit (allowed)."""
    db = get_db()
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_secs)).strftime('%Y-%m-%d %H:%M:%S')
    ih = _ip_hash()
    count = db.execute(
        "SELECT COUNT(*) FROM rate_limit WHERE ip_hash=? AND action=? AND timestamp>?",
        (ih, action, cutoff)
    ).fetchone()[0]
    if count >= limit:
        db.close()
        return False
    db.execute("INSERT INTO rate_limit(ip_hash,action,timestamp) VALUES(?,?,?)",
               (ih, action, now_iso()))
    # Clean old entries
    db.execute("DELETE FROM rate_limit WHERE timestamp < ?", (cutoff,))
    db.commit(); db.close()
    return True

# ── Admin session management ───────────────────────────────────────────────────
SESSION_COOKIE = 'sv_admin_session'
SESSION_HOURS  = 4

def _create_admin_session(admin_id: int, totp_verified: bool = False) -> str:
    token = generate_token(48)
    ts    = now_iso()
    exp   = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).strftime('%Y-%m-%d %H:%M:%S')
    db    = get_db()
    db.execute("""
        INSERT INTO admin_sessions(session_token,admin_id,ip_hash,user_agent_hash,
                                   created_at,last_active,expires_at,totp_verified)
        VALUES(?,?,?,?,?,?,?,?)
    """, (token, admin_id, _ip_hash(), _ua_hash(), ts, ts, exp, 1 if totp_verified else 0))
    db.commit(); db.close()
    return token

def _get_admin_session() -> dict | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    db  = get_db()
    now = now_iso()
    row = db.execute("""
        SELECT s.*, u.username, u.totp_enabled, u.force_pw_change
        FROM admin_sessions s
        JOIN admin_users u ON u.id = s.admin_id
        WHERE s.session_token=? AND s.is_valid=1 AND s.expires_at > ?
    """, (token, now)).fetchone()
    if row:
        db.execute("UPDATE admin_sessions SET last_active=? WHERE session_token=?",
                   (now, token))
        db.commit()
    db.close()
    return dict(row) if row else None

def _invalidate_session(token: str):
    db = get_db()
    db.execute("UPDATE admin_sessions SET is_valid=0 WHERE session_token=?", (token,))
    db.commit(); db.close()

# ── Brute-force lockout ────────────────────────────────────────────────────────
def _is_locked_out(username: str) -> bool:
    db  = get_db()
    max_fails = int(db.execute("SELECT value FROM site_settings WHERE key='max_failed_logins'").fetchone()['value'])
    lock_mins = int(db.execute("SELECT value FROM site_settings WHERE key='lockout_minutes'").fetchone()['value'])
    cutoff    = (datetime.now(timezone.utc) - timedelta(minutes=lock_mins)).strftime('%Y-%m-%d %H:%M:%S')
    ih = _ip_hash()
    fails = db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip_hash=? AND success=0 AND attempted_at>?",
        (ih, cutoff)
    ).fetchone()[0]
    db.close()
    return fails >= max_fails

def _record_login(username: str, success: bool):
    db = get_db()
    db.execute("INSERT INTO login_attempts(ip_hash,username,success,attempted_at) VALUES(?,?,?,?)",
               (_ip_hash(), username, 1 if success else 0, now_iso()))
    db.commit(); db.close()

# ── Admin auth decorator ───────────────────────────────────────────────────────
import functools
def admin_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        adm = _get_admin_session()
        if not adm:
            return redirect(url_for('admin_login'))
        if adm['totp_enabled'] and not adm['totp_verified']:
            return redirect(url_for('admin_2fa'))
        if adm['force_pw_change']:
            flash('You must change your password before continuing.', 'warning')
            return redirect(url_for('admin_settings'))
        g.admin = adm
        g.admin_session_token = request.cookies.get(SESSION_COOKIE)
        return fn(*args, **kwargs)
    return wrapper

# ── Encrypt / Decrypt helpers ──────────────────────────────────────────────────
def _enc(text: str) -> str:
    if not text: return ''
    return encrypt_field(text, get_master_key())

def _dec(enc: str) -> str:
    if not enc: return ''
    try: return decrypt_field(enc, get_master_key())
    except Exception: return '[Decryption Error — key mismatch or tampered data]'

# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    db    = get_db()
    stats = {
        'total':      db.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
        'verified':   db.execute("SELECT COUNT(*) FROM reports WHERE is_verified=1").fetchone()[0],
        'published':  db.execute("SELECT COUNT(*) FROM reports WHERE is_published=1").fetchone()[0],
        'categories': db.execute("SELECT COUNT(DISTINCT category) FROM reports").fetchone()[0],
    }
    recent = db.execute("""
        SELECT token_id,title_enc,category,urgency,status,created_at,province
        FROM reports WHERE is_published=1 ORDER BY created_at DESC LIMIT 6
    """).fetchall()
    ann      = db.execute("SELECT value FROM site_settings WHERE key='announcement'").fetchone()
    cat_stats= db.execute("SELECT category,COUNT(*) cnt FROM reports GROUP BY category ORDER BY cnt DESC LIMIT 8").fetchall()
    db.close()

    # Decrypt published titles for display
    recent_dec = []
    for r in recent:
        d = dict(r)
        d['title'] = _dec(r['title_enc'])[:90]
        recent_dec.append(d)

    return render_template('index.html', stats=stats, recent=recent_dec,
                           announcement=ann['value'] if ann else '',
                           cat_stats=cat_stats)

@app.route('/submit', methods=['GET','POST'])
def submit():
    if request.method == 'POST':
        if not _rate_check('submit', Config.SUBMIT_RATE_LIMIT):
            flash('Rate limit reached. Please wait before submitting again.', 'warning')
            return redirect(url_for('submit'))
        if not _csrf_ok():
            flash('Security validation failed.', 'danger')
            return redirect(url_for('submit'))

        title       = request.form.get('title','').strip()[:200]
        description = request.form.get('description','').strip()[:50000]
        category    = request.form.get('category','other')
        subcategory = request.form.get('subcategory','').strip()[:100]
        province    = request.form.get('province','')
        district    = request.form.get('district','').strip()[:100]
        urgency     = request.form.get('urgency','medium')
        language    = request.form.get('language','en')

        if not title or not description:
            flash('Title and description are required.', 'danger')
            return redirect(url_for('submit'))
        if category not in CATEGORIES: category = 'other'
        if urgency not in URGENCY:     urgency = 'medium'

        # Generate HMAC-signed tracking token
        token_id, full_token = generate_signed_token(app.config['SECRET_KEY'])
        ts = now_iso()
        mk = get_master_key()

        # Encrypt all sensitive fields
        title_enc       = _enc(title)
        desc_enc        = _enc(description)
        sub_enc         = _enc(subcategory) if subcategory else ''
        district_enc    = _enc(district) if district else ''
        content_hash    = sha3_text(title + description)  # integrity check

        db = get_db()
        db.execute("""
            INSERT INTO reports
              (token_id,title_enc,description_enc,category,subcategory_enc,
               province,district_enc,urgency,language,created_at,updated_at,content_hash)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """, (token_id, title_enc, desc_enc, category, sub_enc,
              province, district_enc, urgency, language, ts, ts, content_hash))
        report_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        # ── Encrypt and store uploaded files ──────────────────────────────────
        files = request.files.getlist('attachments')
        for f in files:
            if not f or not f.filename: continue
            if not is_allowed_extension(f.filename): continue

            orig_name = f.filename
            stored    = secure_filename_store(orig_name)
            tmp_path  = os.path.join(Config.UPLOAD_FOLDER, 'tmp_' + stored)
            enc_path  = os.path.join(Config.UPLOAD_FOLDER, stored)

            try:
                f.save(tmp_path)
                if Config.ENCRYPT_FILES:
                    meta = encrypt_file(tmp_path, enc_path, mk)
                    secure_delete(tmp_path)  # securely wipe plaintext tmp file
                else:
                    os.rename(tmp_path, enc_path)
                    meta = {'orig_size': os.path.getsize(enc_path),
                            'enc_size':  os.path.getsize(enc_path),
                            'sha3_digest': sha3_text(orig_name)}

                db.execute("""
                    INSERT INTO attachments
                      (report_id,filename_enc,stored_name,file_type,file_size,
                       enc_size,mime_type_enc,sha3_digest,uploaded_at)
                    VALUES(?,?,?,?,?,?,?,?,?)
                """, (report_id, _enc(orig_name), stored,
                      get_file_category(orig_name),
                      meta['orig_size'], meta.get('enc_size',0),
                      _enc(f.mimetype or ''), meta.get('sha3_digest',''), ts))
            except Exception as ex:
                app.logger.error(f"File upload error: {ex}")
                if os.path.exists(tmp_path): os.remove(tmp_path)

        db.execute("""
            INSERT INTO status_updates(report_id,old_status,new_status,note_enc,updated_at)
            VALUES(?,?,?,?,?)
        """, (report_id, '', 'received', _enc('Report submitted anonymously.'), ts))
        db.commit(); db.close()

        # Store the full signed token in session briefly (to show on success page)
        session['last_full_token'] = full_token
        session['last_token_id']   = token_id
        return redirect(url_for('submit_success', tid=token_id))

    return render_template('submit.html', categories=CATEGORIES,
                           provinces=PROVINCES, urgency_map=URGENCY)

@app.route('/submit/success/<tid>')
def submit_success(tid):
    if session.get('last_token_id') != tid:
        abort(403)
    full_token = session.pop('last_full_token', tid)
    session.pop('last_token_id', None)
    return render_template('submit_success.html', token=full_token, token_id=tid)

@app.route('/track', methods=['GET','POST'])
def track():
    report=None; attachments=[]; history=[]; error=None
    if request.method == 'POST':
        if not _rate_check('track', Config.TRACK_RATE_LIMIT):
            flash('Too many tracking requests. Please wait.', 'warning')
            return redirect(url_for('track'))
        if not _csrf_ok():
            flash('Security error.', 'danger')
            return redirect(url_for('track'))

        raw_token = request.form.get('token','').strip()
        # Verify HMAC signature on token
        token_id = verify_signed_token(raw_token, app.config['SECRET_KEY'])
        if not token_id:
            error = "Invalid or tampered token. Please check and try again."
        else:
            db = get_db()
            row = db.execute("SELECT * FROM reports WHERE token_id=?", (token_id,)).fetchone()
            if row:
                report      = dict(row)
                report['title']       = _dec(row['title_enc'])
                report['description'] = _dec(row['description_enc'])
                report['admin_notes'] = _dec(row['admin_notes_enc']) if row['admin_notes_enc'] else ''

                atts_raw = db.execute("SELECT * FROM attachments WHERE report_id=?",
                                      (row['id'],)).fetchall()
                for a in atts_raw:
                    d = dict(a)
                    d['filename'] = _dec(a['filename_enc'])
                    attachments.append(d)

                hist_raw = db.execute(
                    "SELECT * FROM status_updates WHERE report_id=? ORDER BY updated_at",
                    (row['id'],)).fetchall()
                for h in hist_raw:
                    d = dict(h)
                    d['note'] = _dec(h['note_enc']) if h['note_enc'] else ''
                    history.append(d)

                db.execute("UPDATE reports SET views=views+1 WHERE id=?", (row['id'],))
                db.commit()
            else:
                error = "No report found with this token."
            db.close()

    return render_template('track.html', report=report, attachments=attachments,
                           history=history, error=error, format_size=format_file_size)

@app.route('/browse')
def browse():
    page     = max(1, int(request.args.get('page',1)))
    per_page = 12
    cat      = request.args.get('cat','')
    prov     = request.args.get('prov','')
    urg      = request.args.get('urg','')
    offset   = (page-1)*per_page

    wheres,params = ["is_published=1"],[]
    if cat  in CATEGORIES: wheres.append("category=?");  params.append(cat)
    if prov in PROVINCES:  wheres.append("province=?");  params.append(prov)
    if urg  in URGENCY:    wheres.append("urgency=?");   params.append(urg)
    wsql = " AND ".join(wheres)

    db    = get_db()
    total = db.execute(f"SELECT COUNT(*) FROM reports WHERE {wsql}", params).fetchone()[0]
    rows  = db.execute(f"""
        SELECT token_id,title_enc,category,urgency,status,created_at,province
        FROM reports WHERE {wsql}
        ORDER BY created_at DESC LIMIT ? OFFSET ?
    """, params+[per_page,offset]).fetchall()
    db.close()

    reports = []
    for r in rows:
        d = dict(r)
        d['title'] = _dec(r['title_enc'])
        reports.append(d)

    return render_template('browse.html', reports=reports, total=total,
                           page=page, pages=(total+per_page-1)//per_page,
                           provinces=PROVINCES, sel_cat=cat, sel_prov=prov, sel_urg=urg)

@app.route('/report/<path:token>')
def view_report(token):
    # Accept either full signed token or token_id
    token_id = verify_signed_token(token, app.config['SECRET_KEY']) or token
    db  = get_db()
    row = db.execute(
        "SELECT * FROM reports WHERE token_id=? AND is_published=1", (token_id,)
    ).fetchone()
    if not row: abort(404)
    report      = dict(row)
    report['title']       = _dec(row['title_enc'])
    report['description'] = _dec(row['description_enc'])
    atts_raw    = db.execute("SELECT * FROM attachments WHERE report_id=?", (row['id'],)).fetchall()
    attachments = []
    for a in atts_raw:
        d = dict(a); d['filename'] = _dec(a['filename_enc']); attachments.append(d)
    db.execute("UPDATE reports SET views=views+1 WHERE id=?", (row['id'],))
    db.commit(); db.close()
    return render_template('report_view.html', report=report, attachments=attachments,
                           format_size=format_file_size)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/guide')
def guide():
    return render_template('guide.html')

@app.route('/api/stats')
def api_stats():
    db = get_db()
    data = {
        'total':      db.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
        'verified':   db.execute("SELECT COUNT(*) FROM reports WHERE is_verified=1").fetchone()[0],
        'published':  db.execute("SELECT COUNT(*) FROM reports WHERE is_published=1").fetchone()[0],
        'by_category':{r['category']:r['cnt'] for r in db.execute("SELECT category,COUNT(*) cnt FROM reports GROUP BY category").fetchall()},
        'by_province':{r['province']:r['cnt'] for r in db.execute("SELECT province,COUNT(*) cnt FROM reports WHERE province!='' GROUP BY province").fetchall()},
        'by_urgency': {r['urgency']:r['cnt']  for r in db.execute("SELECT urgency,COUNT(*) cnt FROM reports GROUP BY urgency").fetchall()},
    }
    db.close()
    return jsonify(data)

# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN — AUTH
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if _get_admin_session():
        return redirect(url_for('admin_dashboard'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')

        if _is_locked_out(username):
            log_action(AuditAction.ADMIN_LOGIN_FAIL, f"Login blocked — account locked",
                       username, ip_address=_ip(), hmac_key=get_audit_hmac())
            error = f"Too many failed attempts. Try again in {Config.LOCKOUT_MINUTES} minutes."
        else:
            db   = get_db()
            user = db.execute("SELECT * FROM admin_users WHERE username=?", (username,)).fetchone()
            db.close()

            if user and verify_password(password, user['password_hash']):
                _record_login(username, True)
                db = get_db()
                db.execute("UPDATE admin_users SET last_login=? WHERE id=?", (now_iso(), user['id']))
                db.commit(); db.close()

                if user['totp_enabled']:
                    # Store partial session (awaiting 2FA)
                    session['pending_2fa_user_id'] = user['id']
                    session['pending_2fa_username'] = username
                    log_action(AuditAction.ADMIN_LOGIN_OK,
                               "Password verified — 2FA required",
                               username, ip_address=_ip(), hmac_key=get_audit_hmac())
                    return redirect(url_for('admin_2fa'))
                else:
                    tok = _create_admin_session(user['id'], totp_verified=True)
                    log_action(AuditAction.ADMIN_LOGIN_OK, "Login successful",
                               username, ip_address=_ip(), hmac_key=get_audit_hmac())
                    resp = make_response(redirect(url_for('admin_dashboard')))
                    resp.set_cookie(SESSION_COOKIE, tok, httponly=True,
                                    samesite='Strict', secure=Config.SESSION_COOKIE_SECURE,
                                    max_age=SESSION_HOURS*3600)
                    return resp
            else:
                _record_login(username, False)
                log_action(AuditAction.ADMIN_LOGIN_FAIL, "Invalid credentials",
                           username, ip_address=_ip(), hmac_key=get_audit_hmac())
                error = "Invalid username or password."

    return render_template('admin/login.html', error=error)

@app.route('/admin/2fa', methods=['GET','POST'])
def admin_2fa():
    uid  = session.get('pending_2fa_user_id')
    uname= session.get('pending_2fa_username','')
    if not uid:
        return redirect(url_for('admin_login'))

    error = None
    if request.method == 'POST':
        code = request.form.get('code','').strip()
        db   = get_db()
        user = db.execute("SELECT * FROM admin_users WHERE id=?", (uid,)).fetchone()
        db.close()
        if user and verify_totp(user['totp_secret'], code):
            session.pop('pending_2fa_user_id', None)
            session.pop('pending_2fa_username', None)
            tok  = _create_admin_session(uid, totp_verified=True)
            log_action(AuditAction.ADMIN_2FA_OK, "2FA verified",
                       uname, ip_address=_ip(), hmac_key=get_audit_hmac())
            resp = make_response(redirect(url_for('admin_dashboard')))
            resp.set_cookie(SESSION_COOKIE, tok, httponly=True, samesite='Strict',
                            secure=Config.SESSION_COOKIE_SECURE, max_age=SESSION_HOURS*3600)
            return resp
        else:
            log_action(AuditAction.ADMIN_2FA_FAIL, "2FA code incorrect",
                       uname, ip_address=_ip(), hmac_key=get_audit_hmac())
            error = "Invalid TOTP code. Try again."

    return render_template('admin/2fa.html', error=error, username=uname)

@app.route('/admin/logout')
def admin_logout():
    tok = request.cookies.get(SESSION_COOKIE)
    adm = _get_admin_session()
    if tok:
        _invalidate_session(tok)
    if adm:
        log_action(AuditAction.ADMIN_LOGOUT, "Logged out",
                   adm['username'], ip_address=_ip(),
                   session_id=tok, hmac_key=get_audit_hmac())
    session.clear()
    resp = make_response(redirect(url_for('index')))
    resp.delete_cookie(SESSION_COOKIE)
    return resp

# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN — DASHBOARD & REPORT MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/admin')
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db    = get_db()
    stats = {
        'total':     db.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
        'received':  db.execute("SELECT COUNT(*) FROM reports WHERE status='received'").fetchone()[0],
        'reviewing': db.execute("SELECT COUNT(*) FROM reports WHERE status='reviewing'").fetchone()[0],
        'verified':  db.execute("SELECT COUNT(*) FROM reports WHERE is_verified=1").fetchone()[0],
        'published': db.execute("SELECT COUNT(*) FROM reports WHERE is_published=1").fetchone()[0],
        'critical':  db.execute("SELECT COUNT(*) FROM reports WHERE urgency='critical'").fetchone()[0],
        'flagged':   db.execute("SELECT COUNT(*) FROM reports WHERE is_flagged=1").fetchone()[0],
    }
    page      = max(1, int(request.args.get('page',1)))
    per       = 20
    offset    = (page-1)*per
    flt_status= request.args.get('status','')
    flt_cat   = request.args.get('cat','')
    flt_urg   = request.args.get('urg','')
    search    = request.args.get('q','').strip()

    wheres,params = [],[]
    if flt_status: wheres.append("status=?");   params.append(flt_status)
    if flt_cat:    wheres.append("category=?"); params.append(flt_cat)
    if flt_urg:    wheres.append("urgency=?");  params.append(flt_urg)
    wsql = ("WHERE " + " AND ".join(wheres)) if wheres else ""

    total_rows = db.execute(f"SELECT COUNT(*) FROM reports {wsql}", params).fetchone()[0]
    rows = db.execute(f"""
        SELECT r.id, r.token_id, r.title_enc, r.category, r.urgency, r.status,
               r.created_at, r.is_verified, r.is_published, r.is_flagged, r.views,
               r.province,
               (SELECT COUNT(*) FROM attachments WHERE report_id=r.id) as att_count
        FROM reports r {wsql}
        ORDER BY CASE urgency WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                              WHEN 'medium' THEN 2 ELSE 3 END,
                 r.created_at DESC
        LIMIT ? OFFSET ?
    """, params+[per,offset]).fetchall()
    db.close()

    # Decrypt titles for listing (admins see decrypted content)
    reports = []
    for r in rows:
        d = dict(r)
        d['title'] = _dec(r['title_enc'])[:70]
        # Search filter on decrypted content
        if search and search.lower() not in d['title'].lower() and search.lower() not in r['token_id'].lower():
            total_rows -= 1
            continue
        reports.append(d)

    log_action(AuditAction.REPORT_VIEWED, f"Dashboard viewed (page {page})",
               g.admin['username'], ip_address=_ip(),
               session_id=g.admin_session_token, hmac_key=get_audit_hmac())

    return render_template('admin/dashboard.html', stats=stats, reports=reports,
                           pages=(total_rows+per-1)//per, page=page, total=total_rows,
                           flt_status=flt_status, flt_cat=flt_cat,
                           flt_urg=flt_urg, search=search)

@app.route('/admin/report/<token_id>')
@admin_required
def admin_report(token_id):
    db  = get_db()
    row = db.execute("SELECT * FROM reports WHERE token_id=?", (token_id,)).fetchone()
    if not row: abort(404)

    # Decrypt ALL fields for admin view
    report = dict(row)
    report['title']       = _dec(row['title_enc'])
    report['description'] = _dec(row['description_enc'])
    report['subcategory'] = _dec(row['subcategory_enc']) if row['subcategory_enc'] else ''
    report['district']    = _dec(row['district_enc'])    if row['district_enc'] else ''
    report['admin_notes'] = _dec(row['admin_notes_enc']) if row['admin_notes_enc'] else ''

    atts_raw = db.execute("SELECT * FROM attachments WHERE report_id=?", (row['id'],)).fetchall()
    attachments = []
    for a in atts_raw:
        d = dict(a)
        d['filename']  = _dec(a['filename_enc'])
        d['mime_type'] = _dec(a['mime_type_enc']) if a['mime_type_enc'] else ''
        attachments.append(d)

    hist_raw = db.execute(
        "SELECT * FROM status_updates WHERE report_id=? ORDER BY updated_at", (row['id'],)
    ).fetchall()
    history = []
    for h in hist_raw:
        d = dict(h)
        d['note'] = _dec(h['note_enc']) if h['note_enc'] else ''
        history.append(d)

    # Integrity check
    plaintext_hash = sha3_text(report['title'] + report['description'])
    integrity_ok   = (plaintext_hash == row['content_hash']) if row['content_hash'] else None

    db.execute("UPDATE reports SET views=views+1 WHERE id=?", (row['id'],))
    db.commit(); db.close()

    log_action(AuditAction.REPORT_VIEWED,
               f"Report viewed: {token_id[:16]}…",
               g.admin['username'], report_token=token_id,
               ip_address=_ip(), session_id=g.admin_session_token,
               hmac_key=get_audit_hmac())

    return render_template('admin/report_detail.html',
                           report=report, attachments=attachments,
                           history=history, integrity_ok=integrity_ok,
                           format_size=format_file_size, all_statuses=STATUS_FLOW)

@app.route('/admin/report/<token_id>/update', methods=['POST'])
@admin_required
def admin_update_report(token_id):
    if not _csrf_ok():
        flash('Security error.', 'danger')
        return redirect(url_for('admin_report', token_id=token_id))

    db  = get_db()
    row = db.execute("SELECT * FROM reports WHERE token_id=?", (token_id,)).fetchone()
    if not row: abort(404)

    new_status   = request.form.get('status', row['status'])
    admin_notes  = request.form.get('admin_notes','').strip()[:5000]
    status_note  = request.form.get('status_note','').strip()[:1000]
    is_published = 1 if request.form.get('is_published') else 0
    is_verified  = 1 if request.form.get('is_verified')  else 0
    is_flagged   = 1 if request.form.get('is_flagged')   else 0
    ts = now_iso()

    old_status = row['status']
    db.execute("""
        UPDATE reports SET status=?, admin_notes_enc=?, is_published=?,
                           is_verified=?, is_flagged=?, updated_at=?
        WHERE id=?
    """, (new_status, _enc(admin_notes), is_published, is_verified, is_flagged, ts, row['id']))

    if old_status != new_status:
        db.execute("""
            INSERT INTO status_updates(report_id,old_status,new_status,note_enc,updated_at)
            VALUES(?,?,?,?,?)
        """, (row['id'], old_status, new_status, _enc(status_note), ts))

    db.commit(); db.close()

    action = (AuditAction.REPORT_PUBLISHED if is_published and not row['is_published']
              else AuditAction.REPORT_VERIFIED if is_verified
              else AuditAction.REPORT_UPDATED)
    log_action(action, f"Status: {old_status}→{new_status}",
               g.admin['username'], report_token=token_id,
               session_id=g.admin_session_token, ip_address=_ip(),
               extra={'published':is_published,'verified':is_verified,'flagged':is_flagged},
               hmac_key=get_audit_hmac())

    flash('Report updated successfully.', 'success')
    return redirect(url_for('admin_report', token_id=token_id))

@app.route('/admin/report/<token_id>/delete', methods=['POST'])
@admin_required
def admin_delete_report(token_id):
    if not _csrf_ok():
        flash('Security error.', 'danger')
        return redirect(url_for('admin_dashboard'))

    db  = get_db()
    row = db.execute("SELECT id FROM reports WHERE token_id=?", (token_id,)).fetchone()
    if row:
        atts = db.execute("SELECT stored_name FROM attachments WHERE report_id=?", (row['id'],)).fetchall()
        for a in atts:
            path = os.path.join(Config.UPLOAD_FOLDER, a['stored_name'])
            secure_delete(path)  # 3-pass wipe

        db.execute("DELETE FROM attachments   WHERE report_id=?", (row['id'],))
        db.execute("DELETE FROM status_updates WHERE report_id=?", (row['id'],))
        db.execute("DELETE FROM reports        WHERE id=?",         (row['id'],))
        db.commit()

    db.close()
    log_action(AuditAction.REPORT_DELETED, f"Report deleted: {token_id[:16]}…",
               g.admin['username'], report_token=token_id,
               session_id=g.admin_session_token, ip_address=_ip(),
               hmac_key=get_audit_hmac())
    flash('Report and all files permanently deleted.', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/file/<int:att_id>')
@admin_required
def admin_download_file(att_id):
    db  = get_db()
    att = db.execute("SELECT * FROM attachments WHERE id=?", (att_id,)).fetchone()
    if not att: abort(404)
    orig_name   = _dec(att['filename_enc'])
    stored_path = os.path.join(Config.UPLOAD_FOLDER, att['stored_name'])
    db.close()

    if not os.path.exists(stored_path):
        abort(404)

    if Config.ENCRYPT_FILES:
        try:
            plaintext = decrypt_file(stored_path, get_master_key())
        except ValueError as e:
            log_action(AuditAction.FILE_DOWNLOADED,
                       f"File decryption FAILED: {str(e)} — att_id={att_id}",
                       g.admin['username'], session_id=g.admin_session_token,
                       ip_address=_ip(), hmac_key=get_audit_hmac())
            flash(f'File integrity check failed: {e}', 'danger')
            return redirect(request.referrer or url_for('admin_dashboard'))

        # Verify SHA3 integrity
        import hashlib as _hl
        computed = _hl.sha3_256(plaintext).hexdigest()
        if att['sha3_digest'] and computed != att['sha3_digest']:
            flash('⚠️ File integrity mismatch — SHA3-256 does not match stored digest!', 'danger')
            log_action(AuditAction.FILE_DOWNLOADED,
                       f"Integrity mismatch on att_id={att_id}",
                       g.admin['username'], hmac_key=get_audit_hmac())
            # Still serve but warn
    else:
        with open(stored_path, 'rb') as fh:
            plaintext = fh.read()

    log_action(AuditAction.FILE_DOWNLOADED, f"File downloaded: {orig_name[:40]}",
               g.admin['username'], session_id=g.admin_session_token,
               ip_address=_ip(), hmac_key=get_audit_hmac())

    resp = make_response(plaintext)
    resp.headers['Content-Type']        = 'application/octet-stream'
    resp.headers['Content-Disposition'] = f'attachment; filename="{orig_name}"'
    resp.headers['Content-Length']      = len(plaintext)
    return resp

# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN — SETTINGS, 2FA, AUDIT
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/admin/settings', methods=['GET','POST'])
@admin_required
def admin_settings():
    db = get_db()
    if request.method == 'POST':
        if not _csrf_ok():
            flash('Security error.', 'danger')
            return redirect(url_for('admin_settings'))

        for key in ['site_active','submission_open','announcement',
                    'max_failed_logins','lockout_minutes']:
            val = request.form.get(key,'')
            db.execute("INSERT OR REPLACE INTO site_settings(key,value) VALUES(?,?)", (key,val))

        new_pw = request.form.get('new_password','')
        if new_pw:
            if len(new_pw) < 12:
                flash('Password must be at least 12 characters.', 'danger')
                db.close()
                return redirect(url_for('admin_settings'))
            ph = hash_password(new_pw)
            db.execute("UPDATE admin_users SET password_hash=?, force_pw_change=0 WHERE id=?",
                       (ph, g.admin['id']))
            log_action(AuditAction.PW_CHANGED, "Password changed",
                       g.admin['username'], session_id=g.admin_session_token,
                       ip_address=_ip(), hmac_key=get_audit_hmac())
            flash('Password updated successfully.', 'success')

        db.commit()
        log_action(AuditAction.SETTINGS_CHANGED, "Site settings updated",
                   g.admin['username'], session_id=g.admin_session_token,
                   ip_address=_ip(), hmac_key=get_audit_hmac())
        flash('Settings saved.', 'success')

    settings = {r['key']:r['value'] for r in
                db.execute("SELECT key,value FROM site_settings").fetchall()}
    db.close()
    return render_template('admin/settings.html', settings=settings, admin=g.admin)

@app.route('/admin/2fa/enroll', methods=['GET','POST'])
@admin_required
def admin_2fa_enroll():
    db   = get_db()
    user = db.execute("SELECT * FROM admin_users WHERE id=?", (g.admin['id'],)).fetchone()

    if request.method == 'POST':
        if not _csrf_ok(): abort(403)
        secret = request.form.get('totp_secret','')
        code   = request.form.get('code','').strip()
        action = request.form.get('action','')

        if action == 'disable':
            db.execute("UPDATE admin_users SET totp_enabled=0, totp_secret='' WHERE id=?",
                       (g.admin['id'],))
            db.commit(); db.close()
            flash('Two-Factor Authentication disabled.', 'info')
            return redirect(url_for('admin_settings'))

        if verify_totp(secret, code):
            db.execute("UPDATE admin_users SET totp_secret=?, totp_enabled=1 WHERE id=?",
                       (secret, g.admin['id']))
            db.commit(); db.close()
            log_action(AuditAction.TOTP_ENROLLED, "2FA enrolled",
                       g.admin['username'], session_id=g.admin_session_token,
                       ip_address=_ip(), hmac_key=get_audit_hmac())
            flash('Two-Factor Authentication enabled successfully! 🔐', 'success')
            return redirect(url_for('admin_settings'))
        else:
            db.close()
            flash('Invalid TOTP code. Enrollment failed.', 'danger')
            return redirect(url_for('admin_2fa_enroll'))

    # Generate new secret for enrollment
    secret = user['totp_secret'] if user['totp_enabled'] else generate_totp_secret()
    uri    = totp_provisioning_uri(secret, user['username'])

    # Generate QR code as inline SVG/data URI (stdlib only — no qrcode lib needed)
    qr_uri = _qr_datauri(uri)
    db.close()
    return render_template('admin/2fa_enroll.html', secret=secret, uri=uri,
                           qr_uri=qr_uri, admin=g.admin, user=dict(user))

def _qr_datauri(text: str) -> str:
    """Generate a simple QR-like placeholder. Real deployment: use qrcode lib."""
    # We'll just return the URI itself for display — admins can use any QR generator
    return None  # Template will show the URI text directly

@app.route('/admin/audit')
@admin_required
def admin_audit():
    page   = max(1, int(request.args.get('page',1)))
    per    = 50
    offset = (page-1)*per
    action_filter = request.args.get('action','')

    db     = get_db()
    wheres = []
    params = []
    if action_filter:
        wheres.append("action LIKE ?")
        params.append(f"%{action_filter}%")
    wsql = ("WHERE " + " AND ".join(wheres)) if wheres else ""

    total   = db.execute(f"SELECT COUNT(*) FROM audit_log {wsql}", params).fetchone()[0]
    entries = db.execute(f"""
        SELECT * FROM audit_log {wsql}
        ORDER BY id DESC LIMIT ? OFFSET ?
    """, params+[per,offset]).fetchall()

    # Verify chain integrity
    chain_status = verify_audit_chain(get_audit_hmac())
    db.close()

    return render_template('admin/audit.html',
                           entries=entries, total=total,
                           page=page, pages=(total+per-1)//per,
                           chain_status=chain_status,
                           action_filter=action_filter)

@app.route('/admin/sessions')
@admin_required
def admin_sessions():
    db   = get_db()
    sess = db.execute("""
        SELECT s.*, u.username FROM admin_sessions s
        JOIN admin_users u ON u.id = s.admin_id
        ORDER BY s.last_active DESC LIMIT 100
    """).fetchall()
    db.close()
    return render_template('admin/sessions.html', sessions=sess)

@app.route('/admin/sessions/revoke/<int:sid>', methods=['POST'])
@admin_required
def admin_revoke_session(sid):
    db = get_db()
    db.execute("UPDATE admin_sessions SET is_valid=0 WHERE id=?", (sid,))
    db.commit(); db.close()
    flash('Session revoked.', 'info')
    return redirect(url_for('admin_sessions'))

@app.route('/admin/export')
@admin_required
def admin_export():
    db = get_db()
    rows = db.execute("SELECT * FROM reports ORDER BY created_at DESC").fetchall()
    out  = []
    for r in rows:
        d = dict(r)
        d['title']       = _dec(r['title_enc'])
        d['description'] = _dec(r['description_enc'])
        d['subcategory'] = _dec(r['subcategory_enc']) if r['subcategory_enc'] else ''
        d['district']    = _dec(r['district_enc'])    if r['district_enc'] else ''
        d.pop('title_enc',None); d.pop('description_enc',None)
        d.pop('subcategory_enc',None); d.pop('district_enc',None)
        d.pop('admin_notes_enc',None)
        atts = db.execute("SELECT * FROM attachments WHERE report_id=?", (r['id'],)).fetchall()
        d['attachments'] = [{'filename':_dec(a['filename_enc']),'type':a['file_type'],'size':a['file_size']} for a in atts]
        out.append(d)
    db.close()

    log_action(AuditAction.EXPORT_TRIGGERED, f"Full export ({len(out)} reports)",
               g.admin['username'], session_id=g.admin_session_token,
               ip_address=_ip(), hmac_key=get_audit_hmac())

    from flask import Response
    return Response(json.dumps(out, ensure_ascii=False, indent=2),
                    mimetype='application/json',
                    headers={'Content-Disposition':'attachment;filename=satyavani_export.json'})

# ── Template filters ───────────────────────────────────────────────────────────
@app.template_filter('fmtdate')
def fmt_date(s):
    try: return datetime.strptime(str(s)[:19],'%Y-%m-%d %H:%M:%S').strftime('%d %b %Y, %H:%M UTC')
    except: return str(s)

@app.template_filter('fmtsize')
def fmt_size(n):
    try: return format_file_size(int(n))
    except: return str(n)

@app.template_filter('catinfo')
def cat_info(key):
    return CATEGORIES.get(key, CATEGORIES['other'])

@app.template_filter('nl2br')
def nl2br(s):
    from markupsafe import Markup, escape
    return Markup(escape(s).replace('\n','<br>'))

# ── Error handlers ─────────────────────────────────────────────────────────────
@app.errorhandler(404)
def e404(e): return render_template('error.html', code=404, msg="Page not found."), 404
@app.errorhandler(403)
def e403(e): return render_template('error.html', code=403, msg="Access denied."), 403
@app.errorhandler(413)
def e413(e):
    flash('File too large. Maximum is 500MB total.','danger')
    return redirect(url_for('submit'))

# ── Bootstrap ──────────────────────────────────────────────────────────────────
def bootstrap():
    init_db()
    db    = get_db()
    count = db.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]
    if count == 0:
        ph = hash_password('Admin@Nepal2024!')
        db.execute(
            "INSERT INTO admin_users(username,password_hash,created_at,force_pw_change) VALUES(?,?,?,?)",
            ('admin', ph, now_iso(), 1)  # force password change on first login
        )
        db.commit()
        print("⚠️  Default admin: admin / Admin@Nepal2024!")
        print("   You MUST change this password on first login.")
    db.close()

if __name__ == '__main__':
    bootstrap()
    app.run(debug=False, host='0.0.0.0', port=5000)
