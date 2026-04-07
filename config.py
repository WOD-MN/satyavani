import os, secrets
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # ── Security ──────────────────────────────────────────────────────────────
    SECRET_KEY               = os.environ.get('SECRET_KEY') or secrets.token_hex(64)
    SESSION_COOKIE_HTTPONLY  = True
    SESSION_COOKIE_SAMESITE  = 'Strict'
    SESSION_COOKIE_SECURE    = os.environ.get('HTTPS', '0') == '1'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=4)

    # ── Database ───────────────────────────────────────────────────────────────
    DB_PATH = os.path.join(BASE_DIR, 'instance', 'satyavani.db')

    # ── File Uploads ───────────────────────────────────────────────────────────
    UPLOAD_FOLDER         = os.path.join(BASE_DIR, 'uploads', 'secure')
    MAX_CONTENT_LENGTH    = 500 * 1024 * 1024
    ALLOWED_EXTENSIONS    = {
        'documents': ['pdf','doc','docx','txt','odt','rtf','csv','xlsx','pptx','ods'],
        'images':    ['jpg','jpeg','png','gif','bmp','webp','tiff','svg','heic','raw'],
        'videos':    ['mp4','avi','mov','mkv','webm','flv','wmv','3gp','ogv','ts'],
        'audio':     ['mp3','wav','ogg','aac','flac','m4a','wma','opus','amr'],
        'archives':  ['zip','rar','7z','tar','gz','bz2','xz'],
        'other':     ['json','xml','html','eml','msg','mbox','vcf'],
    }

    # ── Crypto ─────────────────────────────────────────────────────────────────
    ENCRYPT_FIELDS  = True     # AES-256-GCM encrypt all sensitive DB fields
    ENCRYPT_FILES   = True     # AES-256-GCM encrypt all uploaded files

    # ── Auth ───────────────────────────────────────────────────────────────────
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINUTES    = 30
    SESSION_HOURS      = 4
    REQUIRE_2FA        = False  # Set True to force 2FA for all admins

    # ── Privacy ────────────────────────────────────────────────────────────────
    LOG_IP        = False    # Never log raw IPs anywhere
    STRIP_METADATA = True

    # ── Rate Limiting ──────────────────────────────────────────────────────────
    SUBMIT_RATE_LIMIT = 5    # per hour
    TRACK_RATE_LIMIT  = 30

    # ── HTTP Security Headers ──────────────────────────────────────────────────
    SECURITY_HEADERS = {
        'X-Content-Type-Options':    'nosniff',
        'X-Frame-Options':           'DENY',
        'X-XSS-Protection':          '1; mode=block',
        'Referrer-Policy':           'no-referrer',
        'Permissions-Policy':        'geolocation=(), microphone=(), camera=(), payment=()',
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
        'Cache-Control':             'no-store, no-cache, must-revalidate, private',
        'Pragma':                    'no-cache',
    }
    CSP = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self';"
    )

    APP_NAME    = 'सत्यवाणी'
    APP_TAGLINE = 'Speak Truth. Stay Hidden. Fight Corruption.'
