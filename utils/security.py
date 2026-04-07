"""
Security utilities — encryption, token generation, metadata stripping.
"""
import hashlib, hmac, secrets, os, base64, struct
from datetime import datetime

def generate_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)

def hash_password(password: str) -> str:
    salt = secrets.token_hex(32)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 310_000)
    return f"{salt}${dk.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, dk_hex = stored.split('$', 1)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 310_000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, 100_000)

def encrypt_text(plain: str, key: str) -> str:
    salt  = secrets.token_bytes(16)
    dk    = _derive_key(key, salt)
    data  = plain.encode('utf-8')
    ks    = b''
    ctr   = 0
    while len(ks) < len(data):
        ks += hashlib.sha256(dk + struct.pack('>Q', ctr)).digest()
        ctr += 1
    cipher = bytes(a ^ b for a, b in zip(data, ks))
    combined = salt + cipher
    return base64.b64encode(combined).decode()

def decrypt_text(enc: str, key: str) -> str:
    combined = base64.b64decode(enc.encode())
    salt, cipher = combined[:16], combined[16:]
    dk = _derive_key(key, salt)
    ks = b''
    ctr = 0
    while len(ks) < len(cipher):
        ks += hashlib.sha256(dk + struct.pack('>Q', ctr)).digest()
        ctr += 1
    plain = bytes(a ^ b for a, b in zip(cipher, ks))
    return plain.decode('utf-8')

def secure_filename_custom(filename: str) -> str:
    ext = os.path.splitext(filename)[-1].lower().strip('.')
    return f"{secrets.token_hex(24)}.{ext}" if ext else secrets.token_hex(24)

def get_file_category(ext: str) -> str:
    from config import Config
    ext = ext.lower().lstrip('.')
    for cat, exts in Config.ALLOWED_EXTENSIONS.items():
        if ext in exts:
            return cat
    return 'unknown'

def is_allowed_file(filename: str) -> bool:
    from config import Config
    ext = os.path.splitext(filename)[-1].lower().lstrip('.')
    all_exts = {e for exts in Config.ALLOWED_EXTENSIONS.values() for e in exts}
    return ext in all_exts

def format_file_size(size: int) -> str:
    for unit in ['B','KB','MB','GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

def now_iso() -> str:
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
