# 🔱 सत्यवाणी — SatyaVani
## Anonymous Anti-Corruption Whistleblower Platform for Nepal

> *सत्यमेव जयते — Truth Alone Triumphs*

---

## Overview

SatyaVani is a secure, anonymous, full-featured whistleblower platform inspired by WikiLeaks, SecureDrop, and GlobaLeaks — built specifically for Nepal's anti-corruption context with a UI rooted in Hindu mythology and Nepali cultural identity.

## Tech Stack

| Layer      | Technology |
|------------|-----------|
| Framework  | Flask (Python) |
| Database   | SQLite3 (stdlib) |
| Auth       | PBKDF2-SHA256 session-based |
| Encryption | Custom XOR+SHA256 keystream |
| Tokens     | CSPRNG (secrets module) |
| Frontend   | Pure HTML/CSS/JS (no frameworks) |
| Fonts      | Tiro Devanagari Sanskrit + Cinzel Decorative + Crimson Pro |
| Particles  | Custom Canvas particle engine |

## Features

### For Whistleblowers
- ✅ Fully anonymous submission (no IP logging, no account)
- ✅ Upload ANY file type: DOCX, PDF, images, video, audio, archives
- ✅ Multi-file drag-and-drop uploads
- ✅ Cryptographically secure tracking tokens
- ✅ Status tracking without revealing identity
- ✅ Nepali + English bilingual interface
- ✅ Tor Browser compatible
- ✅ CSRF protected forms
- ✅ Rate limiting per IP
- ✅ File metadata stripped on upload

### Report Features
- ✅ 14 corruption categories (government, police, judiciary, elections, etc.)
- ✅ Province + District classification (all 7 provinces of Nepal)
- ✅ Urgency levels (Critical / High / Medium / Low)
- ✅ Status workflow: received → reviewing → verified → published → forwarded → closed
- ✅ Full-text description (50,000 chars)
- ✅ Multiple attachment types

### Admin Panel (`/admin`)
- ✅ Secure admin login with PBKDF2 hashed passwords
- ✅ Full report management (view, update status, add notes, verify, publish, flag, delete)
- ✅ File download (all attachment types)
- ✅ Search + filter (by status, category, urgency, keywords)
- ✅ Status history timeline
- ✅ JSON export of all reports
- ✅ Site settings (toggle submissions, announcement banner, password change)
- ✅ Statistics dashboard

### UI / Design
- ✅ Nepali mythology theme (Trishul, Lotus, Garuda, Yama, Shiva's Eye)
- ✅ Sacred particle system (Devanagari symbols, mandala geometry)
- ✅ Animated Dharmachakra in footer
- ✅ Dark crimson/gold/saffron color palette
- ✅ Fully responsive (mobile, tablet, desktop)
- ✅ Accessibility: keyboard nav, ARIA labels, skip links, reduced motion

## Quick Start

```bash
# 1. Clone / enter project
cd satyavani

# 2. Install Flask (only external dependency)
pip install flask

# 3. Run
python run.py

# 4. Open browser at http://localhost:5000
# 5. Admin panel at http://localhost:5000/admin
#    Default: admin / Admin@1234!  ← CHANGE IMMEDIATELY
```

## Production Deployment

```bash
# With Gunicorn
pip install gunicorn
gunicorn -c gunicorn.conf.py "app:app"

# With Nginx reverse proxy (recommended)
# Set SECRET_KEY environment variable!
export SECRET_KEY="your-64-char-random-string"
```

## File Structure

```
satyavani/
├── app.py              # Main Flask application
├── config.py           # Configuration
├── database.py         # SQLite3 database layer
├── run.py              # Development startup script
├── gunicorn.conf.py    # Production server config
├── utils/
│   └── security.py     # Tokens, hashing, encryption
├── templates/
│   ├── base.html        # Sacred Nepali-themed base layout
│   ├── index.html       # Hero + stats + mythology + features
│   ├── submit.html      # Anonymous submission form
│   ├── submit_success.html  # Token display page
│   ├── track.html       # Token-based status tracking
│   ├── browse.html      # Public report browser
│   ├── report_view.html # Single report view
│   ├── about.html       # Mission + mythology
│   ├── guide.html       # Whistleblower safety guide
│   ├── error.html       # Error pages (404, 403)
│   └── admin/
│       ├── login.html
│       ├── dashboard.html
│       ├── report_detail.html
│       └── settings.html
├── static/
│   ├── css/style.css   # Full theme (60KB)
│   └── js/main.js      # Particles + counters + UI
├── uploads/secure/     # Stored evidence files
└── instance/
    └── satyavani.db    # SQLite database
```

## Security Model

- **No IP logging** — `Config.LOG_IP = False`
- **CSRF protection** — all POST forms validated
- **Rate limiting** — 5 submissions/hour per IP (in-memory)
- **Secure filenames** — all uploads renamed to random hex strings
- **Admin auth** — PBKDF2-SHA256 with 310,000 iterations
- **Tracking tokens** — `secrets.token_urlsafe(20)` (160-bit entropy)
- **Session security** — HttpOnly, SameSite=Lax cookies

## Inspirations

- WikiLeaks — public disclosure model
- SecureDrop (Freedom of the Press Foundation) — anonymous submission
- GlobaLeaks — NGO-oriented whistleblower framework
- CIAA Nepal — Commission for Investigation of Abuse of Authority

## Mythology Reference

The UI draws from:
- **Yama / Dharmaraj** — cosmic justice, accountability (the "Chitragupta" ledger)
- **Shiva's Trishul** — destroys corruption at its root; third eye sees through lies
- **Garuda** — fearless messenger of truth; enemy of serpents (corruption)
- **Lotus (Kamal)** — purity rising from the mud of corruption
- **Saraswati** — knowledge as weapon against darkness
- **Dharmachakra** — the wheel of dharma, justice, right action

---

*धर्मो रक्षति रक्षितः — Dharma protects those who protect it.*
