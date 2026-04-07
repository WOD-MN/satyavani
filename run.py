"""
SatyaVani startup script — bootstraps DB and starts Flask dev server.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from database import init_db
from utils.security import hash_password, now_iso

def bootstrap():
    print("🔱 SatyaVani — Initialising...")
    init_db()
    print("✅ Database ready.")

    # Ensure default admin exists
    from database import get_db
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]
    if count == 0:
        ph = hash_password('Admin@1234!')
        db.execute(
            "INSERT INTO admin_users(username,password_hash,created_at) VALUES(?,?,?)",
            ('admin', ph, now_iso())
        )
        db.commit()
        print("⚠️  Default admin created.")
        print("   Username : admin")
        print("   Password : Admin@1234!")
        print("   ➜  CHANGE THIS via /admin/settings after first login!")
    else:
        print(f"✅ {count} admin user(s) exist.")
    db.close()

if __name__ == '__main__':
    bootstrap()
    from app import app
    print("\n🚀 Starting SatyaVani server at http://0.0.0.0:5000")
    print("📋 Admin panel  : http://localhost:5000/admin")
    print("🔏 Submit report: http://localhost:5000/submit")
    print("🔍 Track report : http://localhost:5000/track")
    print("   Press Ctrl+C to stop.\n")
    app.run(debug=True, host='0.0.0.0', port=5001, use_reloader=False)
