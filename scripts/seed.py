"""Create demo users and print their credentials.  Usage: python scripts/seed.py"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app          # noqa: E402
from app.seed import seed_demo      # noqa: E402

app = create_app()
with app.app_context():
    creds = seed_demo()

path = Path(app.instance_path) / "demo_credentials.json"
if creds:
    path.write_text(json.dumps(creds, indent=2))
    print("Demo accounts created. Credentials saved to", path)
    for user, info in creds.items():
        print("  %-10s role=%-9s password=%s  totp_secret=%s" % (user, info["role"], info["password"], info["totp_secret"]))
    print("\nGet a login code with:  python scripts/totp.py <totp_secret>")
else:
    print("Demo accounts already exist. See", path)
