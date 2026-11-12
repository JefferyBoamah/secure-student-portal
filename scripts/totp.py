"""Acts like an authenticator app: prints the current 6-digit code for a secret.
Usage: python scripts/totp.py <base32-secret>      (or: python scripts/totp.py ama   to use demo credentials)"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.security import totp_now   # noqa: E402

if len(sys.argv) != 2:
    sys.exit(__doc__)
arg = sys.argv[1]
creds_file = Path(__file__).resolve().parent.parent / "instance" / "demo_credentials.json"
if creds_file.exists() and arg in json.loads(creds_file.read_text()):
    arg = json.loads(creds_file.read_text())[arg]["totp_secret"]
print(totp_now(arg), "(valid for about %d more seconds)" % (30 - int(time.time()) % 30))
