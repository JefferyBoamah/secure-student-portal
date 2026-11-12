"""Acts as the payment provider: sends a signed 'payment succeeded' webhook.
Usage: python3 scripts/confirm_payment.py PAY-XXXXXXXXXXXX 5000"""
import json, sys, secrets
from pathlib import Path
import requests
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from app.security import sign_webhook
ref, cents = sys.argv[1], int(sys.argv[2])
secret = json.loads((ROOT / "instance" / "secrets.json").read_text())["WEBHOOK_SECRET"]
body = json.dumps({"event_id": "evt_" + secrets.token_hex(4), "reference": ref,
                   "amount_cents": cents, "status": "succeeded"}).encode()
s = requests.Session(); s.trust_env = False; s.verify = str(ROOT / "instance" / "certs" / "cert.pem")
r = s.post("https://127.0.0.1:5000/api/webhooks/payment", data=body,
           headers={"X-Signature": sign_webhook(body, secret)}, timeout=10)
print(r.status_code, r.text)
