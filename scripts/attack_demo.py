"""Live attack demonstration against a RUNNING portal (your own local copy).

1.  python scripts/seed.py            (once)
2.  python run.py                     (leave it running in another terminal)
3.  python scripts/attack_demo.py

Every attack should print BLOCKED. A line that prints FAIL means a control is not working.
Only run this against your own local instance.
"""
import json
import re
import secrets
import sys
import time
from pathlib import Path

import jwt
import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from app.security import sign_webhook, totp_now      # noqa: E402

BASE = "https://127.0.0.1:5000"
HTTP_BASE = "http://127.0.0.1:5080"
CERT = str(ROOT / "instance" / "certs" / "cert.pem")  # we verify TLS against our own certificate
creds = json.loads((ROOT / "instance" / "demo_credentials.json").read_text())
secrets_file = ROOT / "instance" / "secrets.json"
server_secrets = json.loads(secrets_file.read_text()) if secrets_file.exists() else {}

results = []


def check(title, blocked, detail=""):
    results.append(blocked)
    print("  [%s] %s%s" % ("BLOCKED" if blocked else "FAIL   ", title, (" -> " + detail) if detail else ""))


def section(name):
    print("\n== " + name)


def new_session():
    s = requests.Session()
    s.trust_env = False        # ignore proxy / CA-bundle environment variables: we talk to localhost only
    s.verify = CERT            # TLS verification stays ON, pinned to the portal's own certificate
    return s


def csrf(session, path):
    html = session.get(BASE + path, timeout=10).text
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def fresh_code(secret):
    return totp_now(secret)


def web_login(session, username, password, secret):
    for attempt in range(2):
        session.post(BASE + "/login", data={"csrf_token": csrf(session, "/login"), "username": username,
                                            "password": password}, allow_redirects=False, timeout=10)
        r = session.post(BASE + "/mfa/verify", data={"csrf_token": csrf(session, "/mfa/verify"),
                                                     "code": fresh_code(secret)}, allow_redirects=False, timeout=10)
        if r.status_code == 302:
            return True
        print("    (code already used in this 30s window, waiting for the next one...)")
        time.sleep(31 - int(time.time()) % 30)
    return False


def api_token(username):
    s = new_session()
    for attempt in range(2):
        r = s.post(BASE + "/api/token", json={"username": username, "password": creds[username]["password"],
                                              "totp": fresh_code(creds[username]["totp_secret"])}, timeout=10)
        if r.status_code == 200:
            return r.json()["access_token"]
        time.sleep(31 - int(time.time()) % 30)
    raise SystemExit("could not get an API token")


print("Secure Student Portal: live attack demonstration")
print("Target:", BASE)
try:
    requests.get(BASE + "/login", verify=CERT, timeout=5)
except requests.RequestException as exc:
    sys.exit("Cannot reach %s (%s). Start it with: python run.py" % (BASE, exc))

# ---------------------------------------------------------------- transport
section("1. Man-in-the-middle / downgrade (plain HTTP)")
r = requests.get(HTTP_BASE + "/login", allow_redirects=False, timeout=5)
check("Plain HTTP request is redirected to HTTPS", r.status_code == 301 and r.headers["Location"].startswith("https://"),
      "HTTP %d -> %s" % (r.status_code, r.headers.get("Location")))
r = requests.get(BASE + "/login", verify=CERT, timeout=5)
check("HSTS header tells browsers to refuse plain HTTP", "max-age" in r.headers.get("Strict-Transport-Security", ""))

section("2. Clickjacking, MIME sniffing and script injection headers")
check("X-Frame-Options: DENY and frame-ancestors 'none'",
      r.headers.get("X-Frame-Options") == "DENY" and "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", ""))
check("Content-Security-Policy blocks inline scripts", "script-src 'self'" in r.headers.get("Content-Security-Policy", ""))
check("Server banner hides framework/version", "Werkzeug" not in r.headers.get("Server", "") and "Python" not in r.headers.get("Server", ""),
      r.headers.get("Server", ""))

section("3. Host-header attack (password-reset / phishing relay)")
import http.client       # noqa: E402
import ssl                # noqa: E402

ctx = ssl.create_default_context(cafile=CERT)         # TLS still verified against "localhost"; only the HTTP Host differs
conn = http.client.HTTPSConnection("127.0.0.1", 5000, context=ctx, timeout=5)
conn.putrequest("GET", "/login", skip_host=True)
conn.putheader("Host", "evil.example")
conn.endheaders()
status = conn.getresponse().status
conn.close()
check("Request with a forged Host header is rejected", status == 400, "HTTP %d" % status)

# ---------------------------------------------------------------- authenticated attacks
section("4. Broken access control / IDOR (student A reads student B's result)")
ama = new_session()
assert web_login(ama, "ama", creds["ama"]["password"], creds["ama"]["totp_secret"]), "demo login failed"
mine = {int(x) for x in re.findall(r"/results/(\d+)", ama.get(BASE + "/results", timeout=10).text)}
leaked = 0
for rid in range(1, 40):
    if rid in mine:
        continue
    if ama.get(BASE + "/results/%d" % rid, timeout=10).status_code == 200:
        leaked += 1
check("Enumerating result IDs 1-39 exposes only my own results", leaked == 0, "%d foreign records leaked" % leaked)
check("Student cannot open the staff grading page", ama.get(BASE + "/staff/grades", timeout=10).status_code == 403)
check("Student cannot open the admin audit log", ama.get(BASE + "/admin/audit", timeout=10).status_code == 403)

section("5. CSRF (a malicious site makes the logged-in browser submit a form)")
r = ama.post(BASE + "/fees", data={"amount": "1.00"}, timeout=10)
check("POST without a valid CSRF token is rejected", r.status_code == 400, "HTTP %d" % r.status_code)

section("6. Forged and tampered JWTs")
good = api_token("kofi")
claims = jwt.decode(good, options={"verify_signature": False})
head = {"Authorization": "Bearer " + good}
check("Genuine token works", requests.get(BASE + "/api/me/results", headers=head, verify=CERT, timeout=10).status_code == 200)
forgeries = {
    "alg=none (unsigned) token": jwt.encode(claims, None, algorithm="none"),
    "token signed with attacker's key": jwt.encode(claims, "attacker-key-attacker-key-attacker-key!", algorithm="HS256"),
    "expired token": jwt.encode({**claims, "exp": int(time.time()) - 60}, "attacker-key-attacker-key-attacker-key!", algorithm="HS256"),
    "tampered signature": good[:-3] + ("AAA" if not good.endswith("AAA") else "BBB"),
}
for name, tok in forgeries.items():
    rr = requests.get(BASE + "/api/me/results", headers={"Authorization": "Bearer " + tok}, verify=CERT, timeout=10)
    check("Rejected: " + name, rr.status_code == 401, "HTTP %d" % rr.status_code)
requests.post(BASE + "/api/token/revoke", headers=head, verify=CERT, timeout=10)
rr = requests.get(BASE + "/api/me/results", headers=head, verify=CERT, timeout=10)
check("Revoked token no longer works (logout kills the token)", rr.status_code == 401)

section("7. Webhook forgery and replay (fake 'payment confirmed' messages)")
secret = server_secrets.get("WEBHOOK_SECRET", "")
body = json.dumps({"event_id": "evt_" + secrets.token_hex(4), "reference": "PAY-DOESNOTEXIST", "amount_cents": 100,
                   "status": "succeeded"}).encode()
r1 = requests.post(BASE + "/api/webhooks/payment", data=body, verify=CERT, timeout=10)
check("Unsigned webhook rejected", r1.status_code == 401, "HTTP %d" % r1.status_code)
r2 = requests.post(BASE + "/api/webhooks/payment", data=body, headers={"X-Signature": sign_webhook(body, "wrong-secret")},
                   verify=CERT, timeout=10)
check("Webhook signed with the wrong secret rejected", r2.status_code == 401, "HTTP %d" % r2.status_code)
old = sign_webhook(body, secret, time.time() - 3600)
r3 = requests.post(BASE + "/api/webhooks/payment", data=body, headers={"X-Signature": old}, verify=CERT, timeout=10)
check("Replayed (old, captured) webhook rejected", r3.status_code == 401, "HTTP %d" % r3.status_code)

section("8. SQL injection through the forms and API")
s = new_session()
tok = csrf(s, "/login")
codes = []
for payload in ("' OR '1'='1' --", "admin1' --", "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14 --"):
    rr = s.post(BASE + "/login", data={"csrf_token": tok, "username": payload, "password": "x"}, allow_redirects=False, timeout=10)
    codes.append(rr.status_code)
check("SQL injection strings in the login form do not log in", all(c == 401 for c in codes), "HTTP %s" % codes)
rr = requests.post(BASE + "/api/token", json={"username": "' OR 1=1 --", "password": "x", "totp": "000000"}, verify=CERT, timeout=10)
check("SQL injection through the API does not issue a token", rr.status_code == 401)

section("9. Stored XSS through registration")
s = new_session()
rr = s.post(BASE + "/register", data={"csrf_token": csrf(s, "/register"), "username": "xss" + secrets.token_hex(3),
            "email": "xss%s@example.edu" % secrets.token_hex(3), "full_name": "<script>alert(1)</script>",
            "password": "Gr3at!Passphrase#Here", "password2": "Gr3at!Passphrase#Here"}, allow_redirects=False, timeout=10)
check("Script tag in the name field is refused", rr.status_code == 400)

section("10. Password brute force on a throw-away account")
s = new_session()
user, pw = "victim" + secrets.token_hex(3), "Gr3at!Passphrase#Here"
rr = s.post(BASE + "/register", data={"csrf_token": csrf(s, "/register"), "username": user, "email": user + "@example.edu",
            "full_name": "Victim Account", "password": pw, "password2": pw}, allow_redirects=False, timeout=10)
if rr.status_code != 302:
    print("    (could not create the throw-away account: HTTP %d; registration is rate limited, wait 5 minutes)" % rr.status_code)
else:
    secret_b32 = re.search(r'class="secret">([A-Z2-7]+)<', s.get(BASE + "/mfa/setup", timeout=10).text).group(1)
    s.post(BASE + "/mfa/setup", data={"csrf_token": csrf(s, "/mfa/setup"), "code": totp_now(secret_b32)}, timeout=10)
    attacker = new_session()
    tok = csrf(attacker, "/login")
    statuses = []
    for guess in ("123456", "password", "Qwerty123!", "Summer2026!", "letmein", pw):
        rr = attacker.post(BASE + "/login", data={"csrf_token": tok, "username": user, "password": guess},
                           allow_redirects=False, timeout=10)
        statuses.append(rr.status_code)
    check("5 wrong guesses lock the account: even the CORRECT password is then refused",
          statuses[-1] == 401, "HTTP codes %s" % statuses)
    statuses = []
    for _ in range(14):
        statuses.append(attacker.post(BASE + "/login", data={"csrf_token": tok, "username": "nobody", "password": "x"},
                                      allow_redirects=False, timeout=10).status_code)
    check("Rapid guessing is throttled with HTTP 429", 429 in statuses, "HTTP codes %s" % statuses)

section("11. Request flood (application-layer DoS)")
codes = []
for _ in range(330):
    codes.append(requests.get(BASE + "/login", verify=CERT, timeout=10).status_code)
check("More than 300 requests/minute from one IP get HTTP 429", 429 in codes,
      "%d x 200, %d x 429" % (codes.count(200), codes.count(429)))

print("\nSummary: %d/%d attacks blocked" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
