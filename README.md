# Secure Student Portal

A student portal (login, results, fee payment, grade approval, audit log) designed and built **security-first**.
It is the group project for the Information Security course: *design and build a secured IT infrastructure
architecture for one of the Seven Domains of an IT infrastructure, deploy the security controls, and show them
denying popular cyber attacks.*

| | |
|---|---|
| **Domain focus** | System/Application domain (with the LAN-to-WAN perimeter and User domain controls that protect it) |
| **Stack** | Python 3, Flask, SQLite, `cryptography`, `PyJWT` |
| **Evidence** | 62 automated security tests + a live attack demo (25 attacks, all blocked) |

## Group members

## Group members

| # | Name | Index number | Area of responsibility |
|---|------|--------------|------------------------|
| 1 | ⁠⁠Boamah Jeffrey | 10374466 | **Authentication and MFA**: password policy, PBKDF2 hashing, account lockout, TOTP two-factor login, session handling (`app/authn.py`, `app/routes/auth.py`) |
| 2 | Agbenu Caleb  | 10335038 | **Access control (IAM)**: role-based permissions, protection against viewing other students' records, grade maker-checker workflow, admin audit page (`app/routes/portal.py`, `staff.py`, `admin.py`) |
| 3 | Yahya Mohammed Yakubu | 10322490 | **API security**: JWT tokens and revocation, HMAC-signed payment webhooks, replay protection (`app/routes/api.py`) |
| 4 | ⁠⁠Michael Affum Dankwah | 19335041 | **Data protection and web attack defences**: field encryption, SQL injection prevention, XSS, CSRF, security headers, tamper-evident audit log (`app/db.py`, `app/security.py`, `app/templates/`) |
| 5 | Jason Quaye | 10335048 | **Infrastructure and testing**: Nginx, firewall, fail2ban, Kerberos reference config, rate limiting, the 62 security tests and the live attack demo (`deploy/`, `tests/`, `scripts/attack_demo.py`) |

---

## 1. Architecture

```
                                    INTERNET / CAMPUS LAN
                                              |
                                  [ Host firewall: UFW ]           deploy/firewall.sh
                                  only 80, 443; SSH from mgmt net
                                              |
                        [ Nginx reverse proxy: TLS 1.2/1.3 + HSTS ]   deploy/nginx.conf
                        rate limits, size/timeout limits, hides banners
                                              |   127.0.0.1 only
                       +----------------------v-----------------------+
                       |          Flask application (app/)            |
                       |                                              |
   request ---------->  perimeter  -> global rate limit -> session   |
                       |  (Host,       (per IP)             load      |
                       |   HTTPS)                              |      |
                       |                                  CSRF check  |
                       |                                       |      |
                       |   auth  |  portal  |  staff  |  admin | api |
                       |  (pwd+   (results,   (grades,  (audit)  (JWT,|
                       |   TOTP)   fees)      maker-             HMAC |
                       |                      checker)         hooks)|
                       |        RBAC permission check on every view   |
                       +----------------------+-----------------------+
                                              |  parameterised SQL only
                       +----------------------v-----------------------+
                       |  SQLite database                             |
                       |  hashed passwords | encrypted phone + TOTP   |
                       |  secrets | hash-chained audit log            |
                       +----------------------------------------------+

   Staff SSO (optional):  Kerberos KDC  --ticket-->  web server        deploy/kerberos/
   Monitoring:            security.log -> fail2ban bans repeat offenders   deploy/fail2ban/
```

### Where this sits in the Seven Domains of an IT infrastructure

| Domain | What we secure here |
|---|---|
| **System/Application** (main focus) | Secure coding, parameterised SQL, RBAC, session handling, CSRF, output escaping, data encryption, audit trail |
| **LAN-to-WAN** | Firewall (UFW), Nginx perimeter, TLS, rate limiting and fail2ban |
| **User** | Strong password policy, MFA (TOTP), lockout, security-aware error messages |
| **Remote Access** | HTTPS-only access, MFA for every login, Kerberos SSO for staff (reference config) |
| Workstation / LAN / WAN | Out of scope for this build (covered in the individual risk assessment) |

---

## 2. Security controls and the attacks they stop

| Requirement from the brief | Implementation | Where | Proven by |
|---|---|---|---|
| **MFA** | TOTP (RFC 6238) required for every login, replay-protected, implemented with the standard library | `app/security.py` (section 4), `app/routes/auth.py` | `test_login_needs_second_factor`, `test_totp_code_cannot_be_replayed`, `test_totp_matches_rfc6238_test_vectors` |
| **Strong password** | 12+ chars, mixed classes, banned words, no username in password; PBKDF2-HMAC-SHA256 (600,000 iterations) with per-password salt; lockout after 5 failures | `security.validate_password`, `hash_password`, `authn.py` | `test_weak_passwords_rejected`, `test_account_lockout_after_failures` |
| **JWT** | Short-lived (15 min) HS256 tokens, algorithm pinned, issuer/audience/expiry required, revocation list, role read from the database (not the token) | `security.issue_token / decode_token`, `routes/api.py` | `test_jwt_*` (alg=none, wrong key, expired, wrong audience, tampered, revoked, forged role) |
| **Webhooks** | HMAC-SHA256 signature over timestamp + body, constant-time compare, 5-minute window, idempotent event IDs, amount verification | `security.verify_webhook`, `routes/api.py` | `test_webhook_*` (forged, replayed, stale, modified, amount mismatch) |
| **IAM** | Roles (student, lecturer, registry, admin) with least-privilege permissions; admins cannot read or change grades; maker-checker grade approval | `security.PERMISSIONS`, `routes/staff.py` | `test_student_cannot_reach_staff_or_admin`, `test_admin_cannot_read_or_change_grades`, `test_maker_checker_grade_workflow` |
| **Encryption of data sent to the database** | Field-level Fernet (AES + HMAC) encryption of phone numbers and TOTP secrets before they are stored, with key rotation; passwords are hashed, never encrypted; TLS protects data in transit | `security.encrypt_field / decrypt_field` | `test_sensitive_fields_are_encrypted_at_rest` (value is not even present in the database file), `test_encryption_key_rotation` |
| **Kerberos** | Reference configuration for staff SSO (KDC, `krb5.conf`, keytab, `mod_auth_gssapi`). Not executed here (needs a real KDC) | `deploy/kerberos/` | n/a |
| **Security perimeters** | Host allow-list, HTTPS enforcement + HSTS, Nginx rate limits, UFW firewall, fail2ban, private upstream on 127.0.0.1 | `security.enforce_perimeter`, `deploy/` | `test_http_is_redirected_to_https`, `test_host_header_attack_rejected` |

| Attack | Defence | Result in the live demo |
|---|---|---|
| **Phishing** (stolen password) | MFA means a phished password alone cannot log in; generic login errors; lockout; HSTS + Host allow-list stop look-alike relays. Training and DMARC are organisational controls (see the risk assessment) | Password-only login yields no session |
| **DDoS / flooding** (application layer) | Per-IP sliding-window limits (global, login, MFA, API, webhook), body-size cap, Nginx limits and timeouts, fail2ban. Large volumetric DDoS needs upstream scrubbing by the ISP/CDN; no app can stop that alone | 330 requests: 207 served, 123 answered with HTTP 429 |
| **Man-in-the-middle** | HTTPS only, HTTP redirected (301), HSTS, TLS 1.2+, Secure/HttpOnly/SameSite=Strict `__Host-` cookie | Plain HTTP redirected; headers present |
| **SQL injection** | Parameterised queries everywhere, strict input validation, least-privilege design, generic errors | `' OR '1'='1' --` and UNION payloads all return 401 |
| **XSS** | Auto-escaped templates, input validation, strict CSP (no inline scripts), HttpOnly cookies | Script tag refused at registration and escaped on output |
| **CSRF** | Per-session token on every state-changing form, SameSite=Strict | Forged POST returns 400 |
| **IDOR / broken access control** | Ownership check on every record, 404 instead of 403, RBAC on every view | IDs 1-39 enumerated, 0 foreign records leaked |
| **Brute force / credential stuffing** | Lockout, rate limits, identical response for unknown user and wrong password, constant-time work for both | Correct password refused once locked; HTTP 429 on rapid guessing |
| **Session hijacking / fixation** | Server-side sessions, new ID at login, idle (15 min) and absolute (8 h) timeouts, revoked on logout and on password change | `test_logout_invalidates_session`, `test_password_change_revokes_other_sessions` |
| **Insider tampering** | Hash-chained audit log (editing any row breaks the chain), maker-checker grades | `test_audit_chain_detects_tampering` |
| **Log forging** | Newlines stripped from logged values | `test_log_forging_is_neutralised` |

---

## 3. Run it (macOS / Linux)

```bash
cd secure-student-portal
python3 -m venv .venv && source .venv/bin/activate      # optional but tidy
pip install -r requirements.txt
```

**Create demo users (once):**
```bash
python3 scripts/seed.py
```
This prints the demo usernames, passwords and TOTP secrets (`admin1`, `registry1`, `lecturer1`, `ama`, `kofi`)
and saves them in `instance/demo_credentials.json`. These are demo-only accounts; the folder `instance/` is git-ignored.

**Start the server:**
```bash
python3 run.py
```
Open **https://localhost:5000**. The browser warns about the self-signed certificate (expected for local
development). Plain HTTP on port 5080 redirects to HTTPS.

**Logging in (acts like an authenticator app):** in a second terminal run
```bash
python3 scripts/totp.py ama
```
and type the 6-digit code at the "Enter your code" page. You can also register a new student account in the browser:
the page shows a secret key you can add to Google Authenticator / Microsoft Authenticator.

### Demonstrating it to the class (5 minutes)

1. `python3 -m pytest -v` shows 62 security tests passing (each test is an attack).
2. Start the server, then run `python3 scripts/attack_demo.py` and watch 25 attacks print **BLOCKED**.
3. In the browser: log in as `ama`, open Results, then change the number in `/results/<id>` to another student's ID and show the 404.
4. Log in as `lecturer1`, propose a grade for `kofi`; show it is hidden from `kofi`; approve it as `registry1`; show it appears.
5. Log in as `admin1` and open **Audit log**: show the hash-chain verification and all the security events from the demo.

> Run `attack_demo.py` only against your own local copy.

---

## 4. Deploying for production

The `run.py` server is for development and demos. For production:

```bash
pip install gunicorn
export PORTAL_BEHIND_PROXY=1 PORTAL_ALLOWED_HOSTS=portal.example.edu
export PORTAL_SECRET_KEY=... PORTAL_JWT_SECRET=... PORTAL_FERNET_KEY=... PORTAL_WEBHOOK_SECRET=...
gunicorn -w 4 -b 127.0.0.1:8000 "app:create_app()"
```
Then install `deploy/nginx.conf` (with a real certificate), run `deploy/firewall.sh`, and enable `deploy/fail2ban/`.
Generate the Fernet key with `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
Secrets come from environment variables (preferred) or a private `instance/secrets.json`; they are never in source control.

---

## 5. Honest limitations

- **Single-process rate limiter.** The in-memory limiter is per process; with several Gunicorn workers each has its own
  counters. The Nginx `limit_req` layer provides the shared limit; use Redis for a fully shared application-level limit.
- **SQLite** keeps the project easy to run. A production system should use PostgreSQL with a least-privilege application role and database-level TLS.
- **Kerberos** is provided as a reference configuration because it needs a KDC / Active Directory server. Everything else was run and tested.
- **Volumetric DDoS** cannot be stopped by application code; it needs upstream protection (ISP scrubbing or a CDN). The app handles application-layer floods.
- **Phishing** also needs user training, DMARC/SPF/DKIM and email filtering. The portal limits the damage a stolen password can do through MFA.
- Demo passwords are hard-coded in `app/seed.py` for the classroom demo only. Never seed them in a real deployment.
- No third-party penetration test was performed; the tests and the attack script are written by the project team.

---

## 6. Project structure

```
secure-student-portal/
├── run.py                    start the HTTPS server (dev)
├── requirements.txt
├── app/
│   ├── __init__.py           application factory, error handlers
│   ├── config.py             every security setting in one place
│   ├── security.py           all controls: RBAC, passwords, TOTP, encryption, audit, rate limit, CSRF, JWT, webhooks
│   ├── authn.py              credential + second-factor checks, lockout
│   ├── db.py                 SQLite schema and parameterised helpers
│   ├── seed.py               demo accounts and data
│   ├── routes/               auth, portal, staff, admin, api
│   ├── templates/            HTML (auto-escaped, no inline scripts)
│   └── static/style.css
├── scripts/                  seed.py, totp.py, make_cert.py, attack_demo.py
├── tests/                    62 security tests (pytest)
└── deploy/                   nginx.conf, firewall.sh, fail2ban/, kerberos/
```
