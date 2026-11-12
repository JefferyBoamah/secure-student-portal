# Kerberos single sign-on for staff (reference configuration)

> **Status: reference configuration. It was NOT executed in the development environment** because Kerberos needs
> a real KDC (a Windows Active Directory domain controller or an MIT Kerberos server). The files below are the
> standard settings used to put Kerberos in front of the staff pages. The student pages keep password + TOTP MFA.

## Why Kerberos here

Kerberos gives staff (registry, lecturers, admins) single sign-on with tickets instead of passwords crossing the
network: the user proves identity to the KDC, receives a time-limited service ticket for `HTTP/portal.example.edu`,
and the web server validates it without ever seeing the password. Tickets expire (default 10 hours) and are bound to
the service, which limits replay.

```
Staff PC --(1) password/AS-REQ--> KDC (Active Directory / MIT)
Staff PC <-(2) TGT -------------- KDC
Staff PC --(3) TGS-REQ for HTTP/portal.example.edu --> KDC
Staff PC <-(4) service ticket ---- KDC
Staff PC --(5) HTTPS + "Authorization: Negotiate <ticket>" --> Nginx/Apache --> Portal (staff area)
```

## 1. KDC: create the service principal and keytab (MIT Kerberos example)

```bash
kadmin.local -q "addprinc -randkey HTTP/portal.example.edu@EXAMPLE.EDU"
kadmin.local -q "ktadd -k /etc/portal/portal.keytab HTTP/portal.example.edu@EXAMPLE.EDU"
chown www-data:www-data /etc/portal/portal.keytab && chmod 400 /etc/portal/portal.keytab
```
(On Active Directory: create a service account, then `ktpass -princ HTTP/portal.example.edu@EXAMPLE.EDU ...`.)

## 2. `/etc/krb5.conf` on the web server

```ini
[libdefaults]
    default_realm = EXAMPLE.EDU
    dns_lookup_kdc = true
    ticket_lifetime = 10h
    renew_lifetime = 7d
    forwardable = false
    rdns = false
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    allow_weak_crypto = false             # refuse DES / RC4

[realms]
    EXAMPLE.EDU = {
        kdc = kdc1.example.edu
        admin_server = kdc1.example.edu
    }

[domain_realm]
    .example.edu = EXAMPLE.EDU
    example.edu = EXAMPLE.EDU
```

## 3. Web server: Apache `mod_auth_gssapi` in front of the staff area

```apache
<Location "/staff">
    AuthType GSSAPI
    AuthName "University SSO"
    GssapiCredStore keytab:/etc/portal/portal.keytab
    GssapiLocalName On
    GssapiNegotiateOnce On
    Require valid-user
    # Pass the verified Kerberos identity to the app. The app must only trust this header when the request
    # arrives from the local proxy, and the proxy must strip any client-supplied copy of it.
    RequestHeader unset X-Remote-User
    RequestHeader set  X-Remote-User "%{REMOTE_USER}s"
</Location>
```

## 4. Hardening notes

- Time must be synchronised (NTP) on KDC, server and clients, since Kerberos rejects tickets if clocks drift more than 5 minutes.
- Use AES encryption types only; disable DES and RC4 (`allow_weak_crypto = false`).
- Keep the keytab readable only by the web server user (chmod 400) and rotate it with `kvno` changes.
- Combine with the portal's role checks: Kerberos proves *who* the staff member is; the portal's RBAC still decides *what* they may do.
- Keep password + TOTP as the fallback for off-campus access.
