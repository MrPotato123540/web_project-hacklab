# Session Cookie Forgery — When the SECRET_KEY is Not Secret

This attack does not exploit a bug in the code logic. It exploits a configuration mistake: the application uses a weak, guessable `SECRET_KEY`. That single string is the only thing protecting every user session on the entire platform.

---

## What is SECRET_KEY and What Does It Do

Flask stores session data inside a cookie on the user's browser. But cookies can be edited by anyone — open DevTools, change the value, done. To prevent tampering, Flask **signs** the cookie with HMAC-SHA1 using the SECRET_KEY. The signature is appended to the cookie, and on every request Flask recalculates the signature and compares. If someone changes the cookie data, the signature will not match, and Flask rejects it.

The critical detail: the session data is **not encrypted**. It is Base64-encoded, which is a reversible encoding, not a cipher. Anyone can decode a Flask cookie and read its contents. The signature only prevents **modification**, not **reading**.

This means the SECRET_KEY serves exactly one purpose: proving that the cookie was created by the server and has not been tampered with. If an attacker knows the key, they can create validly signed cookies from scratch. No password needed, no login form, no authentication of any kind.

---

## The Vulnerability in This Application

Line 14 of `app.py`:

```python
app.config['SECRET_KEY'] = 'super-secret-key-123'
```

This key is hardcoded in the source file, short, human-readable, and easily guessable. An attacker can obtain it through several paths that already exist in this application:

**Path 1 — LFI.** The `/download` endpoint has a path traversal vulnerability. An attacker requests `/download?file=../../../../../../../home/potato/Desktop/web_project/vulnerable/app.py` and reads the entire source code, including the SECRET_KEY line.

**Path 2 — Werkzeug debug console.** If the attacker has already calculated the debug PIN (using the LFI → PIN chain demonstrated earlier), they type `flask.current_app.config['SECRET_KEY']` in the console and get the key instantly.

**Path 3 — Guessing.** Developers frequently use weak keys during development and forget to change them. Common values like `secret`, `changeme`, `dev`, `password123`, and `super-secret-key-123` can be tested against a captured cookie's signature in milliseconds. A dictionary of a few thousand common keys would crack this one instantly.

**Path 4 — Source code exposure.** If the code is pushed to a public GitHub repository (or if the `.git` directory is accessible on the web server), the key is visible to anyone.

---

## The Attack Step by Step

### Step 1 — Obtain the SECRET_KEY

Using any of the methods above. For this demo, it is already known: `super-secret-key-123`.

### Step 2 — Forge a Session Cookie

Flask uses `itsdangerous.URLSafeTimedSerializer` to sign cookies. The attacker recreates this process:

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = 'super-secret-key-123'

serializer = SecureCookieSessionInterface().get_signing_serializer(app)

forged_cookie = serializer.dumps({
    'logged_in': True,
    'username': 'admin',
    '_permanent': True,
})

print(forged_cookie)
```

This outputs a string like:

```
eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYWRtaW4ifQ.ZxYzAB.abc123...
```

This cookie is indistinguishable from one created by the real server. The signature is valid because it was generated with the same key.

### Step 3 — Use the Forged Cookie

The attacker opens the browser, navigates to the target site, opens DevTools (F12), goes to Application → Cookies, and sets the `session` cookie to the forged value. On the next page load, Flask reads the cookie, verifies the signature (which passes, because the key is correct), deserializes the session data, sees `logged_in: True` and `username: admin`, and grants full access.

No password was entered. No login form was submitted. The server's authentication was completely bypassed.

### Step 4 — Impersonate Anyone

The attacker can forge cookies for any username — including users who do not even exist. The `before_request` hook in this application only checks `session.get('logged_in')`. It does not verify whether the username in the session corresponds to a real user in the USERS dictionary. So a cookie with `username: 'ceo'` would be accepted even though no such user exists.

---

## Why This is Worse Than Stealing a Password

When an attacker steals a password, the victim can change it and the attacker is locked out. When an attacker knows the SECRET_KEY, changing passwords does nothing — the attacker forges a new cookie with the same username and is back in. The only fix is changing the SECRET_KEY itself, which invalidates ALL existing sessions for ALL users.

Additionally, password theft affects one account. SECRET_KEY exposure affects every account on the platform simultaneously.

---

## Connection to Other Attacks in This Project

This vulnerability does not exist in isolation. It connects to every other attack demonstrated here:

**XSS → Cookie Theft → Decode.** XSS Test 2 steals the session cookie via `document.cookie`. With the SECRET_KEY, the attacker does not just replay the cookie — they decode it, read the session data, and understand the application's session structure. Then they forge new cookies with modified data.

**LFI → Source Code → SECRET_KEY.** The path traversal vulnerability reads `app.py` from disk. The SECRET_KEY is right there in the source. One vulnerability enables the next.

**Debug Console → Config Dump.** The Werkzeug RCE chain ends with arbitrary Python execution. One of the first things an attacker would do is dump the application configuration, which includes the SECRET_KEY.

**CSRF + Forgery.** If the attacker forges an admin cookie, they do not even need CSRF — they can perform any action directly. But combined with CSRF, they could forge a cookie, set it in a victim's browser via XSS, and make the victim appear to be a different user.

---

## How to Prevent This

**Use a cryptographically random key:**

```python
import secrets
app.config['SECRET_KEY'] = secrets.token_hex(32)
```

This generates 64 characters of random hexadecimal — effectively impossible to guess or brute force.

**Never hardcode the key:**

```python
import os
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
```

The key lives in an environment variable, not in source code. It never appears in version control.

**Use server-side sessions:**

```python
from flask_session import Session
app.config['SESSION_TYPE'] = 'redis'
Session(app)
```

With server-side sessions, the cookie only contains a random session ID. The actual session data lives on the server (in Redis, a database, or the filesystem). Even if the attacker knows the SECRET_KEY, they cannot forge session content because the content is not in the cookie — it is on the server, keyed by the random ID.

**Rotate keys periodically:**

If a key compromise is suspected, changing the SECRET_KEY immediately invalidates all existing sessions. Every user must log in again, but the attacker's forged cookies stop working.

---

## Automated Attack Script

```bash
# Full demo: decode, forge, impersonate, show LFI key theft
python3 scripts/session_forgery.py

# Quick forge for a specific user
python3 scripts/session_forgery.py --forge-user admin

# Decode a captured cookie
python3 scripts/session_forgery.py --decode "paste_cookie_here"
```
