# Secure Version — Security Changes Documentation

This document details every security fix applied to the `secure/` version of the application, what each change prevents, and how it maps to the exploit scripts in `vulnerable/scripts/`.

---

## Setup

```bash
cd secure/

# Delete old DB — new schema (password_hash, owner) required
rm -f instance/notes.db

# Install new dependencies
pip install -r requirements.txt --break-system-packages

# Run on port 5001 (vulnerable can run simultaneously on 5000)
python3 app.py
```

---

## 1. SECRET_KEY — Static → Random

| | Vulnerable | Secure |
|---|---|---|
| **Code** | `'super-secret-key-123'` | `os.environ.get('SECRET_KEY') or secrets.token_hex(32)` |
| **Risk** | Readable via LFI, guessable | 64 hex chars per startup, impossible to brute force |

**Attack prevented:** Session Cookie Forgery (`session_forgery.py`)

When the SECRET_KEY is known, an attacker can sign valid session cookies for any user without a password. A cryptographically random 256-bit key eliminates guessing and brute force entirely.

---

## 2. Password Storage — Plaintext → Hash

| | Vulnerable | Secure |
|---|---|---|
| **Storage** | `password='admin123'` | `password_hash=generate_password_hash('admin123')` |
| **Verification** | `filter_by(password=input)` | `user.check_password(input)` |
| **Algorithm** | None | PBKDF2-SHA256 + random salt |

**Attack prevented:** Credential Dump (`credential_dump.py`)

Even if the database is stolen, hashes cannot be reversed. Each user gets a unique salt — rainbow table attacks are useless. Weak passwords like `admin123` still take hours to crack instead of zero seconds.

**models.py changes:**
- `password` column → `password_hash` column (VARCHAR 256)
- `set_password()` and `check_password()` methods added
- `owner` column added to `Note` model (for IDOR protection)

---

## 3. SQL Injection — Raw SQL → ORM

| | Vulnerable | Secure |
|---|---|---|
| **Query** | `f"SELECT ... WHERE title LIKE '%{q}%'"` | `Note.query.filter(Note.title.like(f"%{q}%"))` |
| **Errors** | `error = str(e)` — leaks SQL internals | Generic "An error occurred" |
| **Debug** | `executed_sql` shown on page | Removed |

**Attacks prevented:** SQLi Classic, SQLi Blind, SQLi Time-based (`sqli_classic.py`, `sqli_blind.py`, `sqli_time.py`)

The ORM generates parameterized queries — user input is never part of the SQL structure. Payloads like `UNION SELECT`, `SUBSTR()`, and `zeroblob()` are treated as literal search terms.

---

## 4. Command Injection — shell=True → Argument List

| | Vulnerable | Secure |
|---|---|---|
| **Command** | `f"ping -c 2 {host}"` + `shell=True` | `["ping", "-c", "2", host]` + `shell=False` |
| **Validation** | None | `re.match(r'^[a-zA-Z0-9._-]+$', host)` |
| **Errors** | Detailed error messages | Generic message |

**Attack prevented:** OS Command Injection (`cmdi.py`)

With `shell=False`, metacharacters like `;`, `|`, `&&` are not interpreted by the shell — they are passed as literal arguments to `ping`. The regex whitelist provides defense in depth by rejecting any input containing special characters before the command runs.

---

## 5. LFI/Path Traversal — No Validation → realpath Check

| | Vulnerable | Secure |
|---|---|---|
| **Path** | `os.path.join(base_dir, filename)` | `os.path.realpath(os.path.join(base_dir, filename))` |
| **Check** | None | `file_path.startswith(os.path.realpath(base_dir))` |
| **Errors** | File paths leaked in messages | `abort(403)` / `abort(404)` |
| **Delivery** | Manual `open()` + read | `send_from_directory()` |

**Attacks prevented:** LFI→RCE chain, Credential Dump via DB theft (`lfi_to_rce.py`, `credential_dump.py`)

`os.path.realpath()` resolves all `../` sequences to an absolute path. If the result falls outside `base_dir`, the request is rejected with `403 Forbidden`. `send_from_directory()` adds an additional safety layer. Payloads like `../../etc/passwd` and `../../instance/notes.db` are blocked.

---

## 6. SSRF — Unfiltered → Multi-Layer Protection

| | Vulnerable | Secure |
|---|---|---|
| **IP check** | None | `ipaddress.is_private`, `is_loopback`, `is_link_local` |
| **Protocol** | All allowed | Only `http` and `https` |
| **Metadata** | `169.254.169.254` accessible | Blocked |
| **Cookies** | User cookies forwarded | Cookies never sent |
| **Redirects** | `allow_redirects=True` | `allow_redirects=False` |
| **Size** | Unlimited | Max 50KB response |

**Attack prevented:** SSRF port scanning and vulnerability chaining (`ssrf.py`)

The `is_ssrf_safe()` function resolves hostnames via DNS, then checks the resulting IP against private ranges (10.x, 172.16.x, 192.168.x), loopback (127.0.0.1), link-local, and the cloud metadata endpoint (169.254.169.254). Cookies are never forwarded, preventing session leakage. Redirects are not followed, blocking redirect-chain attacks.

**Improvement over markdown recommendation:** The markdowns suggested only IP blocklisting. The secure version adds DNS resolution before checking (prevents DNS rebinding), disables redirect following (prevents redirect chains to internal services), removes cookie forwarding (prevents session leakage to external URLs), and caps response size at 50KB (prevents DoS via large responses).

---

## 7. Open Redirect — No Validation → urlparse Check

| | Vulnerable | Secure |
|---|---|---|
| **next parameter** | `redirect(next_url)` — no validation | `is_safe_redirect()` — scheme/netloc/bypass check |
| **before_request** | `next=request.url` (full URL with scheme) | `next=request.path` (relative path only) |

**Attack prevented:** Open Redirect→Phishing (`open_redirect.py`)

The `is_safe_redirect()` function uses `urlparse` to check for scheme and netloc. Protocol-relative (`//evil.com`), backslash trick (`/\evil.com`), and `@` trick bypasses are all blocked. Only relative paths starting with `/` are accepted. The `before_request` hook now stores only the path (e.g., `/settings`) instead of the full URL (e.g., `http://127.0.0.1:5000/settings`), which eliminates scheme injection at the source.

---

## 8. XSS — |safe Filter → bleach Sanitization + CSP

| | Vulnerable | Secure |
|---|---|---|
| **Output** | `{{ content\|safe }}` — all HTML passes | `sanitize_html()` then `{{ content\|safe }}` |
| **Allowed** | Everything including `<script>`, `<iframe>`, `onerror=` | Only `<h1>`, `<p>`, `<a>`, `<code>`, `<table>`, etc. |
| **CSP** | None | `script-src 'self'` — inline scripts blocked by browser |

**Attacks prevented:** All XSS variants — Alert, Cookie Theft, Keylogger+Defacement, Worm (`xss_1` through `xss_4`)

`bleach.clean()` applies whitelist-based sanitization. Tags not in `ALLOWED_TAGS` (like `<script>`, `<iframe>`) and attributes not in `ALLOWED_ATTRS` (like `onerror`, `onclick`) are stripped from the output. Legitimate markdown HTML (`<h1>`, `<p>`, `<code>`, `<a>`) passes through normally.

The Content-Security-Policy header adds a second layer: even if a `<script>` tag somehow survives sanitization, the browser refuses to execute inline scripts because the CSP only allows scripts loaded from `'self'`.

**Improvement over markdown recommendation:** The markdowns suggested either bleach OR CSP. The secure version applies both — defense in depth. The `|safe` filter is still used (necessary for markdown rendering), but the content is sanitized before reaching the template.

---

## 9. Brute Force — Unlimited → Rate Limiting

| | Vulnerable | Secure |
|---|---|---|
| **Login** | Unlimited attempts | `@limiter.limit("5/minute")` |
| **Register** | Unlimited registration | `@limiter.limit("10/minute")` |
| **Enumeration** | "Username already taken" | "Registration failed. Please try a different username." |
| **Validation** | None | Min 8 char password, 3-30 char username, alphanumeric only |

**Attack prevented:** Username Enumeration + Brute Force (`brute_force.py`)

5 login attempts per minute means a 10,000-word password list takes 33 hours instead of 30 seconds. The registration endpoint no longer confirms whether a username exists — the error message is identical regardless.

**Improvement over markdown recommendation:** The markdowns suggested rate limiting only. The secure version also adds username enumeration prevention (generic error messages), input validation (password length, username format), and applies rate limiting to registration as well (prevents mass account creation).

---

## 10. CSRF — Unprotected → Flask-WTF Token

| | Vulnerable | Secure |
|---|---|---|
| **Token** | None | `CSRFProtect(app)` + `{{ csrf_token() }}` in every form |
| **delete_note** | GET allowed — deletable via `<img src>` | POST only + CSRF token required |
| **change_password** | GET allowed — changeable via URL | POST only + CSRF token + current password required |
| **add_note** | GET parameters accepted | POST only + CSRF token required |
| **Cookie** | `SameSite=None` | `SameSite=Lax` |

**Attack prevented:** CSRF attacks (`csrf_attacker_site.html`, `csrf_newsletter.html`)

Every form includes a `csrf_token()` hidden field. POST requests without a valid token are automatically rejected with `400 Bad Request`. `SameSite=Lax` prevents the browser from sending session cookies on cross-site POST requests, adding a second layer of protection.

The password change form now requires the current password, which means even if CSRF protection were somehow bypassed, the attacker would still need to know the victim's current password to change it.

**Not covered in markdowns:** The vulnerability markdowns did not include CSRF remediation. This is an entirely new protection layer.

---

## 11. Session/Cookie Security

| | Vulnerable | Secure |
|---|---|---|
| **HttpOnly** | `False` | `True` — JavaScript cannot access `document.cookie` |
| **SameSite** | `None` | `Lax` — cookies not sent on cross-site requests |
| **Lifetime** | 5 minutes | 30 minutes |

These settings work together with XSS and CSRF protections. Even if an XSS vulnerability were found, `HttpOnly=True` prevents cookie theft via `document.cookie`. Even if a CSRF vector existed, `SameSite=Lax` prevents the browser from attaching cookies to cross-origin POST requests.

---

## 12. Debug Mode — Enabled → Disabled

| | Vulnerable | Secure |
|---|---|---|
| **debug** | `True` | `False` |
| **debug_test** | ZeroDivisionError endpoint | Removed entirely |
| **debug_test2** | FileNotFoundError endpoint | Removed entirely |

**Attack prevented:** Werkzeug Debug PIN→RCE (`lfi_to_rce.py`, `werkzeug_pin_calc.py`)

With `debug=False`, the Werkzeug interactive debugger is completely disabled. Error pages show a generic 500 response instead of an interactive Python console. The deliberately crashing endpoints (`/debug_test`, `/debug_test2`) are removed.

---

## 13. Security Headers (New)

```
Content-Security-Policy: default-src 'self'; script-src 'self'; ...
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

Added via `@app.after_request` — applied to every response automatically.

- **CSP:** Blocks inline script execution (additional XSS layer)
- **X-Frame-Options:** Prevents clickjacking by blocking iframe embedding
- **X-Content-Type-Options:** Prevents MIME sniffing attacks
- **Referrer-Policy:** Limits referrer information leakage

**Not covered in markdowns:** Security headers were mentioned briefly in the XSS and LFI markdowns but never implemented. The secure version applies them globally.

---

## 14. IDOR Protection (New)

The `Note` model now includes an `owner` column. When deleting a note, the application checks `note.owner != session.get('username')` and returns `403 Forbidden` if the logged-in user is not the note's owner.

This prevents an attacker from deleting other users' notes by guessing note IDs (e.g., `POST /delete_note/5` when the note belongs to a different user).

---

## 15. Error Messages — Verbose → Generic

All endpoints suppress internal error details (file paths, SQL queries, exception types, stack traces). Users see generic messages like "An error occurred." Details are available only in server logs, not in HTTP responses.

This prevents information disclosure that attackers use to map the application's internal structure, identify technologies, and craft targeted attacks.

---

## Verification — Run Exploit Scripts Against Secure Version

The definitive test: run the same exploit scripts against both versions.

```bash
# Terminal 1 — Vulnerable (port 5000)
cd ~/Desktop/web_project/vulnerable && python3 app.py

# Terminal 2 — Secure (port 5001)
cd ~/Desktop/web_project/secure && python3 app.py

# Terminal 3 — Run any exploit against both
python3 scripts/sqli_classic.py --target http://127.0.0.1:5000   # SUCCESS — data dumped
python3 scripts/sqli_classic.py --target http://127.0.0.1:5001   # FAIL — attack blocked

python3 scripts/brute_force.py --target http://127.0.0.1:5000    # SUCCESS — creds found
python3 scripts/brute_force.py --target http://127.0.0.1:5001    # FAIL — rate limited

python3 scripts/lfi_to_rce.py --target http://127.0.0.1:5000     # SUCCESS — RCE achieved
python3 scripts/lfi_to_rce.py --target http://127.0.0.1:5001      # FAIL — path traversal blocked
```

Every script should succeed against vulnerable and fail against secure. That delta is the proof that each protection works.
