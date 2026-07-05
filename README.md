<div align="center">

# HackLab

**Deliberately Vulnerable Web Application + Automated Exploits + Hardened Secure Version**

A security education platform built around a real Flask application.  
13 vulnerability classes. 13 exploit scripts. Two codebases — one broken, one fixed.

[Quick Start](#quick-start) · [Attack Catalog](#attack-catalog) · [Secure Version](#the-secure-version) · [Project Structure](#project-structure)

</div>

---

## Table of Contents

- [Background](#background)
- [Quick Start](#quick-start)
  - [Vulnerable Version](#vulnerable-version-port-5000)
  - [Secure Version](#secure-version-port-5001)
  - [Running Exploits](#running-exploit-scripts)
- [The Application](#the-application)
- [Attack Catalog](#attack-catalog)
  - [1. SQL Injection — Classic (UNION)](#1-sql-injection--classic-union-based)
  - [2. SQL Injection — Blind (Boolean)](#2-sql-injection--blind-boolean-based)
  - [3. SQL Injection — Time-based Blind](#3-sql-injection--time-based-blind)
  - [4. OS Command Injection](#4-os-command-injection)
  - [5. Path Traversal / LFI](#5-path-traversal--local-file-inclusion-lfi)
  - [6. SSRF](#6-server-side-request-forgery-ssrf)
  - [7. Session Cookie Forgery](#7-session-cookie-forgery)
  - [8. Werkzeug Debug PIN -> RCE](#8-werkzeug-debug-pin--rce)
  - [9. Stored XSS](#9-stored-cross-site-scripting-xss)
  - [10. CSRF](#10-cross-site-request-forgery-csrf)
  - [11. Open Redirect](#11-open-redirect)
  - [12. Brute Force](#12-brute-force--username-enumeration)
  - [13. Credential Dump](#13-credential-dump-via-database-theft)
- [The Secure Version](#the-secure-version)
  - [What Changed](#what-changed)
  - [New Dependencies](#new-dependencies)
  - [Security Headers](#security-headers)
  - [Verification](#verification)
- [Project Structure](#project-structure)
- [Disclaimer](#disclaimer)

---

## Background

About a year ago I was learning fullstack development and built a small web app with Flask — a QR code encoder/decoder and a markdown note editor. I got it working, learned what I wanted to learn, and left the project sitting.

Months later I picked it back up with a completely different goal. Made a single copy documented, and exploitable with automated scripts. Then built a second copy with all of them properly fixed.

The result is a two-sided security lab. Run the vulnerable version, watch the exploits tear it apart, then run the secure version and watch the exact same scripts fail. The delta between the two codebases is the actual lesson.

<div align="right"><a href="#table-of-contents">back to top</a></div>

---

## Quick Start

### Vulnerable Version (port 5000)

```bash
cd vulnerable/
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 scripts/import_notes.py   # loads markdown notes (including XSS payloads)
python3 app.py                    # http://127.0.0.1:5000
```

Default credentials: `admin / admin123` and `potato / test123`

### Secure Version (port 5001)

```bash
cd secure/
source ../vulnerable/venv/bin/activate
pip install flask-wtf flask-limiter bleach
rm -f instance/notes.db           # schema changed, needs a fresh DB
python3 app.py                    # http://127.0.0.1:5001
python3 scripts/import_notes.py
```

Both run simultaneously.

### Running Exploit Scripts

Every script takes `--target` to point at either version:

```bash
# against vulnerable (attacks succeed)
python3 scripts/sqli_classic.py --target http://127.0.0.1:5000

# against secure (attacks fail)
python3 scripts/sqli_classic.py --target http://127.0.0.1:5001
```

<div align="right"><a href="#table-of-contents">back to top</a></div>

---

## The Application

At its core this is a multi-tool web app with a dark-themed UI:

| Feature | Description |
|---|---|
| **QR Code Generator** | Encode text into QR codes, decode uploaded QR images back to text |
| **Markdown Note Editor** | Create, view, search, categorize notes with full markdown rendering |
| **File Download Service** | Serve files from a static directory |
| **Network Ping Tool** | Send ICMP ping to a hostname and display the output |
| **URL Preview Tool** | Fetch and display the content of any URL |
| **User Authentication** | Register, login, logout, change password |
| **Search** | Full-text search across all notes |

Each feature works correctly for normal users. The vulnerabilities are in how the features handle untrusted input.

<div align="right"><a href="#table-of-contents">back to top</a></div>

---

## Attack Catalog

Each section explains the vulnerability in depth — what the code does wrong, exactly how the exploit works at the payload level, what the automated script does step by step, and what the secure version changes.

---

### 1. SQL Injection — Classic (UNION-based)

> **Script:** `sqli_classic.py` · **Endpoint:** `/search` · **Severity:** Critical

<details>
<summary><b>The Vulnerable Code</b></summary>

```python
q = request.args.get('q', '')
sql = f"SELECT id, title, content, category, created_at FROM notes WHERE title LIKE '%{q}%' OR content LIKE '%{q}%'"
result = db.session.execute(text(sql))
```

The search term `q` is inserted into the SQL string via f-string. There is no parameterization, no escaping, no validation. Whatever the user types becomes part of the SQL query structure.

</details>

**How the attack works:**

**Step 1 — Confirm injection.** The attacker enters `' OR 1=1 --` in the search box. The query becomes:

```sql
SELECT ... WHERE title LIKE '%' OR 1=1 --%' OR content ...
```

The single quote closes the LIKE string. `OR 1=1` makes the WHERE clause always true. `--` comments out the rest. If this returns more results than a normal search, injection is confirmed.

**Step 2 — Find column count.** UNION SELECT requires both queries to return the same number of columns. The attacker sends `' ORDER BY 1 --`, `' ORDER BY 2 --`, incrementing until the database throws an error. `ORDER BY 6` fails but `ORDER BY 5` succeeds — the query has 5 columns.

**Step 3 — Read the database schema.** SQLite stores CREATE TABLE statements in `sqlite_master`:

```sql
' UNION SELECT 0, tbl_name, sql, '__schema__', 0 FROM sqlite_master WHERE type='table' --
```

Table names and column definitions appear as search results.

**Step 4 — Dump credentials.**

```sql
' UNION SELECT 0, username, password, role, 0 FROM users --
```

Every username and plaintext password shows up in the search results. The entire attack takes about 5 HTTP requests.

**Secure version fix:** ORM parameterized queries. Input is bound as data, never part of the SQL structure. Debug SQL display removed.

<div align="right"><a href="#attack-catalog">back to catalog</a> · <a href="#table-of-contents">top</a></div>

---

### 2. SQL Injection — Blind (Boolean-based)

> **Script:** `sqli_blind.py` · **Endpoint:** `/search` · **Severity:** Critical

Works when UNION results are not visible on the page. The attacker asks the database yes/no questions:

```sql
' AND SUBSTR((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a' --
```

If true — search returns results. If false — zero results.

The attacker tests every character (73 in charset) at every position. To extract an 8-character password: roughly 8 × 73 / 2 = ~290 requests on average.

The payload template `' AND 1=0 OR ({condition}) --` kills the original results so only the injected condition determines whether results appear. Clean true/false signal regardless of what notes exist.

**Secure version fix:** Same — ORM parameterized queries. No injection point exists.

<div align="right"><a href="#attack-catalog">back to catalog</a> · <a href="#table-of-contents">top</a></div>

---

### 3. SQL Injection — Time-based Blind

> **Script:** `sqli_time.py` · **Endpoint:** `/search` · **Severity:** Critical

When even result counts are hidden. The only signal is how long the server takes to respond.

SQLite has no `SLEEP()`, so we force a heavy computation:

```sql
CASE WHEN (condition) THEN length(randomblob(50000000)) ELSE 0 END
```

TRUE condition: SQLite allocates 50MB of random data in memory — takes 200-500ms. FALSE condition: returns 0 instantly.

The script calibrates first — measures baseline vs delayed response, sets a threshold, then extracts data character by character using timing. Each character requires one timed request per charset entry.

**Secure version fix:** Same — parameterized queries prevent all three SQLi types.

<div align="right"><a href="#attack-catalog">back to catalog</a> · <a href="#table-of-contents">top</a></div>

---

### 4. OS Command Injection

> **Script:** `cmdi.py` · **Endpoint:** `/ping` · **Severity:** Critical

<details>
<summary><b>The Vulnerable Code</b></summary>

```python
cmd = f"ping -c 2 {host}"
subprocess.run(cmd, shell=True, capture_output=True, text=True)
```

`shell=True` passes the string to `/bin/sh`, which interprets all metacharacters.

</details>

**Seven injection techniques:**

| Technique | Payload | Effect |
|---|---|---|
| Semicolon | `127.0.0.1; whoami` | Run both commands sequentially |
| AND | `127.0.0.1 && cat /etc/passwd` | Run second if first succeeds |
| OR | `invalid \|\| whoami` | Run second if first fails |
| Pipe | `127.0.0.1 \| whoami` | Pipe output into second command |
| Newline | `127.0.0.1\nwhoami` | Newline acts as separator |
| Subshell | `$(whoami)` | Command substitution |
| Backticks | `` `whoami` `` | Legacy command substitution |

After confirming injection, the script gathers system recon (username, hostname, OS, network config), reads sensitive files (`/etc/passwd`, `app.py`), proves write capability (`echo > /tmp/proof.txt`), and surveys installed tools (`curl`, `wget`, `python3`, `gcc`, `nc`).

Unlike LFI which can only read files, command injection gives full OS access — read, write, execute, download tools, open reverse shells.

**Secure version fix:** Two layers. Regex whitelist `^[a-zA-Z0-9._-]+$` rejects metacharacters. `subprocess.run(["ping", "-c", "2", host])` with `shell=False` — the shell never interprets the input.

<div align="right"><a href="#attack-catalog">back to catalog</a> · <a href="#table-of-contents">top</a></div>

---

### 5. Path Traversal / Local File Inclusion (LFI)

> **Scripts:** `credential_dump.py`, `session_forgery.py`, `lfi_to_rce.py` · **Endpoint:** `/download` · **Severity:** Critical

<details>
<summary><b>The Vulnerable Code</b></summary>

```python
file_path = os.path.join(base_dir, filename)
with open(file_path, 'r') as f:
    content = f.read()
```

`os.path.join` does not block `../` sequences.

</details>

**What can be read via path traversal:**

| Payload | Leaks | Used by |
|---|---|---|
| `../../app.py` | SECRET_KEY, database URI, all route logic | session_forgery.py |
| `../../instance/notes.db` | Entire SQLite database (all users, all notes) | credential_dump.py |
| `../../etc/passwd` | System usernames, home directories | lfi_to_rce.py |
| `../../etc/machine-id` | Machine identifier (Werkzeug PIN input) | lfi_to_rce.py |
| `../../proc/self/cgroup` | Cgroup info (Werkzeug PIN input) | lfi_to_rce.py |
| `../../sys/class/net/eth0/address` | MAC address (Werkzeug PIN input) | lfi_to_rce.py |

Three different scripts chain LFI with other vulnerabilities:
- **credential_dump.py** — LFI + plaintext passwords -> downloads DB, reads all credentials
- **session_forgery.py** — LFI + hardcoded SECRET_KEY -> reads app.py, forges admin cookies
- **lfi_to_rce.py** — LFI + debug mode -> reads system files, calculates Werkzeug PIN, gets RCE

**Secure version fix:** `os.path.realpath()` resolves `../` to absolute path, `startswith()` confirms it stays inside the allowed directory, `send_from_directory()` for safe file serving. Generic error messages.

<div align="right"><a href="#attack-catalog">back to catalog</a> · <a href="#table-of-contents">top</a></div>

---

### 6. Server-Side Request Forgery (SSRF)

> **Script:** `ssrf.py` · **Endpoint:** `/preview` · **Severity:** High

The server fetches any URL the user provides — no validation, forwards session cookies, follows redirects. The attacker turns the server into a proxy.

**What the script demonstrates:**

| Phase | Technique | Impact |
|---|---|---|
| Internal access | `http://127.0.0.1:5000/notes` | Reach firewalled endpoints via localhost |
| SSRF -> LFI | `http://127.0.0.1:5000/download?file=../../etc/passwd` | Server exploits its own path traversal |
| SSRF -> SQLi | `http://127.0.0.1:5000/search?q=' UNION SELECT ...` | Server sends injection payloads to itself |
| Port scan | `http://127.0.0.1:{22,3306,6379,...}/` | Map internal services invisible from outside |
| Cloud metadata | `http://169.254.169.254/latest/meta-data/iam/` | Steal cloud credentials (Capital One breach technique) |

Cookie forwarding makes it worse — internal requests via SSRF are authenticated because the server sends the victim's session cookie along.

**Secure version fix:** DNS resolution first, then check resolved IP against private ranges (`is_private`, `is_loopback`, `is_link_local`). Only HTTP/HTTPS. No cookie forwarding. No redirect following. Response capped at 50KB.

<div align="right"><a href="#attack-catalog">back to catalog</a> · <a href="#table-of-contents">top</a></div>

---

### 7. Session Cookie Forgery

> **Script:** `session_forgery.py` · **Target:** SECRET_KEY + Flask sessions · **Severity:** Critical

Flask session cookies are signed (HMAC-SHA1) but not encrypted. The app hardcodes `SECRET_KEY = 'super-secret-key-123'`.

**The full chain:**

1. Register a throwaway account
2. Read `app.py` via LFI -> extract SECRET_KEY
3. Use Flask's `SecureCookieSessionInterface` to sign a cookie with `{logged_in: True, username: 'admin'}`
4. Set the cookie in browser -> instant admin access, no password needed

The script also forges cookies for users that do not exist (`ghost_user`), and the server accepts them because `before_request` only checks `session['logged_in']`, not whether the username is real.

This is worse than stealing a password. Changing the victim's password does nothing — the attacker forges a new cookie. The only fix is rotating the SECRET_KEY, which logs out every user.

**Secure version fix:** `secrets.token_hex(32)` — 256 bits of randomness. Even reading the source shows `os.environ.get(...)`, not a literal. LFI also fixed.

<div align="right"><a href="#attack-catalog">back to catalog</a> · <a href="#table-of-contents">top</a></div>

---

### 8. Werkzeug Debug PIN -> RCE

> **Scripts:** `werkzeug_pin_calc.py`, `lfi_to_rce.py` · **Target:** debug console · **Severity:** Critical

With `debug=True`, unhandled exceptions show an interactive Python console protected by a PIN. The PIN is calculated from values the attacker reads via LFI:

| Value | Source | How obtained |
|---|---|---|
| Username | Stack trace | Trigger `/debug_test` |
| `flask.app` / `Flask` | Hardcoded | Always the same |
| Flask install path | Stack trace | Visible in traceback |
| MAC address | `/sys/class/net/<iface>/address` | LFI |
| Machine ID | `/etc/machine-id` | LFI |
| Cgroup info | `/proc/self/cgroup` | LFI |

`werkzeug_pin_calc.py` reimplements Werkzeug's SHA-1 PIN algorithm locally. `lfi_to_rce.py` chains the entire attack: register -> error page -> LFI system files -> calculate PIN -> authenticate to debugger -> `os.popen('whoami')` -> full RCE.

Neither vulnerability alone is enough. `debug=True` without LFI: PIN blocks console. LFI without `debug=True`: no console exists. Together: complete server control.

**Secure version fix:** `debug=False`. Crash endpoints removed. No interactive console at all.

<div align="right"><a href="#attack-catalog">back to catalog</a> · <a href="#table-of-contents">top</a></div>

---

### 9. Stored Cross-Site Scripting (XSS)

> **Payloads:** `xss_1_alert.md` through `xss_4_phishing.md` · **Endpoint:** `/notes/<id>` · **Severity:** High

The markdown library converts `.md` to HTML and `{{ content|safe }}` in the template disables Jinja2 auto-escaping. Raw `<script>` tags in notes execute in the viewer's browser.

**Four test payloads included:**

| Note | Attack | Detail |
|---|---|---|
| **xss_1_alert** | Proof of concept | `alert('XSS')` — confirms the vector |
| **xss_2_cookie** | Cookie theft | Invisible `<img>` sends `document.cookie` to attacker's server |
| **xss_3_defacement** | Keylogger + phishing | Replaces page with fake login form, captures keystrokes |
| **xss_4_phishing** | Self-propagating worm | Auto-creates new notes with the same payload, hijacks clipboard |

Cookie theft works because `SESSION_COOKIE_HTTPONLY = False` — JavaScript can read `document.cookie`.

**Secure version fix:** `bleach.clean()` with tag whitelist strips `<script>`, `<iframe>`, `onerror=` while allowing `<h1>`, `<p>`, `<code>`, `<a>`, `<table>`. CSP header `script-src 'self'` as second layer. `HttpOnly=True` makes cookie theft return empty.

<div align="right"><a href="#attack-catalog">back to catalog</a> · <a href="#table-of-contents">top</a></div>

---

### 10. Cross-Site Request Forgery (CSRF)

> **Attacker pages:** `csrf_attacker_site.html`, `csrf_newsletter.html` · **Targets:** `/change_password`, `/delete_note`, `/add_note` · **Severity:** High

Password changes work via GET parameters with no CSRF token and no current password check:

```
GET /change_password?new_password=hacked
```

An attacker embeds `<img src="http://127.0.0.1:5000/change_password?new_password=hacked">` on any website. The victim's browser loads the "image," sends the GET request with the session cookie (because `SameSite=None`), and the password changes silently.

`csrf_attacker_site.html` auto-submits hidden forms that change passwords, delete notes, and inject XSS payloads. `csrf_newsletter.html` disguises the attack as a newsletter signup.

**Secure version fix:** Flask-WTF `CSRFProtect` validates a hidden token on every POST. State changes are POST-only. Password changes require current password. `SameSite=Lax` blocks cross-site cookie sending.

<div align="right"><a href="#attack-catalog">back to catalog</a> · <a href="#table-of-contents">top</a></div>

---

### 11. Open Redirect

> **Script:** `open_redirect.py` · **Endpoint:** `/login?next=` · **Severity:** Medium

After login, the app redirects to whatever is in `?next=` with no validation. The attacker crafts:

```
http://your-site.com/login?next=http://evil.com/fake-login
```

The victim sees the legitimate domain, logs in normally, gets redirected to a phishing page showing "Session expired." They enter credentials again — this time on the attacker's server.

**Eight bypass techniques tested:**

| Technique | Payload | How it bypasses validation |
|---|---|---|
| Direct | `http://evil.com` | No validation exists |
| Protocol-relative | `//evil.com` | Browser adds current protocol |
| Backslash | `/\evil.com` | Some parsers treat as hostname |
| @ trick | `http://legit.com@evil.com` | Browser goes to evil.com |
| Encoded dots | `http://evil%2Ecom` | Encoded dot bypasses string match |
| Tab injection | `http://evil\t.com` | Tab confuses validators |
| Double encoding | `http%3A%2F%2Fevil.com` | Bypasses single-decode checks |
| Path confusion | `http://legit.com%2F@evil.com` | Confuses URL parsers |

The script starts its own HTTP server on port 8888 to serve the phishing page — no separate terminal needed.

**Secure version fix:** `urlparse()` rejects scheme/netloc. Catches `//` and `/\` tricks. Only relative paths starting with `/` accepted. `before_request` stores `request.path` not `request.url`.

<div align="right"><a href="#attack-catalog">back to catalog</a> · <a href="#table-of-contents">top</a></div>

---

### 12. Brute Force + Username Enumeration

> **Script:** `brute_force.py` · **Targets:** `/register`, `/login` · **Severity:** Medium

**Phase 1 — Username enumeration.** The registration endpoint says "Username already taken" for existing users. The script sends 92 common usernames from `wordlists/usernames.txt` and collects the confirmed ones.

**Phase 2 — Password brute force.** For each discovered user, the script tries:
1. Per-user mutations first: `admin` -> `admin123`, `Admin!`, `admin1`, `ADMIN`, `nimda`, etc. (15 mutations)
2. Full `wordlists/passwords.txt` (217 entries)

No rate limiting, no lockout, no CAPTCHA. Runs at hundreds of requests per second. `admin / admin123` typically cracks within 50 attempts.

**Secure version fix:** Generic "Registration failed" message. Login: 5 attempts/min. Register: 10/min. Min 8 char password. Alphanumeric username validation.

<div align="right"><a href="#attack-catalog">back to catalog</a> · <a href="#table-of-contents">top</a></div>

---

### 13. Credential Dump via Database Theft

> **Script:** `credential_dump.py` · **Endpoint:** `/download` + `instance/notes.db` · **Severity:** Critical

Chains LFI with plaintext password storage. The script downloads the SQLite database via path traversal (`/download?file=../../../instance/notes.db`), checks for the `SQLite format 3` magic header, saves it locally, opens with `sqlite3`, and reads every username and password in seconds.

One vulnerability (LFI) exposes every account simultaneously. Users who reuse passwords across sites get compromised everywhere — email, banking, social media. Even after patching the LFI, stolen passwords remain valid.

**Secure version fix:** PBKDF2-SHA256 hashing — even a stolen database yields hashes that take hours to crack. LFI also fixed.

<div align="right"><a href="#attack-catalog">back to catalog</a> · <a href="#table-of-contents">top</a></div>

---

## The Secure Version

The `secure/` directory is the same codebase with targeted fixes for every vulnerability. Diff the two `app.py` files to see exactly what changed.

### What Changed

| Component | Vulnerable | Secure |
|---|---|---|
| SECRET_KEY | `'super-secret-key-123'` | `secrets.token_hex(32)` |
| Passwords | Plaintext in DB | PBKDF2-SHA256 hashed |
| SQL queries | f-string interpolation | ORM parameterized |
| Shell commands | `shell=True` + f-string | `shell=False` + arg list + regex |
| File downloads | `os.path.join` only | `realpath` + `startswith` + `send_from_directory` |
| URL preview | No validation | DNS resolve + private IP block + no cookies |
| Redirect | No validation | `urlparse` + scheme/netloc check |
| XSS | `\|safe` directly | `bleach.clean()` whitelist + CSP headers |
| CSRF | No tokens, GET state changes | Flask-WTF + POST only + current password |
| Rate limiting | None | 5 login/min, 10 register/min |
| Cookies | `SameSite=None`, `HttpOnly=False` | `SameSite=Lax`, `HttpOnly=True` |
| Debug | `True` | `False`, crash endpoints removed |
| Errors | Full tracebacks, file paths | Generic messages |
| Notes | No ownership | Owner field + IDOR check on delete |

### New Dependencies

| Package | Purpose |
|---|---|
| **Flask-WTF** | CSRF token generation and validation on every form |
| **Flask-Limiter** | Per-IP rate limiting with in-memory storage |
| **bleach** | HTML sanitization with tag/attribute whitelisting |

### Security Headers

Every response includes:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; ...
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

### Verification

```bash
# terminal 1: vulnerable
cd vulnerable && python3 app.py

# terminal 2: secure
cd secure && python3 app.py

# terminal 3: compare
python3 scripts/sqli_classic.py --target http://127.0.0.1:5000   # dumps all credentials
python3 scripts/sqli_classic.py --target http://127.0.0.1:5001   # "Injection did not change results"

python3 scripts/brute_force.py --target http://127.0.0.1:5000    # cracks admin in seconds
python3 scripts/brute_force.py --target http://127.0.0.1:5001    # "Found: 0 valid usernames"

python3 scripts/lfi_to_rce.py --target http://127.0.0.1:5000     # achieves full RCE
python3 scripts/lfi_to_rce.py --target http://127.0.0.1:5001     # "LFI failed"
```

<div align="right"><a href="#table-of-contents">back to top</a></div>

---

## Project Structure

```
web_project/
├── README.md
│
├── vulnerable/                  # intentionally broken (port 5000)
│   ├── app.py                   # every OWASP vulnerability class
│   ├── models.py                # plaintext passwords
│   ├── requirements.txt
│   ├── templates/               # jinja2 templates (|safe filter, no CSRF tokens)
│   ├── static/                  # CSS, images, downloadable files
│   ├── scripts/                 # 13 automated exploit scripts
│   │   ├── sqli_classic.py      # UNION-based SQL injection
│   │   ├── sqli_blind.py        # boolean-based blind SQLi
│   │   ├── sqli_time.py         # time-based blind SQLi
│   │   ├── cmdi.py              # OS command injection
│   │   ├── credential_dump.py   # LFI -> DB theft -> plaintext passwords
│   │   ├── session_forgery.py   # LFI -> SECRET_KEY -> cookie forgery
│   │   ├── lfi_to_rce.py        # LFI -> Werkzeug PIN -> RCE
│   │   ├── werkzeug_pin_calc.py # standalone PIN calculator
│   │   ├── ssrf.py              # SSRF port scan + vuln chaining
│   │   ├── brute_force.py       # username enum + password brute force
│   │   ├── open_redirect.py     # redirect bypass + phishing server
│   │   ├── db.py                # database initializer
│   │   └── import_notes.py      # markdown note importer
│   ├── markdowns/               # note content + XSS payloads
│   │   └── hacklab/             # attack documentation (.md)
│   └── wordlists/               # username + password lists
│       ├── usernames.txt
│       └── passwords.txt
│
├── secure/                      # hardened version (port 5001)
│   ├── app.py                   # every vulnerability fixed
│   ├── models.py                # password hashing, ownership
│   ├── requirements.txt         # + flask-wtf, flask-limiter, bleach
│   ├── templates/               # CSRF tokens, no info leakage
│   ├── scripts/                 # same scripts (verify fixes work)
│   ├── SECURITY_CHANGES.md      # detailed fix documentation
│   └── ...
│
└── attacker_pages/              # standalone attacker HTML pages
    ├── csrf_attacker_site.html   # auto-submitting CSRF forms
    ├── csrf_newsletter.html      # disguised CSRF attack
    └── open_redirect_phishing.html  # fake login phishing page
```

<div align="right"><a href="#table-of-contents">back to top</a></div>

---

## Disclaimer

This project is for educational purposes only. Run it on your own machine, on your own network. Do not use these tools or techniques against systems you do not own or have explicit written permission to test.

<div align="right"><a href="#table-of-contents">back to top</a></div>
