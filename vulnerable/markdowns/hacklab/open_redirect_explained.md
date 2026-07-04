# Open Redirect — Phishing via Login Redirect

## Overview

Open Redirect occurs when a web application redirects users to a URL specified in a parameter without validating it. While it doesn't directly compromise the server, it turns the application's legitimate domain into a phishing delivery mechanism — the victim trusts the link because it points to the real site.

OWASP classifies this under "Unvalidated Redirects and Forwards," and it is a key enabler of credential phishing, OAuth token theft, and malware delivery.

## Vulnerable Code

Two changes create the vulnerability:

### 1. before_request passes the original URL

```python
@app.before_request
def require_login():
    if request.endpoint not in allowed and not session.get('logged_in'):
        # VULNERABLE: passes full request URL as next parameter
        return redirect(url_for('login', next=request.url))
```

### 2. Login redirects to unvalidated next parameter

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if user:
        session['logged_in'] = True
        session['username'] = username
        # VULNERABLE: no validation on next_url!
        next_url = request.args.get('next', url_for('welcome'))
        return redirect(next_url)
```

The `next` parameter is taken directly from the URL and passed to `redirect()`. Since there's no check for external URLs, an attacker can set `next=http://evil.com`.

## Attack Flow

### Normal flow (intended behavior):

```
User visits /settings → not logged in → redirect to /login?next=/settings
→ user logs in → redirect to /settings ✓
```

### Attack flow:

```
Attacker crafts: http://site.com/login?next=http://evil.com/fake-login
→ victim clicks link → sees REAL login page at site.com
→ victim logs in successfully → server redirects to evil.com
→ victim sees "session expired" on attacker's page
→ victim re-enters credentials on the FAKE page
→ attacker captures credentials
```

The critical insight: the victim interacted with the **real** login page and entered their **real** credentials successfully. The redirect to the phishing page happens automatically and almost invisibly.

## Bypass Techniques

Even if basic filtering exists (e.g., blocking `http://`), attackers have many bypass options:

| Technique | Payload | Why it works |
|-----------|---------|-------------|
| Direct | `http://evil.com` | No filtering at all |
| Protocol-relative | `//evil.com` | Browser adds current protocol |
| Backslash | `/\evil.com` | Some parsers treat as host |
| URL encoding | `http://evil%2Ecom` | Decoded after validation |
| @ trick | `http://site.com@evil.com` | Browser interprets as user@host |

## Chaining with Other Vulnerabilities

Open Redirect becomes much more dangerous when combined with other attacks already present in this application:

### Open Redirect + Stored XSS

The app already has stored XSS in notes (XSS tests 1-5). An attacker can inject:

```html
<script>window.location='http://site.com/login?next=http://evil.com/phishing'</script>
```

Any user viewing that note gets silently redirected to the phishing page. The XSS delivers the link without the victim ever clicking anything.

### Open Redirect + CSRF

The CSRF attack pages in `attacker_pages/` can incorporate the redirect link, combining forced actions with credential theft.

### Open Redirect + Session Forgery

If the attacker has the SECRET_KEY (stolen via LFI → app.py or SQL injection → source dump), they can forge a session cookie AND use open redirect to send the victim to a harvesting page for additional secrets like 2FA codes or API keys.

### Open Redirect + SSRF

The SSRF `/preview` endpoint can trigger redirects server-side, potentially reaching internal services through a chain of redirects.

### Open Redirect + Brute Force

After enumerating usernames via `brute_force.py`, the attacker crafts personalized phishing links targeting specific users.

## The Phishing Page

The file `attacker_pages/open_redirect_phishing.html` simulates the attacker's phishing page:

- Visually identical to the real DevToolkit login page
- Shows a "Session expired" warning to explain why re-login is needed
- Captures entered credentials and displays them (in a real attack, they'd be sent to the attacker's server)
- Open it directly in a browser — no extra server needed

## Example Attack Script Output

```
PHASE 2 — Test Redirect Bypass Techniques
  REDIRECT  Direct external URL      → http://evil.com/fake-login
            No tricks — just the external URL directly

PHASE 3 — Full Attack Chain Demonstration
  The Phishing Link:
  http://127.0.0.1:5000/login?next=http://127.0.0.1:8888/fake-login

  Attack flow:
  1. BAIT    → Attacker sends link (or injects via stored XSS)
  2. LOGIN   → Victim sees REAL login, enters REAL credentials
  3. REDIRECT → Server sends 302 to evil URL (invisible, <100ms)
  4. PHISHING → Fake "session expired" page captures credentials
  5. CAPTURED → Attacker has username + password
```

## Fix (Remediation)

### 1. Validate that redirect target is internal

```python
from urllib.parse import urlparse

next_url = request.args.get('next', '/')
parsed = urlparse(next_url)

# Reject anything with a scheme or netloc (= external URL)
if parsed.netloc or parsed.scheme:
    next_url = '/'

return redirect(next_url)
```

### 2. Allowlist valid redirect paths

```python
VALID_REDIRECTS = ['/', '/settings', '/notes', '/search', '/files', '/ping', '/preview']

next_url = request.args.get('next', '/')
if next_url not in VALID_REDIRECTS:
    next_url = '/'
```

### 3. Same-origin check

```python
if not next_url.startswith(request.host_url):
    next_url = url_for('welcome')
```

Note: this can still be bypassed with the `@` trick (`http://site.com@evil.com`), so combine with `urlparse` validation.

## References

- [OWASP Unvalidated Redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [PortSwigger Open Redirect](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
- [HackTricks Open Redirect Payloads](https://book.hacktricks.xyz/pentesting-web/open-redirect)
