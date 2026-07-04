# Username Enumeration + Brute Force — Credential Theft Chain

This attack chains two weaknesses that seem minor on their own. The registration page leaks which usernames exist. The login page allows unlimited password guesses. Together, they give an attacker valid credentials without any insider knowledge.

---

## Phase 1 — Username Enumeration

The `/register` endpoint responds differently depending on whether a username is taken:

```
POST /register  username=admin
→ "Username already taken"      ← user EXISTS

POST /register  username=nobody
→ 302 redirect to /             ← user did NOT exist (now created)
```

An attacker submits a wordlist of common usernames — admin, root, test, user, moderator, guest — and checks the response. Every "already taken" response confirms a valid account.

The `/login` endpoint handles this correctly: it says "Invalid username or password" regardless of whether the username exists or the password is wrong. This is the standard practice. But `/register` undoes that protection by explicitly confirming which usernames are registered.

The side effect of enumeration is worth noting: every username that does NOT exist gets registered during the scan. The attacker creates throwaway accounts as a byproduct. This is also a weakness — there is no email verification, no CAPTCHA, nothing preventing mass account creation.

---

## Phase 2 — Password Brute Force

Once the attacker has a list of valid usernames, they attack `/login` with a password wordlist. The application has none of the standard protections:

No rate limiting. The server processes every request at full speed. A typical Flask development server handles 50-200 requests per second. At that rate, a 10,000-word password list is exhausted in under a minute.

No account lockout. The attacker can try 1,000 passwords against the same account without consequence. There is no counter tracking failed attempts, no temporary lock, no escalating delay.

No CAPTCHA. Every request is a simple POST with two fields. Fully automatable with a five-line Python script.

Weak passwords in the system. The application stores `admin:admin123` and `potato:test456`. Both are common patterns that appear in standard wordlists. `admin123` is typically in the top 50 of any password list.

The combination means the attack is fast, silent, and effective. The server logs show hundreds of POST /login requests but nothing alerts anyone or slows the attacker down.

---

## Why the Chain Matters

Without enumeration, the attacker would need to guess both the username and the password simultaneously. That is a much larger search space. If there are 20 possible usernames and 10,000 possible passwords, trying every combination is 200,000 attempts.

With enumeration, the attacker first confirms which 2-3 usernames exist, then runs 10,000 passwords against each. That is 20,000-30,000 attempts — an order of magnitude fewer. And the enumeration phase itself takes only seconds.

---

## Connection to Other Attacks

Credentials obtained through brute force feed directly into other attack chains in this application:

**Brute Force → LFI → RCE.** The attacker cracks a password, logs in, and uses the `/download` path traversal to read system files. From there, they calculate the Werkzeug debug PIN and achieve remote code execution.

**Brute Force → LFI → Session Forgery.** After logging in, the attacker reads `app.py` via LFI, extracts the SECRET_KEY, and forges session cookies for any user — including ones whose passwords they did not crack.

**Username Enumeration → Phishing.** Knowing which usernames exist makes social engineering more convincing. An email saying "your account 'admin' has been flagged" is more believable when the attacker knows that account actually exists.

---

## How to Prevent This

**Registration error messages.** Never confirm whether a username exists. Use a generic message: "If this username is available, your account has been created." Or better: require email verification, so the response is always "Check your email for confirmation" regardless of whether the username is taken.

**Rate limiting.** Flask-Limiter can restrict login attempts per IP:

```python
from flask_limiter import Limiter
limiter = Limiter(app, default_limits=["200/day"])

@app.route('/login', methods=['POST'])
@limiter.limit("5/minute")
def login():
    ...
```

Five attempts per minute means a 10,000-word list takes 33 hours instead of 30 seconds.

**Account lockout.** After 5 failed attempts, lock the account for 15 minutes. This makes brute force impractical even without rate limiting.

**Strong password requirements.** Enforce minimum length (12+ characters), check against breached password databases (haveibeenpwned API), and reject common patterns like `username123`.

**Multi-factor authentication.** Even if the password is cracked, the attacker needs a second factor (TOTP, SMS, hardware key) to log in.

---

## Automated Attack Script

```bash
python3 scripts/brute_force.py
python3 scripts/brute_force.py --target http://127.0.0.1:5000
```

The script runs both phases automatically: enumerates usernames via `/register`, then brute forces passwords via `/login` for every confirmed user.
