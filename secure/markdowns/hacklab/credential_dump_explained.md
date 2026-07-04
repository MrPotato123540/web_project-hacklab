# LFI → Database Theft → Plaintext Credential Dump

This attack demonstrates why storing passwords in plaintext is catastrophic, and how a single file-read vulnerability can compromise every account on the platform simultaneously.

---

## The Vulnerability Chain

Two weaknesses combine here. The first is the path traversal in `/download`, which allows reading arbitrary files from the server. The second is that the `users` table stores passwords as plain, readable text — no hashing, no encryption, nothing.

Either weakness alone is serious. Together they are devastating.

---

## How the Attack Works

The attacker registers a throwaway account on the site. Using that authenticated session, they exploit the `/download` endpoint to retrieve the SQLite database file:

```
GET /download?file=../../instance/notes.db
```

The server reads the file from disk and sends it back. The database contains the `users` table with every account's username and password in cleartext. The attacker opens it locally:

```bash
sqlite3 stolen_database.db "SELECT username, password, role FROM users;"
```

Output:

```
admin|admin123|admin
potato|test456|user
john|mypassword|user
```

Every credential. Every account. Instantly readable.

---

## Why Plaintext Storage is Catastrophic

When passwords are stored in plaintext, a single database breach exposes every user immediately. There is no delay, no cracking step, no computational barrier. The attacker reads the passwords as easily as reading a text file.

But the damage extends far beyond this one application. Studies consistently show that over 60% of people reuse passwords across multiple services. The password `admin123` on this site might also be the password to someone's email, cloud storage, or banking portal. A plaintext breach on one site cascades into breaches across the internet.

Even after the vulnerability is patched and the server is secured, the stolen passwords remain valid everywhere else they were reused. Every affected user must change their password on every service where they used the same one — and most will never know they need to.

---

## What Hashing Would Have Done

If passwords were hashed with bcrypt, the database would contain entries like:

```
admin|$2b$12$LJ3m4ys5Lz0ecGn/sKFUguKxJj8bR5VN1qG2d...|admin
```

This hash cannot be reversed to recover `admin123`. An attacker with the database would need to try billions of guesses, hashing each one and comparing. For a strong password, this takes years. For a weak password like `admin123`, it might take hours — but that is still infinitely better than the zero seconds it takes to read plaintext.

The key difference: hashing converts a total breach into a partial one. Weak passwords may still fall to dictionary attacks, but strong passwords survive. With plaintext, every password falls instantly regardless of strength.

---

## The Fix

```python
from werkzeug.security import generate_password_hash, check_password_hash

# Registration — hash before storing
user.password = generate_password_hash(password)

# Login — verify against hash
if check_password_hash(user.password, input_password):
    # grant access
```

Werkzeug's `generate_password_hash` uses PBKDF2 by default with a random salt. Each password gets a unique salt, so even two users with the same password will have different hashes. Rainbow table attacks become useless.

For even stronger protection, use bcrypt or argon2 — these are memory-hard functions designed specifically to resist GPU-accelerated cracking.

---

## Automated Attack Script

```bash
python3 scripts/credential_dump.py
```

The script registers an account, downloads the database via LFI, dumps the users table, and verifies each stolen credential by logging in.
