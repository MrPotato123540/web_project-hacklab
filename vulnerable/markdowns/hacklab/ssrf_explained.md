# SSRF — Server-Side Request Forgery

## Overview

Server-Side Request Forgery (SSRF) is an attack where the attacker tricks the server into making HTTP requests on their behalf. Unlike other attacks where the attacker directly interacts with the target, SSRF turns the server itself into a proxy — reaching internal services, bypassing firewalls, and chaining with other vulnerabilities.

SSRF was added to the OWASP Top 10 in 2021 as its own category (A10), reflecting its growing importance in cloud-native environments where metadata services and internal APIs are prime targets.

## Vulnerable Code

```python
@app.route('/preview', methods=['GET', 'POST'])
def preview_url():
    url = request.form.get('url', '')
    
    # VULNERABLE: fetches any URL the user provides
    resp = http_client.get(url, timeout=5)
    
    return render_template('preview.html', content=resp.text)
```

The problem: the server fetches whatever URL the user provides with no validation — including `localhost`, private IP ranges, and cloud metadata endpoints.

## Attack Scenarios

### 1. Internal Service Access

```
URL: http://127.0.0.1:5000/
```

The server fetches its own welcome page. While this seems harmless, it demonstrates that the server will make requests to internal addresses. In a production environment, this could reach admin panels, monitoring dashboards, or internal APIs that are not exposed to the internet.

### 2. SSRF → LFI Chain

```
URL: http://127.0.0.1:5000/download?file=../../etc/passwd
```

The attacker doesn't need to access the `/download` endpoint directly. Instead, they make the server access it through the preview feature. Even if `/download` were restricted by IP allowlist or firewall rules, the request comes from `127.0.0.1` — the server itself — so it passes all internal checks.

```
URL: http://127.0.0.1:5000/download?file=../../app.py
```

This chains SSRF with LFI to read the application source code, revealing `SECRET_KEY`, database credentials, and other secrets.

### 3. SSRF → SQL Injection Chain

```
URL: http://127.0.0.1:5000/search?q=' UNION SELECT 0,username,password,role,0 FROM users --
```

The server exploits its own SQL injection vulnerability through the SSRF proxy. The search results (containing dumped credentials) are returned in the preview response. The attacker performed a full SQL injection attack without ever touching the `/search` endpoint directly.

### 4. Internal Port Scanning

```
URL: http://127.0.0.1:22/      → Connection refused (SSH not running)
URL: http://127.0.0.1:3306/    → Connection refused (no MySQL)
URL: http://127.0.0.1:5000/    → 200 OK (Flask app found!)
URL: http://127.0.0.1:6379/    → Connection refused (no Redis)
```

The attacker uses the server as a port scanner. By observing which requests return "Connection refused" vs actual responses, they map out all internal services. This is invisible to external network monitoring because all traffic stays on the server.

### 5. Cloud Metadata Theft

```
URL: http://169.254.169.254/latest/meta-data/
URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

In cloud environments (AWS, GCP, Azure), a special IP address (`169.254.169.254`) provides instance metadata including temporary security credentials. SSRF can steal these credentials, giving the attacker access to the entire cloud account.

The 2019 Capital One data breach, which exposed 100 million customer records, was caused by exactly this attack — an SSRF vulnerability allowed the attacker to steal AWS IAM credentials from the metadata service.

## Why SSRF is Different

| Attack | Who makes the request | What they can reach |
|--------|----------------------|-------------------|
| XSS | Victim's browser | Whatever the victim can access |
| CSRF | Victim's browser | Whatever the victim is authorized for |
| SSRF | **The server** | Internal network, localhost, cloud metadata |
| LFI | The server (file read) | Local files only |
| Cmd Injection | The server (OS) | Everything on the machine |

SSRF is unique because the server is typically in a privileged network position — behind firewalls, in a VPC, with access to internal services and cloud metadata that are completely invisible from the outside.

## Fix (Remediation)

### 1. URL Allowlist

```python
import urllib.parse

ALLOWED_DOMAINS = ["example.com", "api.github.com", "cdn.example.com"]

parsed = urllib.parse.urlparse(url)
if parsed.hostname not in ALLOWED_DOMAINS:
    return "Domain not allowed", 403
```

Only allow requests to known, trusted domains.

### 2. Block Internal IPs

```python
import ipaddress
import socket

parsed = urllib.parse.urlparse(url)
ip = socket.gethostbyname(parsed.hostname)

if ipaddress.ip_address(ip).is_private:
    return "Internal addresses not allowed", 403

# Also block the metadata IP
if ip == "169.254.169.254":
    return "Metadata endpoint blocked", 403
```

Resolve the hostname to an IP and check if it's a private/internal address.

### 3. Protocol Restriction

```python
if parsed.scheme not in ("http", "https"):
    return "Only HTTP and HTTPS allowed", 403
```

Block `file://`, `ftp://`, `gopher://`, and other dangerous protocols.

### 4. Network-Level Protection

Use a dedicated outbound proxy that enforces network policies, or run the URL fetcher in an isolated network segment with no access to internal services.

On AWS, enable IMDSv2 (Instance Metadata Service v2) which requires a special token header — this prevents simple SSRF from accessing metadata.

## References

- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PortSwigger SSRF Labs](https://portswigger.net/web-security/ssrf)
- [Capital One Breach Analysis](https://blog.cloudsploit.com/the-capital-one-breach-how-a-firewall-misconfiguration-led-to-a-massive-data-leak)
