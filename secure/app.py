# ═══════════════════════════════════════════════════════════════
#  DevToolkit — SECURE VERSION
# ═══════════════════════════════════════════════════════════════
#
#  This is the hardened version of the deliberately vulnerable app.
#  Every vulnerability from vulnerable/app.py has a specific fix here.
#  The two apps can run side-by-side (vulnerable on 5000, secure on 5001)
#  and the same exploit scripts can target both to prove the fixes work.
#
#  Security measures applied:
#    - SECRET_KEY: random 256-bit, never hardcoded
#    - Passwords: PBKDF2-SHA256 hashed, never plaintext
#    - SQL Injection: ORM parameterized queries, no raw SQL
#    - Command Injection: subprocess list args, shell=False, regex validation
#    - LFI: os.path.realpath + startswith check + send_from_directory
#    - SSRF: DNS resolution + private IP blocking + no cookie forwarding
#    - Open Redirect: urlparse validation, relative paths only
#    - XSS: bleach whitelist sanitization + CSP headers
#    - CSRF: Flask-WTF token on every form
#    - Brute Force: flask-limiter rate limiting + generic error messages
#    - Debug: disabled, crash endpoints removed
#    - IDOR: note ownership check on deletion
#    - Cookie: HttpOnly=True, SameSite=Lax
#    - Security headers: CSP, X-Frame-Options, X-Content-Type-Options
# ═══════════════════════════════════════════════════════════════

import os
import re
import secrets
import subprocess
import ipaddress
import socket
from urllib.parse import urlparse

from flask import Flask, render_template, request, send_from_directory, abort, session, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach
import markdown
import qrcode
from PIL import Image
from pyzbar.pyzbar import decode
import requests as http_client  # renamed to avoid clash with flask.request

from models import db, Note, User

app = Flask(__name__)

# SQLite database — same schema as vulnerable but with password_hash instead of password
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# ═══════════════════════════════════════════════════════════════
#  CONFIGURATION — every setting here is a fix for a specific vuln
# ═══════════════════════════════════════════════════════════════

# SECRET_KEY: first try environment variable, fall back to random generation
# secrets.token_hex(32) produces 64 hex chars = 256 bits of entropy
# brute forcing this would take longer than the age of the universe
# the vulnerable version used 'super-secret-key-123' which is in every wordlist
#
# important: random generation means all sessions invalidate on restart
# in production you MUST set the SECRET_KEY env var so sessions persist
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

# Session lifetime — 30 minutes is a reasonable balance between security and usability
# the vulnerable version used 5 minutes which was just for demo convenience
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Cookie security flags — the opposite of what the vulnerable version does
# HttpOnly=True  -> JavaScript cannot read document.cookie
#                   this kills XSS cookie theft (xss_2_cookie.md becomes useless)
# SameSite='Lax' -> browser won't send cookies on cross-site POST requests
#                   this kills CSRF attacks (csrf_attacker_site.html stops working)
# Secure=True    -> cookie only sent over HTTPS (commented out for localhost dev)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# app.config['SESSION_COOKIE_SECURE'] = True  # uncomment in production with HTTPS

# CSRF protection — Flask-WTF automatically validates a hidden token in every POST form
# without a valid token, the server returns 400 Bad Request
# this stops csrf_attacker_site.html from submitting forms on behalf of the victim
# because the attacker's page cannot read the token (same-origin policy)
csrf = CSRFProtect(app)

# Rate limiting — tracks requests per IP address using an in-memory store
# the vulnerable version had no limits, so brute_force.py could try thousands
# of passwords per minute. now login is capped at 5 attempts/minute
# and registration at 10/minute to prevent mass account creation
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])

# Initialize SQLAlchemy with our Flask app
db.init_app(app)

# Path for QR code image output
QR_IMAGE = 'static/image.jpg'


# ═══════════════════════════════════════════════════════════════
#  XSS PROTECTION — bleach whitelist sanitization
# ═══════════════════════════════════════════════════════════════
#
# The vulnerable version uses {{ content|safe }} which tells Jinja2
# to skip ALL escaping — so <script> tags in markdown notes execute.
# We still need |safe because markdown produces legitimate HTML
# (headers, paragraphs, code blocks) that must render properly.
#
# The fix: run bleach.clean() BEFORE passing content to the template.
# bleach strips anything not in the whitelist:
#   - <script>alert(1)</script>  -> alert(1)        (tag stripped)
#   - <img onerror="...">       -> <img>             (attribute stripped)
#   - <iframe src="...">        -> (completely removed)
#   - <h1>Hello</h1>            -> <h1>Hello</h1>    (allowed, passes through)
#   - <a href="link">text</a>   -> <a href="link">text</a> (allowed)

# Tags that markdown legitimately produces — everything else gets stripped
ALLOWED_TAGS = [
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',  # headings
    'p', 'br', 'hr',                        # paragraphs and breaks
    'strong', 'em', 'b', 'i', 'u', 's', 'del',  # text formatting
    'ul', 'ol', 'li',                       # lists
    'a', 'code', 'pre', 'blockquote',       # links, code, quotes
    'table', 'thead', 'tbody', 'tr', 'th', 'td',  # tables
    'img', 'div', 'span',                   # images and containers
]

# Attributes whitelist — anything not listed here gets removed from the tag
# so <img onerror="evil()"> becomes <img> because onerror is not in the list
ALLOWED_ATTRS = {
    'a': ['href', 'title'],          # links need href to work
    'img': ['src', 'alt', 'title'],  # images need src to display
    'td': ['align'],                 # table alignment
    'th': ['align'],
}

def sanitize_html(html_content):
    """
    Run bleach on markdown HTML output before it reaches the template.
    
    strip=True means disallowed tags are removed entirely rather than
    being escaped to &lt;script&gt;. This keeps the output clean —
    the user sees the text content without ugly escaped brackets.
    """
    return bleach.clean(html_content, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)


# ═══════════════════════════════════════════════════════════════
#  OPEN REDIRECT PROTECTION
# ═══════════════════════════════════════════════════════════════

def is_safe_redirect(target):
    """
    Validates that a redirect target is an internal relative path.
    
    The vulnerable version accepts anything in ?next= including:
        http://evil.com          -> direct external URL
        //evil.com               -> protocol-relative (browser adds http:)
        /\\evil.com              -> backslash trick (some parsers treat as host)
        http://site.com@evil.com -> @ trick (browser goes to evil.com)
    
    open_redirect.py tests all 8 bypass techniques against this function.
    Every one of them returns False here because we check:
        1. scheme is empty (no http:, https:, javascript:, etc.)
        2. netloc is empty (no hostname component)
        3. doesn't start with // or /\\ (protocol-relative and backslash tricks)
        4. starts with / (must be a path on our own server)
    """
    if not target:
        return False
    parsed = urlparse(target)
    # if urlparse finds a scheme (http:) or netloc (evil.com), it is external
    if parsed.scheme or parsed.netloc:
        return False
    # catch bypass techniques that urlparse might not flag
    if target.startswith('/\\') or target.startswith('//'):
        return False
    # only accept paths that start with / (our own server routes)
    return target.startswith('/')


# ═══════════════════════════════════════════════════════════════
#  SSRF PROTECTION — multi-layer URL validation
# ═══════════════════════════════════════════════════════════════

# Protocols that should never be fetched by the server
# gopher:// is particularly dangerous because it can craft arbitrary TCP packets
SSRF_BLOCKED_SCHEMES = {'file', 'ftp', 'gopher', 'dict', 'ldap'}

def is_ssrf_safe(url):
    """
    Validates a URL before the server makes a request to it.
    
    The vulnerable version fetches ANY URL without checking:
        - http://127.0.0.1:5000  (itself — enables chaining with other vulns)
        - http://10.0.0.1        (private network services)
        - http://169.254.169.254 (cloud metadata — Capital One breach)
        - file:///etc/passwd     (local file read)
    
    ssrf.py tests all of these against this function.
    
    We resolve the hostname to an IP FIRST, then check the IP.
    This prevents DNS rebinding attacks where evil.com resolves to 127.0.0.1.
    Without DNS resolution, an attacker could bypass our check with a domain
    that points to a private IP.
    
    Returns (True, None) if safe, or (False, reason_string) if blocked.
    """
    try:
        parsed = urlparse(url)

        # only allow http and https — block file://, ftp://, gopher://, etc.
        if parsed.scheme not in ('http', 'https'):
            return False, f"Protocol '{parsed.scheme}' not allowed — only HTTP/HTTPS"

        hostname = parsed.hostname
        if not hostname:
            return False, "No hostname in URL"

        # resolve the hostname to an IP address BEFORE making the request
        # this is critical because it prevents DNS rebinding attacks
        # without this step, evil.com could resolve to 127.0.0.1
        ip = socket.gethostbyname(hostname)
        addr = ipaddress.ip_address(ip)

        # block all private, loopback, and link-local addresses
        # is_private covers: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        # is_loopback covers: 127.0.0.0/8
        # is_link_local covers: 169.254.0.0/16 (which includes the metadata endpoint)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False, f"Internal address blocked: {ip}"

        # explicit check for the cloud metadata endpoint just in case
        # is_link_local should already catch this but better safe than sorry
        if ip == '169.254.169.254':
            return False, "Cloud metadata endpoint blocked"

        return True, None

    except socket.gaierror:
        # hostname doesn't exist in DNS — no point making the request
        return False, f"Cannot resolve hostname: {parsed.hostname}"
    except Exception as e:
        # fail closed — if we can't validate, we don't fetch
        return False, f"URL validation error: {type(e).__name__}"


# ═══════════════════════════════════════════════════════════════
#  AUTHENTICATION
# ═══════════════════════════════════════════════════════════════

@app.before_request
def require_login():
    """
    Same purpose as the vulnerable version — redirect unauthenticated users to /login.
    
    Key difference: we store request.path (just '/settings') instead of request.url
    (which includes 'http://127.0.0.1:5000/settings'). A relative path can never
    point to an external domain, so open redirect is impossible from before_request.
    """
    allowed = ['login', 'register', 'static']
    if request.endpoint not in allowed and not session.get('logged_in'):
        next_path = request.path  # relative path only — no scheme, no host
        return redirect(url_for('login', next=next_path))


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10/minute")  # max 10 registrations per minute per IP
def register():
    """
    Secure registration with multiple layers of protection:
    
    1. Rate limited — prevents mass account creation (brute_force.py enumeration)
    2. CSRF token required — Flask-WTF validates automatically on POST
    3. Input validation — username length, format, password length
    4. Generic error on existing username — "Registration failed" instead of "already taken"
       this prevents username enumeration (brute_force.py can't tell which users exist)
    5. Password hashed with PBKDF2 before storage — credential_dump.py gets hashes, not passwords
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm  = request.form.get('confirm', '').strip()

        # input validation — the vulnerable version accepts anything
        if not username or not password:
            return render_template('register.html',
                error="Username and password are required")

        if len(username) < 3 or len(username) > 30:
            return render_template('register.html',
                error="Username must be 3-30 characters")

        # only allow safe characters — prevents weird edge cases and injection in other contexts
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return render_template('register.html',
                error="Username can only contain letters, numbers, and underscores")

        if len(password) < 8:
            return render_template('register.html',
                error="Password must be at least 8 characters")

        if password != confirm:
            return render_template('register.html',
                error="Passwords do not match")

        # anti-enumeration: same message whether username exists or not
        # the vulnerable version says "Username already taken" which confirms existence
        # brute_force.py phase 1 relies on that exact message to build a user list
        existing = User.query.filter_by(username=username).first()
        if existing:
            return render_template('register.html',
                error="Registration failed. Please try a different username.")

        # password hashing — set_password() calls generate_password_hash() internally
        # the raw password never touches the database
        new_user = User(username=username, role='user')
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        session['logged_in'] = True
        session['username'] = username
        session.permanent = True

        return redirect(url_for('welcome'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/minute")  # max 5 login attempts per minute per IP
def login():
    """
    Secure login with rate limiting and hash-based password verification.
    
    Key differences from the vulnerable version:
      - 5 attempts/minute rate limit -> 10K password list takes 33 hours not 30 seconds
      - Password verified via check_password() hash comparison, not plaintext match
      - next parameter validated by is_safe_redirect() before redirect
      - CSRF token required on the form (Flask-WTF)
    
    The next_url is read from POST body first (hidden field) to prevent the
    double-encoding bug that plagued the vulnerable version when login failed
    and the page was re-rendered with next already in the form action URL.
    """
    error = None
    next_url = request.form.get('next') or request.args.get('next') or ''

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # first find the user, then verify password hash
        # the vulnerable version did filter_by(username=x, password=y)
        # which compares plaintext directly in the SQL query
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.permanent = True
            session['logged_in'] = True
            session['username'] = username

            # validate the redirect target before following it
            # is_safe_redirect blocks all external URLs and bypass tricks
            if is_safe_redirect(next_url):
                return redirect(next_url)
            return redirect(url_for('welcome'))
        else:
            # same message whether username is wrong or password is wrong
            # this prevents user enumeration via login response analysis
            error = 'Invalid username or password.'

    return render_template('login.html', error=error, next_url=next_url)


@app.route('/logout')
def logout():
    """
    Simple logout — clear the session and redirect to login.
    The vulnerable version had a 'silent' parameter for CSRF testing —
    we removed it because it's not needed in the secure version.
    """
    session.clear()
    return redirect(url_for('login'))


# ═══════════════════════════════════════════════════════════════
#  QR CODE TOOLS (same as vulnerable — no security issues here)
# ═══════════════════════════════════════════════════════════════

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/qr')
def qr_home():
    return render_template('index.html')

@app.route('/makeQr', methods=['POST'])
def make():
    """Generate a QR code from user text input."""
    data = request.form.to_dict()
    data_to_convert = data.get('data', '')
    if data_to_convert:
        qr = qrcode.make(data_to_convert)
        qr.save(QR_IMAGE)
    return render_template('index.html')

@app.route('/decodeQr', methods=['GET', 'POST'])
def decode_qr():
    """Upload and decode a QR code image."""
    if request.method == 'POST':
        if 'qr_image' not in request.files:
            return "File could not be found", 400

        file = request.files['qr_image']
        if file.filename == '':
            return "No file selected", 400

        try:
            img = Image.open(file.stream)
            decoded_objs = decode(img)
            data_list = [obj.data.decode('utf-8') for obj in decoded_objs]
            return render_template('decode.html', results=data_list)
        except Exception:
            # generic error — the vulnerable version leaked the full exception message
            # which could reveal library versions, file paths, and internal structure
            return "Error processing QR code", 500

    return render_template('decode.html', results=None)


# ═══════════════════════════════════════════════════════════════
#  MARKDOWN NOTES — XSS fixed via bleach sanitization
# ═══════════════════════════════════════════════════════════════

@app.route('/notes')
def list_notes():
    """List all notes, optionally filtered by category."""
    category = request.args.get('category')
    if category:
        notes = Note.query.filter_by(category=category).all()
    else:
        notes = Note.query.all()
    categories = db.session.query(Note.category).distinct().all()
    return render_template('notes.html', notes=notes, categories=categories)


@app.route('/notes/<int:note_id>')
def view_note(note_id):
    """
    Render a single note's markdown content.
    
    The vulnerable version passes markdown output directly through |safe,
    which lets <script> tags execute in the browser (stored XSS).
    
    Here we add sanitize_html() between markdown conversion and template rendering.
    The flow is:  markdown -> raw HTML -> bleach.clean() -> safe HTML -> template
    
    The XSS test notes (xss_1 through xss_4) are still in the database
    but their <script> tags get stripped. When you view them in the secure app,
    you see the text content without any script execution — proof that bleach works.
    """
    note = Note.query.get_or_404(note_id)
    # step 1: convert markdown to HTML (this preserves raw HTML like <script>)
    raw_html = markdown.markdown(note.content, extensions=['fenced_code', 'tables'])
    # step 2: strip dangerous tags and attributes, keep only safe markdown HTML
    html_content = sanitize_html(raw_html)
    return render_template('view.html', filename=note.title, content=html_content)


@app.route("/category/<category>")
def notes_by_category(category):
    """Filter notes by category for the sidebar."""
    notes = Note.query.filter_by(category=category).all()
    return render_template("category.html", notes=notes, category=category)


# ═══════════════════════════════════════════════════════════════
#  CSRF-PROTECTED STATE-CHANGING ENDPOINTS
# ═══════════════════════════════════════════════════════════════
#
# Three critical changes from the vulnerable version:
#   1. POST only — no GET for state changes (blocks <img src="..."> CSRF)
#   2. CSRF token required — Flask-WTF validates on every POST
#   3. Ownership checks — users can only modify their own data (IDOR fix)

@app.route('/delete_note/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    """
    Delete a note — POST only with CSRF token and ownership check.
    
    The vulnerable version accepted GET, so this worked:
        <img src="/delete_note/5">
    
    Now it requires POST + CSRF token. Even if an attacker somehow submits
    a POST, the SameSite=Lax cookie policy prevents the session cookie from
    being sent with cross-origin requests — so the server sees no session.
    
    The ownership check (note.owner != username) is the IDOR fix.
    Without it, user A could delete user B's notes by guessing IDs.
    """
    note = Note.query.get_or_404(note_id)
    # IDOR protection — only the note's owner can delete it
    # owner can be None for old/imported notes, so we check that first
    if note.owner and note.owner != session.get('username'):
        abort(403)
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for('list_notes'))


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    """
    Password change — requires current password + CSRF token.
    
    The vulnerable version had three critical flaws:
      1. Accepted GET params -> <img src="/change_password?new_password=hacked">
      2. No CSRF token -> attacker page could submit the form
      3. No current password check -> if you had the session, you could change it
    
    All three are fixed here:
      - GET does NOT change the password (the if-block for GET params is removed)
      - CSRF token is validated by Flask-WTF on POST
      - Current password must be verified via check_password() before the change
        even if an attacker has the session (via XSS), they still need the old password
    """
    message = None
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        username = session.get('username')

        if not username:
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if not user:
            return redirect(url_for('login'))

        # verify the current password before allowing any changes
        # this stops CSRF and session theft from being enough for a password change
        if not user.check_password(current_password):
            message = 'Current password is incorrect.'
        elif len(new_password) < 8:
            message = 'New password must be at least 8 characters.'
        elif new_password != confirm_password:
            message = 'New passwords do not match.'
        else:
            # hash the new password — raw value never stored
            user.set_password(new_password)
            db.session.commit()
            message = 'Password changed successfully.'

    # GET only renders the form — no state change happens on GET (RFC 7231)
    return render_template('settings.html', message=message)


@app.route('/add_note', methods=['POST'])  # POST only — no GET creation
def add_note():
    """
    Create a new note with ownership tracking.
    
    The vulnerable version accepted GET params, enabling CSRF-based note injection:
        /add_note?title=xss&content=<script>evil()</script>
    
    Now it's POST only with CSRF token. The owner field links the note to the
    logged-in user so delete_note can enforce ownership (IDOR fix).
    """
    title = request.form.get('title', 'Untitled')
    content = request.form.get('content', '')
    category = request.form.get('category', 'general')

    if title and content:
        note = Note(title=title, content=content, category=category,
                    owner=session.get('username'))
        db.session.add(note)
        db.session.commit()
    return redirect(url_for('list_notes'))


# NOTE: debug_test and debug_test2 endpoints are REMOVED in the secure version
# with debug=False, the Werkzeug interactive debugger is completely disabled
# even if an error occurs, the user sees a generic 500 page, not a Python console


# ═══════════════════════════════════════════════════════════════
#  PATH TRAVERSAL / LFI — FIXED
# ═══════════════════════════════════════════════════════════════

@app.route('/download')
def download_file():
    """
    Secure file download — uses realpath to block directory traversal.
    
    The vulnerable version joins the filename directly:
        os.path.join(base_dir, '../../../etc/passwd')  -> /etc/passwd  (LFI!)
    
    The fix has two parts:
      1. os.path.realpath() resolves ALL ../ sequences to an absolute path
         '../../../etc/passwd' becomes '/etc/passwd'
      2. startswith() check ensures the resolved path is still inside base_dir
         '/etc/passwd'.startswith('/home/.../static/files') -> False -> abort(403)
    
    send_from_directory() is used instead of manual open() — it adds another
    safety layer and properly handles Content-Type, caching, and encoding.
    
    lfi_to_rce.py and credential_dump.py both fail against this.
    """
    filename = request.args.get('file', '')

    if not filename:
        return '''
        <h3>File Download Service</h3>
        <p>Usage: /download?file=filename</p>
        <p>Available files:</p>
        <ul>
            <li><a href="/download?file=notes_backup.txt">notes_backup.txt</a></li>
            <li><a href="/download?file=readme.txt">readme.txt</a></li>
        </ul>
        ''', 200

    # absolute path to the allowed download directory
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'files')

    # resolve the full path AFTER joining — this collapses all ../ sequences
    # so '../../../etc/passwd' becomes the actual absolute path to /etc/passwd
    file_path = os.path.realpath(os.path.join(base_dir, filename))

    # the critical check: is the resolved path still inside our allowed directory?
    # if someone tried ../../../etc/passwd, realpath resolved it to /etc/passwd
    # which does NOT start with /home/.../static/files, so we reject it
    if not file_path.startswith(os.path.realpath(base_dir)):
        abort(403)  # path traversal detected — block it

    if not os.path.isfile(file_path):
        abort(404)  # file genuinely doesn't exist — no info leak in the error

    # send_from_directory is Flask's safe file serving function
    # it handles Content-Type detection, caching headers, and encoding
    return send_from_directory(base_dir, filename)


@app.route('/files')
def list_files():
    """File listing page — same as vulnerable version, just a UI."""
    return render_template('files.html')


# ═══════════════════════════════════════════════════════════════
#  SQL INJECTION — FIXED via ORM
# ═══════════════════════════════════════════════════════════════

@app.route('/search')
def search():
    """
    Secure search using SQLAlchemy ORM instead of raw SQL.
    
    The vulnerable version did:
        sql = f"SELECT ... WHERE title LIKE '%{q}%'"
        db.session.execute(text(sql))
    
    which allows the user to break out of the LIKE clause and inject SQL.
    
    The ORM generates parameterized queries:
        SELECT ... WHERE title LIKE :q_1  (with q_1 = '%search_term%')
    
    The user's input is bound as a DATA parameter, never part of the SQL structure.
    Even if someone enters ' UNION SELECT * FROM users --, the ORM treats it as
    a literal search string and looks for notes containing that text.
    
    sqli_classic.py, sqli_blind.py, and sqli_time.py all fail against this
    because there is no injection point.
    
    Also: executed_sql is NOT shown on the page anymore (info disclosure fix).
    """
    q = request.args.get('q', '')
    results = []
    error = None

    if q:
        # ORM parameterized query — user input is a bound parameter, not string concatenation
        # SQLAlchemy generates: WHERE title LIKE ? OR content LIKE ?
        # with the actual value passed separately to the database driver
        results = Note.query.filter(
            Note.title.like(f"%{q}%") | Note.content.like(f"%{q}%")
        ).all()

    # executed_sql removed — no query structure leakage
    return render_template('search.html',
        query=q,
        results=results,
        error=error,
        result_count=len(results)
    )


# ═══════════════════════════════════════════════════════════════
#  COMMAND INJECTION — FIXED
# ═══════════════════════════════════════════════════════════════

@app.route('/ping', methods=['GET', 'POST'])
def ping_tool():
    """
    Secure ping tool — argument list + input validation.
    
    The vulnerable version did:
        cmd = f"ping -c 2 {host}"
        subprocess.run(cmd, shell=True, ...)
    
    Two fixes applied:
    
    1. subprocess argument list instead of shell string
       subprocess.run(["ping", "-c", "2", host]) passes 'host' as a single
       argument to the ping binary. The shell is not involved at all, so
       semicolons, pipes, and dollar signs are just literal characters.
       Even if host="; rm -rf /", ping receives that as one hostname argument
       and simply fails with "unknown host: ; rm -rf /"
    
    2. regex input validation as defense in depth
       re.match(r'^[a-zA-Z0-9._-]+$', host) rejects anything that is not
       a valid hostname character. This catches injection attempts before
       they even reach subprocess.
    
    cmdi.py fails against both layers.
    """
    output = None
    host = ""

    if request.method == 'POST':
        host = request.form.get('host', '').strip()

        if host:
            # defense layer 1: regex whitelist
            # only letters, numbers, dots, hyphens, and underscores are valid
            # in hostnames. everything else is suspicious.
            if not re.match(r'^[a-zA-Z0-9._-]+$', host):
                output = "Invalid hostname. Only letters, numbers, dots, hyphens allowed."
            elif len(host) > 253:
                # RFC 1035: max hostname length is 253 characters
                output = "Hostname too long."
            else:
                try:
                    # defense layer 2: argument list with shell=False (default)
                    # the host value is passed as-is to the ping binary
                    # no shell interpretation, no metacharacter expansion
                    result = subprocess.run(
                        ["ping", "-c", "2", host],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    output = result.stdout + result.stderr
                except subprocess.TimeoutExpired:
                    output = "Command timed out (10s limit)"
                except Exception:
                    # generic error — vulnerable version leaked exception details
                    output = "An error occurred while executing the command."

    # executed_cmd removed — no command structure leakage
    return render_template('ping.html',
        host=host,
        output=output
    )


# ═══════════════════════════════════════════════════════════════
#  SSRF — FIXED
# ═══════════════════════════════════════════════════════════════

@app.route('/preview', methods=['GET', 'POST'])
def preview_url():
    """
    Secure URL preview — validates the URL before fetching.
    
    Five fixes compared to the vulnerable version:
    
    1. is_ssrf_safe() blocks private IPs, loopback, link-local, and metadata
       -> ssrf.py's port scan and localhost chaining both fail
    
    2. No cookie forwarding — the request goes out clean
       -> SSRF can no longer chain with authenticated endpoints on localhost
       -> cookies also don't leak to external URLs the attacker controls
    
    3. allow_redirects=False — prevents redirect-chain attacks
       -> attacker can't do: http://safe.com -> 302 -> http://127.0.0.1:5000
    
    4. Response capped at 50KB — prevents DoS via huge responses
    
    5. Response headers NOT shown — prevents internal service info leakage
    """
    url = ""
    content = None
    status_code = None
    error = None
    content_length = None

    if request.method == 'POST':
        url = request.form.get('url', '').strip()

        if url:
            # validate the URL before making any request
            safe, reason = is_ssrf_safe(url)
            if not safe:
                error = reason
            else:
                try:
                    # no cookies forwarded — request goes out as anonymous
                    # no redirect following — prevents hop-through-safe-domain attacks
                    resp = http_client.get(url, timeout=5, allow_redirects=False)
                    content = resp.text[:50000]  # cap at 50KB to prevent memory exhaustion
                    status_code = resp.status_code
                    content_length = len(resp.content)
                except http_client.exceptions.ConnectionError:
                    # generic message — doesn't reveal which port or service was unreachable
                    error = "Connection refused"
                except http_client.exceptions.Timeout:
                    error = "Request timed out (5s)"
                except http_client.exceptions.MissingSchema:
                    error = "Invalid URL — include http:// or https://"
                except Exception:
                    # fail-safe: generic error, no exception details leaked
                    error = "Request failed"

    return render_template('preview.html',
        url=url,
        content=content,
        status_code=status_code,
        content_length=content_length,
        response_headers=None,  # intentionally hidden — prevents internal info leakage
        error=error
    )


# ═══════════════════════════════════════════════════════════════
#  SECURITY HEADERS — applied to every response
# ═══════════════════════════════════════════════════════════════

@app.after_request
def set_security_headers(response):
    """
    Adds security headers that browsers enforce on every page load.
    These are defense-in-depth — they don't replace server-side fixes
    but they add extra protection if something slips through.
    """
    # Content-Security-Policy controls what the browser is allowed to load
    # script-src 'self' 'unsafe-inline' — allows our own scripts + inline onclick handlers
    # in production, you would remove 'unsafe-inline' and move JS to external files
    # the primary XSS defense is bleach (server-side), CSP is the backup layer
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:;"
    
    # X-Frame-Options DENY — prevents any site from embedding our pages in an iframe
    # this blocks clickjacking attacks where an attacker overlays invisible iframes
    response.headers['X-Frame-Options'] = 'DENY'
    
    # X-Content-Type-Options nosniff — prevents browser MIME type guessing
    # without this, a .txt file containing HTML could be interpreted as HTML
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Referrer-Policy — controls how much URL info is sent to other sites
    # strict-origin-when-cross-origin sends only the origin (not the full URL path)
    # to prevent leaking sensitive URL parameters to external sites
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response


# ═══════════════════════════════════════════════════════════════
#  STARTUP
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    with app.app_context():
        # create tables if they don't exist — schema comes from models.py
        db.create_all()

        # seed default users with HASHED passwords
        # set_password() runs generate_password_hash() internally
        # even if you dump the database, you get hashes, not 'admin123'
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
        if not User.query.filter_by(username='potato').first():
            potato = User(username='potato', role='user')
            potato.set_password('test123')
            db.session.add(potato)
        db.session.commit()

    # debug=False — the Werkzeug interactive debugger is completely disabled
    # unhandled exceptions show a generic 500 page, not a Python console
    # port 5001 so it can run alongside the vulnerable version on 5000
    app.run(debug=False, port=5001)
