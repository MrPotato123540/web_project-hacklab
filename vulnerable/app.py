# ═══════════════════════════════════════════════════════════════
#  DevToolkit — Deliberately Vulnerable Web Application
# ═══════════════════════════════════════════════════════════════
#
#  This is the VULNERABLE version. Every major OWASP vulnerability
#  class has at least one instance in this file:
#
#    - SQL Injection (classic, blind, time-based)  — /search
#    - OS Command Injection                        — /ping
#    - Path Traversal / LFI                        — /download
#    - SSRF                                        — /preview
#    - Stored XSS                                  — /notes/<id>  (|safe in template)
#    - Open Redirect                               — /login?next=
#    - Session Forgery                             — hardcoded SECRET_KEY
#    - CSRF                                        — GET password change, no tokens
#    - Credential Dump                             — plaintext passwords in DB
#    - Werkzeug Debug RCE                          — debug=True + /debug_test
#
#  The matching exploit scripts live in scripts/ and the theory
#  behind each attack is documented in markdowns/hacklab/.
#
#  DO NOT deploy this on any network you don't fully control.
# ═══════════════════════════════════════════════════════════════

from flask import Flask, render_template, request, send_from_directory, abort, session, redirect, url_for
from models import db, Note, User
import qrcode
from PIL import Image
from pyzbar.pyzbar import decode
import os
import subprocess
import markdown
import requests as http_client  # renamed so it doesn't clash with flask.request

app = Flask(__name__)

# SQLite database lives in instance/notes.db, relative to this file
# SQLAlchemy handles connection pooling and ORM mapping for us
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ───────────────────────────────────────────────────────────────
#  VULNERABLE: SECRET_KEY hardcoded as a short, guessable string
# ───────────────────────────────────────────────────────────────
# Flask signs session cookies with this key using HMAC-SHA1
# If an attacker knows this value they can forge valid cookies
# for ANY user without needing a password
#
# How it gets leaked in this app:
#   1. LFI  -> /download?file=../../../app.py -> read this line directly
#   2. Werkzeug debug console -> flask.current_app.config['SECRET_KEY']
#   3. Guessing — 'super-secret-key-123' is in every common wordlist
#
# The session_forgery.py script chains LFI + this key to forge admin cookies
app.config['SECRET_KEY'] = 'super-secret-key-123'

# Session timeout — after 5 minutes of inactivity the cookie expires
# This is intentionally short for demo purposes
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

# ───────────────────────────────────────────────────────────────
#  VULNERABLE: Cookie security flags deliberately weakened
# ───────────────────────────────────────────────────────────────
# SameSite=None  -> browser sends cookie on cross-origin requests (CSRF works)
# HttpOnly=False -> JavaScript can read document.cookie (XSS cookie theft works)
#
# In a secure app you would set:
#   SESSION_COOKIE_SAMESITE = 'Lax'   -> blocks cross-site POST cookies
#   SESSION_COOKIE_HTTPONLY = True     -> JS cannot touch the cookie
app.config['SESSION_COOKIE_SAMESITE'] = None
app.config['SESSION_COOKIE_HTTPONLY'] = False

# Hook SQLAlchemy to the Flask app so we can use db.session in routes
db.init_app(app)

# Path where generated QR code images are saved
QR_IMAGE = 'static/image.jpg'


# ═══════════════════════════════════════════════════════════════
#  AUTHENTICATION
# ═══════════════════════════════════════════════════════════════

@app.before_request
def require_login():
    """
    Runs before every single request. If the user is not logged in
    and the target is not in the allow-list, redirect them to /login.
    
    VULNERABLE: passes the full request.url (including scheme and host)
    as the ?next= parameter. An attacker can craft a URL like:
        /login?next=http://evil.com/phishing
    and after a successful login Flask will redirect there blindly.
    
    The secure version stores only request.path (relative path like /settings),
    which cannot point to an external domain.
    """
    allowed = ['login', 'register', 'static']
    if request.endpoint not in allowed and not session.get('logged_in'):
        # VULNERABLE: request.url includes scheme+host, enabling open redirect
        # a safe version would use request.path instead
        return redirect(url_for('login', next=request.url))


# ───────────────────────────────────────────────────────────────
#  REGISTER
# ───────────────────────────────────────────────────────────────

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Account creation endpoint.
    
    VULNERABLE in multiple ways:
      1. No CSRF token -> attacker page can auto-submit the form
      2. No rate limiting -> mass account creation possible
      3. Password stored as plaintext in the DB (no hash)
      4. No password strength requirements (even '1' is accepted)
      5. "Username already taken" message leaks which users exist
         -> brute_force.py uses this for username enumeration
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm  = request.form.get('confirm', '').strip()

        if not username or not password:
            return render_template('register.html', 
                error="Username and password are required")
        
        if password != confirm:
            return render_template('register.html',
                error="Passwords do not match")

        # VULNERABLE: this response tells the attacker "this username exists in our DB"
        # brute_force.py sends common usernames and checks for this exact message
        # a safe version would say "Registration failed" regardless
        if User.query.filter_by(username=username).first():
            return render_template('register.html',
                error="Username already taken")

        # VULNERABLE: password stored as-is, no hashing
        # credential_dump.py downloads the DB via LFI and reads passwords directly
        new_user = User(username=username, password=password, role='user')
        db.session.add(new_user)
        db.session.commit()
        
        # Auto-login after registration — set session cookie
        session['logged_in'] = True
        session['username'] = username
        session.permanent = True  # activates PERMANENT_SESSION_LIFETIME

        next_url = request.args.get('next', url_for('welcome'))
        return redirect(url_for(next_url))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login endpoint.
    
    VULNERABLE:
      1. No rate limiting -> brute_force.py can try thousands of passwords per minute
      2. No CSRF token -> attacker can submit login forms from external pages
      3. Plaintext password comparison (no hash check)
      4. next parameter not validated -> open redirect after login
    
    The next parameter can come from either the query string (GET) or
    a hidden form field (POST). We read both so the value survives
    a failed login attempt (page re-render).
    """
    error = None
    # Read next from POST body first (hidden field), fall back to query string
    # This prevents the double-encoding bug that happens when next is in the form action URL
    next_url = request.form.get('next') or request.args.get('next') or ''

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULNERABLE: comparing plaintext password directly against DB
        # a secure version would call user.check_password(password) which uses hash comparison
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session.permanent = True
            session['logged_in'] = True
            session['username'] = username

            # VULNERABLE: next_url is not validated at all
            # it could be http://evil.com, //evil.com, /\evil.com, etc.
            # open_redirect.py tests 8 different bypass techniques against this
            return redirect(next_url or url_for('welcome'))
        else:
            # This message is safe — it does not reveal whether the username exists
            # (unlike the register endpoint which does leak that info)
            error = 'Invalid username or password.'

    return render_template('login.html', error=error, next_url=next_url)


@app.route('/logout')
def logout():
    """
    Clears the session and redirects to login.
    
    The 'silent' parameter exists so CSRF test scripts can log out
    without triggering a redirect chain — they just need the cookie cleared.
    """
    session.clear()
    if request.args.get('silent'):
        resp = app.make_response('logged out')
        resp.delete_cookie(app.config.get('SESSION_COOKIE_NAME', 'session'))
        return resp
    return redirect(url_for('login', next=request.url))


# ═══════════════════════════════════════════════════════════════
#  QR CODE TOOLS (no vulnerabilities here — just utility features)
# ═══════════════════════════════════════════════════════════════

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/qr')
def qr_home():
    return render_template('index.html')

@app.route('/makeQr', methods=['POST'])
def make():
    """Generate a QR code image from user-provided text and save it to static/."""
    data = request.form.to_dict()
    data_to_convert = data['data']
    qr = qrcode.make(data_to_convert)
    qr.save(QR_IMAGE)
    return render_template('index.html')

@app.route('/decodeQr', methods=['GET', 'POST'])
def decode_qr():
    """
    Upload a QR code image -> decode it -> show the embedded text.
    Uses pyzbar (libzbar) for decoding.
    """
    if request.method == 'POST':
        if 'qr_image' not in request.files:
            return "File could not be found", 400

        file = request.files['qr_image']
        if file.filename == '':
            return "No file selected", 400

        try:
            img = Image.open(file.stream)
            decoded_objs = decode(img)
            # Each QR code object has a .data field (bytes) that we decode to UTF-8
            data_list = [obj.data.decode('utf-8') for obj in decoded_objs]
            return render_template('decode.html', results=data_list)
        except Exception as e:
            # VULNERABLE: raw exception message leaks internal paths and library versions
            return f"Error: {e}", 500

    return render_template('decode.html', results=None)


# ═══════════════════════════════════════════════════════════════
#  MARKDOWN NOTES (contains Stored XSS vulnerability)
# ═══════════════════════════════════════════════════════════════

@app.route('/notes')
def list_notes():
    """
    Shows all notes, optionally filtered by category.
    The notes themselves are safe here — the XSS fires in view_note below.
    """
    category = request.args.get('category')
    if category:
        notes = Note.query.filter_by(category=category).all()
    else:
        notes = Note.query.all()
    # Get distinct category names for the sidebar filter
    categories = db.session.query(Note.category).distinct().all()
    return render_template('notes.html', notes=notes, categories=categories)


@app.route('/notes/<int:note_id>')
def view_note(note_id):
    """
    Renders a single note's markdown content as HTML.
    
    VULNERABLE (Stored XSS):
      The markdown library converts .md -> HTML, preserving inline HTML tags.
      The template uses {{ content|safe }} which tells Jinja2 to skip auto-escaping.
      
      So if a note contains:
          <script>alert('XSS')</script>
      
      markdown passes it through unchanged, |safe tells Jinja2 not to escape it,
      and the browser executes the script.
      
      The XSS test notes in markdowns/hacklab/ demonstrate:
        xss_1 -> alert box (proof of concept)
        xss_2 -> silent cookie theft via document.cookie
        xss_3 -> keylogger + fake login page (page defacement)
        xss_4 -> self-propagating worm with clipboard hijacking
      
      The secure version uses bleach.clean() to strip dangerous tags
      while keeping safe ones (<h1>, <p>, <code>, etc.)
    """
    note = Note.query.get_or_404(note_id)
    # markdown() converts markdown syntax to HTML (headers, bold, code blocks, tables)
    # but it also passes through raw HTML tags like <script> without touching them
    html_content = markdown.markdown(note.content, extensions=['fenced_code', 'tables'])
    # content is passed to the template where |safe disables Jinja2's auto-escaping
    return render_template('view.html', filename=note.title, content=html_content)


@app.route("/category/<category>")
def notes_by_category(category):
    """Filter notes by category — used by the sidebar category links."""
    notes = Note.query.filter_by(category=category).all()
    return render_template("category.html", notes=notes, category=category)


# ═══════════════════════════════════════════════════════════════
#  CSRF-VULNERABLE ENDPOINTS
# ═══════════════════════════════════════════════════════════════
#
# These endpoints accept state-changing operations via GET and lack CSRF tokens.
# The attacker pages in attacker_pages/ exploit this:
#   csrf_attacker_site.html  -> auto-submits forms to change passwords and delete notes
#   csrf_newsletter.html     -> disguised as a newsletter signup, actually attacks these endpoints

@app.route('/delete_note/<int:note_id>', methods=['GET', 'POST'])
def delete_note(note_id):
    """
    VULNERABLE: accepts GET requests for a state-changing operation.
    
    An attacker can delete any note by embedding this in a page:
        <img src="http://127.0.0.1:5000/delete_note/5">
    
    The browser makes a GET request, Flask deletes the note.
    The img tag trick works because the browser doesn't care that
    the response isn't actually an image — the request was already sent.
    
    Also: no ownership check. Any logged-in user can delete any note (IDOR).
    """
    note = Note.query.get_or_404(note_id)
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for('list_notes'))


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    """
    VULNERABLE in three critical ways:
    
    1. Accepts GET parameters -> an attacker can change someone's password with:
           <img src="http://127.0.0.1:5000/change_password?new_password=hacked">
       or by embedding this URL in csrf_attacker_site.html
    
    2. No CSRF token -> any external page can submit this form
    
    3. Does not require current password -> if you have the session (via XSS cookie theft
       or session forgery), you can change the password without knowing the old one
    """
    message = None
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        username = session.get('username')

        if new_password and new_password == confirm_password and username:
            user = User.query.filter_by(username=username).first()
            if user:
                # VULNERABLE: stores new password as plaintext, no hash
                user.password = new_password
                db.session.commit()
            message = f'Password changed successfully for {username}.'
        else:
            message = 'Passwords do not match.'

    # VULNERABLE: password change via GET — this should NEVER exist
    # HTTP GET requests must be safe and idempotent (RFC 7231)
    # they should never modify server state
    if request.method == 'GET' and request.args.get('new_password'):
        new_password = request.args.get('new_password')
        username = session.get('username')
        if username:
            user = User.query.filter_by(username=username).first()
            if user:
                user.password = new_password
                db.session.commit()
            message = f'Password changed successfully for {username}.'

    return render_template('settings.html', message=message)


@app.route('/add_note', methods=['GET', 'POST'])
def add_note():
    """
    VULNERABLE: accepts both GET and POST for creating notes.
    
    GET-based note creation enables CSRF — an attacker can inject notes
    containing XSS payloads by tricking a victim into visiting:
        /add_note?title=hacked&content=<script>...</script>&category=xss
    
    The injected note then fires its XSS payload on every subsequent viewer.
    This is how an XSS worm would propagate through the note system.
    """
    title = request.form.get('title') or request.args.get('title', 'Untitled')
    content = request.form.get('content') or request.args.get('content', '')
    category = request.form.get('category') or request.args.get('category', 'general')

    if title and content:
        # No ownership tracking — anyone's note looks the same (IDOR)
        note = Note(title=title, content=content, category=category)
        db.session.add(note)
        db.session.commit()
    return redirect(url_for('list_notes'))


# ═══════════════════════════════════════════════════════════════
#  WERKZEUG DEBUG MODE (RCE vulnerability)
# ═══════════════════════════════════════════════════════════════
#
# With debug=True, unhandled exceptions show an interactive Python console
# in the browser. The console is "protected" by a PIN, but that PIN is
# calculated from values an attacker can read via LFI:
#   - /sys/class/net/eth0/address  (MAC address)
#   - /etc/machine-id
#   - /proc/self/cgroup
#
# lfi_to_rce.py and werkzeug_pin_calc.py automate the entire chain.

@app.route('/debug_test')
def debug_test():
    """
    Deliberately crashes to trigger the Werkzeug interactive debugger.
    The stack trace leaks: username, Flask install path, Python version.
    All of these are inputs to the debug PIN calculation.
    """
    result = 1 / 0  # ZeroDivisionError — Werkzeug catches this and shows the console
    return str(result)

@app.route('/debug_test2')
def debug_test2():
    """
    Another intentional crash — this one leaks file path information
    through the FileNotFoundError traceback.
    """
    with open('/nonexistent/secret/file.txt') as f:
        return f.read()


# ═══════════════════════════════════════════════════════════════
#  PATH TRAVERSAL / LOCAL FILE INCLUSION (LFI)
# ═══════════════════════════════════════════════════════════════

@app.route('/download')
def download_file():
    """
    File download endpoint — looks innocent but has no path validation.
    
    Normal usage:
        /download?file=report.pdf  -> serves static/files/report.pdf
    
    Attack (path traversal):
        /download?file=../../../etc/passwd
        /download?file=../../../sys/class/net/eth0/address   (MAC for PIN calc)
        /download?file=../../../etc/machine-id                (for PIN calc)
        /download?file=../../../proc/self/cgroup              (for PIN calc)
        /download?file=../../app.py                           (leaks SECRET_KEY)
        /download?file=../../instance/notes.db                (steals entire DB)
    
    The vulnerability: os.path.join does NOT prevent ../ sequences.
    When filename='../../../etc/passwd', the resulting path walks out of
    static/files/ all the way up to the root filesystem.
    
    lfi_to_rce.py, credential_dump.py, and session_forgery.py all use this.
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
 
    # VULNERABLE: no path sanitization whatsoever
    # os.path.join simply concatenates the paths — it does not resolve or block ../
    # so base_dir + '../../../../etc/passwd' = '/etc/passwd' after resolution
    base_dir = os.path.join(os.path.dirname(__file__), 'static', 'files')
    file_path = os.path.join(base_dir, filename)
    
    try:
        # Try reading as text first (source code, config files, /etc/passwd)
        with open(file_path, 'r') as f:
            content = f.read()
        return content, 200, {'Content-Type': 'text/plain'}
    except UnicodeDecodeError:
        # Binary files (SQLite .db, images, compiled files) — serve as raw bytes
        # This is what makes credential_dump.py work — it downloads the .db file
        with open(file_path, 'rb') as f:
            content = f.read()
        return content, 200, {'Content-Type': 'application/octet-stream'}
    except FileNotFoundError:
        # VULNERABLE: leaks the full server-side file path in the error message
        # an attacker uses this to understand the directory structure
        return f"Error: File '{filename}' not found at {file_path}", 404
    except PermissionError:
        # VULNERABLE: same issue — confirms the file exists but is protected
        return f"Error: Permission denied for {file_path}", 403
    except Exception as e:
        # VULNERABLE: raw exception details leak internal information
        return f"Error reading file: {e}", 500
 

@app.route('/files')
def list_files():
    """
    A normal-looking file listing page that serves as the entry point
    for LFI discovery. An attacker starts here, sees the /download endpoint,
    and then starts fuzzing the file parameter with ../ sequences.
    """
    return render_template('files.html')


# ═══════════════════════════════════════════════════════════════
#  SQL INJECTION
# ═══════════════════════════════════════════════════════════════

@app.route('/search')
def search():
    """
    Search endpoint — the single most exploited route in this app.
    Three different SQLi scripts target this same endpoint:
    
    sqli_classic.py  -> UNION SELECT to dump tables and credentials directly
    sqli_blind.py    -> Boolean-based: asks yes/no questions character by character
    sqli_time.py     -> Time-based: measures response delay to extract data
    
    All three work because the user's search term is f-string interpolated
    directly into a raw SQL query. The input becomes part of the SQL structure
    rather than being treated as a data parameter.
    
    Additionally, the executed SQL is displayed on the page (executed_sql),
    which helps the attacker understand the query structure and refine payloads.
    """
    q = request.args.get('q', '')
    results = []
    error = None
    executed_sql = None

    if q:
        # ─── THE VULNERABILITY ───────────────────────────────────────
        # f-string puts user input directly inside the SQL string
        # if q = "' OR 1=1 --" the query becomes:
        #   SELECT ... WHERE title LIKE '%' OR 1=1 --%' OR content ...
        # the -- turns the rest into a comment, OR 1=1 matches every row
        #
        # The safe alternative is parameterized queries:
        #   db.session.execute(text("SELECT ... WHERE title LIKE :q"), {"q": f"%{q}%"})
        # or even simpler, use the ORM:
        #   Note.query.filter(Note.title.like(f"%{q}%")).all()
        sql = f"SELECT id, title, content, category, created_at FROM notes WHERE title LIKE '%{q}%' OR content LIKE '%{q}%'"

        # VULNERABLE: showing the actual SQL helps attackers debug their payloads
        # this would never exist in a production app
        executed_sql = sql

        try:
            from sqlalchemy import text
            result = db.session.execute(text(sql))
            results = result.fetchall()
        except Exception as e:
            # VULNERABLE: raw SQL error messages reveal table names, column names,
            # query structure — everything an attacker needs to craft UNION SELECT
            error = str(e)

    return render_template('search.html',
        query=q,
        results=results,
        error=error,
        executed_sql=executed_sql,
        result_count=len(results)
    )


# ═══════════════════════════════════════════════════════════════
#  OS COMMAND INJECTION
# ═══════════════════════════════════════════════════════════════

@app.route('/ping', methods=['GET', 'POST'])
def ping_tool():
    """
    Network diagnostic tool that pings a user-provided hostname.
    
    VULNERABLE: user input goes directly into a shell command via f-string,
    and subprocess.run is called with shell=True, which means the shell
    interprets all metacharacters:
    
        ;     -> sequential execution:  ping host; whoami
        &&    -> conditional:           ping host && cat /etc/passwd
        |     -> pipe:                  ping host | cat /etc/shadow
        $()   -> command substitution:  ping $(whoami)
        `cmd` -> legacy substitution:   ping `id`
    
    cmdi.py automates all of these.
    
    The safe fix is to pass arguments as a list (no shell interpretation):
        subprocess.run(["ping", "-c", "2", host], shell=False)
    and validate input with a regex whitelist.
    """
    output = None
    host = ""
    executed_cmd = None
 
    if request.method == 'POST':
        host = request.form.get('host', '').strip()
 
        if host:
            # VULNERABLE: f-string interpolation puts raw user input into the command
            cmd = f"ping -c 2 {host}"
            
            # Debug: showing the constructed command (would not exist in production)
            executed_cmd = cmd
 
            try:
                # shell=True is the key enabler — it passes the string to /bin/sh
                # which interprets ;, |, &&, $() and every other shell feature
                # without shell=True, subprocess would treat the whole string as
                # a single executable name and fail safely
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                output = result.stdout + result.stderr
            except subprocess.TimeoutExpired:
                output = "Command timed out (10s limit)"
            except Exception as e:
                output = f"Error: {e}"
 
    return render_template('ping.html',
        host=host,
        output=output,
        executed_cmd=executed_cmd
    )


# ═══════════════════════════════════════════════════════════════
#  SERVER-SIDE REQUEST FORGERY (SSRF)
# ═══════════════════════════════════════════════════════════════

@app.route('/preview', methods=['GET', 'POST'])
def preview_url():
    """
    URL preview tool — fetches a URL and displays its content.
    
    VULNERABLE in multiple ways:
    
    1. No URL validation — accepts any scheme, host, port
       -> attacker can target localhost, private IPs, cloud metadata
    
    2. Forwards the user's session cookies with the request
       -> internal requests to localhost:5000 are AUTHENTICATED
       -> this means SSRF can chain with other vulns that require login
       -> also leaks cookies to any external URL the attacker controls
    
    3. Follows redirects (allow_redirects=True)
       -> attacker can redirect through multiple hops to reach internal services
    
    4. No response size limit -> potential for DoS via huge responses
    
    ssrf.py demonstrates:
      - Internal port scanning (22, 3306, 6379, 5000)
      - SSRF -> LFI chain (reading /etc/passwd via localhost)
      - SSRF -> SQLi chain (dumping credentials via localhost)
      - Cloud metadata theft (169.254.169.254)
    """
    url = ""
    content = None
    status_code = None
    error = None
    content_length = None
    response_headers = None
 
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
 
        if url:
            try:
                # VULNERABLE: no validation on the URL whatsoever
                # the server will happily fetch localhost, 10.x.x.x, 192.168.x.x,
                # 169.254.169.254 (cloud metadata), or any other internal address
                #
                # VULNERABLE: forwarding the user's cookies means the request
                # hits internal endpoints as an authenticated user
                cookies = {key: val for key, val in request.cookies.items()}
                resp = http_client.get(url, timeout=5, allow_redirects=True, cookies=cookies)
                content = resp.text
                status_code = resp.status_code
                content_length = len(resp.content)
                # VULNERABLE: showing response headers can leak internal service info
                response_headers = dict(resp.headers)
            except http_client.exceptions.ConnectionError:
                # This error reveals which ports are closed vs open (port scan info)
                error = f"Connection refused — no service at {url}"
            except http_client.exceptions.Timeout:
                error = f"Request timed out (5s) — {url}"
            except http_client.exceptions.MissingSchema:
                error = f"Invalid URL (missing http:// or https://) — {url}"
            except Exception as e:
                # VULNERABLE: detailed error messages leak internal info
                error = f"Request failed: {type(e).__name__}: {e}"
 
    return render_template('preview.html',
        url=url,
        content=content,
        status_code=status_code,
        content_length=content_length,
        response_headers=response_headers,
        error=error
    )


# ═══════════════════════════════════════════════════════════════
#  STARTUP
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    with app.app_context():
        # Create all tables defined in models.py if they don't exist yet
        db.create_all()

        # Seed default users — these are the targets for brute_force.py
        # VULNERABLE: passwords stored as plaintext strings
        # in the secure version, set_password() hashes them with PBKDF2
        if not User.query.filter_by(username='admin').first():
            db.session.add(User(username='admin', password='admin123', role='admin'))
        if not User.query.filter_by(username='potato').first():
            db.session.add(User(username='potato', password='test123', role='user'))
        db.session.commit()

    # VULNERABLE: debug=True activates the Werkzeug interactive debugger
    # any unhandled exception shows a Python console in the browser
    # combined with LFI to calculate the PIN, this gives full RCE
    # the secure version runs with debug=False
    app.run(debug=True)
