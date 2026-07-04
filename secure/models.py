# ═══════════════════════════════════════════════════════════════
#  Database Models — SECURE VERSION
# ═══════════════════════════════════════════════════════════════
#
# Key differences from the vulnerable version:
#   1. password field replaced with password_hash (PBKDF2-SHA256 + random salt)
#   2. set_password() and check_password() methods encapsulate hashing logic
#   3. Note model has an 'owner' field for IDOR protection
#
# Even if the database is stolen (via backup leak, SQL injection, or server breach),
# the attacker gets hashes, not passwords. A strong password with PBKDF2 takes
# years to crack. Without this, credential_dump.py reads every password in seconds.
# ═══════════════════════════════════════════════════════════════

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    # Content goes through bleach.clean() in app.py before reaching the template
    # so even if someone writes <script>alert(1)</script>, it gets stripped
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # SECURE: every note has an owner — delete_note checks this before allowing deletion
    # without this field, user A could delete user B's notes by guessing note IDs (IDOR)
    owner = db.Column(db.String(80), nullable=True)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # SECURE: only the hash is stored, never the raw password
    # each hash includes a random salt so identical passwords produce different hashes
    # this defeats rainbow table attacks completely
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        """Hash the password with PBKDF2-SHA256 and a random salt before storing.
        werkzeug uses 600,000 iterations by default, making brute force expensive.
        The raw password is never written to the database."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Compare a candidate password against the stored hash.
        Returns True only if the password matches. The hash includes
        the salt and iteration count, so this is a constant-time comparison
        that resists timing attacks."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'
