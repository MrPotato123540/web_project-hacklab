# ═══════════════════════════════════════════════════════════════
#  Database Models — VULNERABLE VERSION
# ═══════════════════════════════════════════════════════════════
#
# Two tables: notes and users.
# The critical vulnerability is in the User model — passwords are
# stored as plain VARCHAR strings with zero hashing.
# credential_dump.py exploits this by downloading the DB via LFI
# and reading every password directly.
# ═══════════════════════════════════════════════════════════════

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    # Content can include raw HTML/script tags — this is what enables stored XSS
    # when combined with the |safe filter in view.html
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Note: no 'owner' field — any user can see/delete any note (IDOR vulnerability)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # VULNERABLE: password stored as plaintext VARCHAR
    # when the attacker downloads the DB file via LFI (/download?file=../../instance/notes.db)
    # they can read every password instantly — no cracking step needed
    # the secure version uses password_hash with werkzeug's generate_password_hash
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
