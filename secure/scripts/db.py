# database initialization script
# creates all tables defined in models.py if they dont exist yet
# run this once before starting the app for the first time
# or after deleting instance/notes.db to get a fresh database
#
# we need to add the parent directory to sys.path so python can find
# app.py and models.py which live one level above scripts/

import sys
import os

# insert the project root (one level up from scripts/) at the front of the search path
# without this, "from app import app" would fail with ModuleNotFoundError
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
 
from app import app     # the Flask application instance
from models import db   # the SQLAlchemy database object
 
# app_context() is required because SQLAlchemy needs to know which Flask app
# it is working with -- outside of a request handler there is no implicit context
with app.app_context():
    db.create_all()  # reads all Model classes and creates matching SQL tables
    print("done")
