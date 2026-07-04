# markdown note importer
# walks through the markdowns/ directory tree and loads every .md file
# into the notes database as a separate note entry
#
# the directory structure determines the category:
#   markdowns/hacklab/sqli_classic.md  ->  category = "hacklab"
#   markdowns/general/todo.md          ->  category = "general"
#   markdowns/some_file.md             ->  category = "general" (root = general)
#
# this is how the XSS test notes get into the database
# the xss_1_alert.md through xss_4_phishing.md files contain <script> tags
# that will execute when viewed through the vulnerable app's |safe filter
# in the secure version, bleach.clean() strips those tags before rendering

import sys
import os

# add parent directory to path so we can import app and models
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models import db, Note
from app import app


def extract_category(dirpath, root_directory):
    """derives the note category from the directory path
    if the file is directly in the root markdowns/ folder, category is 'general'
    if it is in a subfolder like markdowns/hacklab/, category is 'hacklab'"""
    relative = os.path.relpath(dirpath, root_directory)
    if relative == ".":
        return "general"
    # convert OS path separators to forward slashes for consistency
    return relative.replace(os.sep, "/")


def import_notes(directory):
    """recursively finds all .md files under the given directory
    and inserts each one as a Note record in the database"""
    with app.app_context():
        for dirpath, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                # only process markdown files
                if filename.endswith('.md'):
                    filepath = os.path.join(dirpath, filename)
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # use the filename without .md extension as the note title
                        title = filename.rsplit('.', 1)[0]
                        # derive category from the directory structure
                        category = extract_category(dirpath, directory)
                        note = Note(title=title, content=content, category=category)
                        db.session.add(note)
        # commit once at the end rather than per-file for better performance
        db.session.commit()


if __name__ == "__main__":
    # markdowns/ directory is at the project root, one level up from scripts/
    project_root = os.path.join(os.path.dirname(__file__), '..')
    import_notes(os.path.join(project_root, "markdowns"))
