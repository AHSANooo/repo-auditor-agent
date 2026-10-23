"""
Main application module — clean, well-structured code.
"""

import os

from flask import Flask

app = Flask(__name__)

# Configuration read from environment — no hardcoded secrets
DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ.get("SECRET_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///app.db")


@app.route("/")
def index() -> str:
    """Return a simple greeting."""
    return "Hello, World!"


if __name__ == "__main__":
    app.run(debug=DEBUG)
