"""
Minimal broken project — used for invalid/edge-case audit testing.

This repo simulates a project with:
- No README (COLLAB)
- No LICENSE (COLLAB)
- No .gitignore (HYGN)
- No CI pipeline
- No tests
- Unpinned dependencies
- A committed secret
"""

# Secret token hardcoded (SEC)
GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"

def do_something() -> None:
    pass
