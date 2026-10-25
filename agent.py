"""
Root-level entry point shim — satisfies the assignment CLI contract.

Usage:
    python agent.py --repo <url> --output <report.json>

This file delegates entirely to src/devops_auditor/cli.py so that the
package code stays clean and importable while the assignment-specified
invocation pattern is also supported.
"""

import sys
from pathlib import Path

# Ensure src is on sys.path so 'python agent.py' works directly out-of-the-box
sys.path.insert(0, str(Path(__file__).parent / "src"))

from devops_auditor.cli import main

if __name__ == "__main__":
    sys.exit(main())
