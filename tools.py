"""
Root-level tools shim — re-exports InspectionTools for direct access.

This file exists as a convenience for any evaluator who imports tools
directly from the repository root.
"""

import sys
from pathlib import Path

# Ensure src is on sys.path so 'import tools' works directly out-of-the-box
sys.path.insert(0, str(Path(__file__).parent / "src"))

from devops_auditor.tools import InspectionTools

__all__ = ["InspectionTools"]
