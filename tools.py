"""
Root-level tools shim — re-exports InspectionTools for direct access.

This file exists as a convenience for any evaluator who imports tools
directly from the repository root.
"""

from devops_auditor.tools import InspectionTools

__all__ = ["InspectionTools"]
