"""Single source of truth for the package version.

Kept dependency-free so any module (including migration tooling that must avoid
importing the package root) can read the version without risking import cycles.
"""

__version__ = "0.8.1"
