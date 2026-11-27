"""The user's opentine config directory: ``$XDG_CONFIG_HOME/opentine``.

``XDG_CONFIG_HOME`` unset or empty means ``~/.config`` (an empty value is
present but meaningless, and ``Path("")`` would be the current directory). The
environment is read at call time, never at import, so a changed environment is
always seen.
"""

from __future__ import annotations

import os
from pathlib import Path


def config_dir(*parts: str) -> Path:
    """``$XDG_CONFIG_HOME/opentine`` (else ``~/.config/opentine``) joined with *parts*."""
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config", "opentine", *parts)


__all__ = ["config_dir"]
