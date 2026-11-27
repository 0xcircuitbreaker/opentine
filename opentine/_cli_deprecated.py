"""Deprecated CLI spellings that keep working (0.85, docs/DEPRECATION.md).

``--key`` is the one spelling of "the Ed25519 key that signs" on every command.
Commands that took ``--sign-key`` accept both; the old spelling prints one
stderr notice per process naming the new one (``OPENTINE_NO_DEPRECATION=1``
silences it) and reaches the same ``sign_key`` destination.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

_SEEN: set[str] = set()


def notify(old: str, new: str) -> None:
    """One stderr line per process for an old spelling, unless silenced."""
    if old in _SEEN or os.environ.get("OPENTINE_NO_DEPRECATION"):
        return
    _SEEN.add(old)
    print(f"tine: `{old}` is deprecated; use `{new}` (the old spelling still works)",
          file=sys.stderr)  # fmt: skip


class SignKeyAction(argparse._StoreAction):
    """Store the key path; note ``--sign-key`` as the old spelling of ``--key``."""

    def __call__(self, parser: Any, namespace: Any, values: Any, option_string: Any = None):
        if option_string == "--sign-key":
            notify("--sign-key", "--key")
        super().__call__(parser, namespace, values, option_string)


__all__ = ["SignKeyAction", "notify"]
