"""What stands between an uncaught exception and the operator's terminal.

Most verbs refuse with a typed, sanitized message, but any exception that got
past them reached Python's default hook, which prints ``str(exc)`` raw. Loader
messages quote artifact content, so an untrusted ``.tine`` could put escape
sequences on the terminal -- a clipboard write (OSC 52), a title change, a
screen clear -- through eleven verbs. Every invocation now ends here: one
sanitized ``tine: <message>`` line on stderr and exit 1. ``OPENTINE_DEBUG=1``
re-raises, for the traceback.

It also installs the CLI's notices for the pricing layers the library skips: an
unsigned workspace overlay (``./.tine/pricing.json``) the operator has not opted
in to, and a signed user catalog older than the bundled one.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

from opentine._cli_text import plain_text
from opentine.billing._catalog_trust import TRUST_WORKSPACE_PRICING_ENV

DEBUG_ENV = "OPENTINE_DEBUG"

_warned: set[str] = set()


def _once(path: Path, message: str) -> None:
    if str(path) not in _warned:
        _warned.add(str(path))
        print(f"tine: note: {message}", file=sys.stderr)


def _warn_overlay(path: Path) -> None:
    _once(
        path,
        f"ignoring unsigned workspace overlay {plain_text(path)} for pricing; set "
        f"{TRUST_WORKSPACE_PRICING_ENV}=1 to apply it",
    )


def _warn_stale(path: Path) -> None:
    _once(path, f"ignoring {plain_text(path)}: it is older than the bundled pricing catalog")


def guarded_dispatch(run: Callable[[], None]) -> None:
    """Run one verb; turn any uncaught exception into one sanitized line."""
    from opentine.billing import catalog

    previous, catalog.workspace_overlay_hook = catalog.workspace_overlay_hook, _warn_overlay
    stale, catalog.stale_catalog_hook = catalog.stale_catalog_hook, _warn_stale
    try:
        run()
    except Exception as exc:  # KeyboardInterrupt and SystemExit pass through
        if os.environ.get(DEBUG_ENV):
            raise
        message = plain_text(exc) or type(exc).__name__
        print(f"tine: {message}", file=sys.stderr)
        raise SystemExit(1) from exc
    finally:
        catalog.workspace_overlay_hook = previous
        catalog.stale_catalog_hook = stale


__all__ = ["DEBUG_ENV", "TRUST_WORKSPACE_PRICING_ENV", "guarded_dispatch"]
