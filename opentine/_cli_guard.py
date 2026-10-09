"""What stands between an uncaught exception and the operator's terminal.

Most verbs refuse with a typed, sanitized message, but any exception that got
past them reached Python's default hook, which prints ``str(exc)`` raw. Loader
messages quote artifact content, so an untrusted ``.tine`` could put escape
sequences on the terminal -- a clipboard write (OSC 52), a title change, a
screen clear -- through eleven verbs. Every invocation now ends here: one
sanitized ``tine: <message>`` line on stderr and exit 1. ``OPENTINE_DEBUG=1``
re-raises, for the traceback.

It also installs the CLI's notice for an unsigned workspace pricing overlay
(``./.tine/pricing.json``), which the library loads silently.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

from opentine._cli_text import plain_text

DEBUG_ENV = "OPENTINE_DEBUG"
#: Set to silence the workspace-overlay notice once its source is trusted.
TRUST_WORKSPACE_PRICING_ENV = "OPENTINE_TRUST_WORKSPACE_PRICING"

_warned: set[str] = set()


def _warn_overlay(path: Path) -> None:
    key = str(path)
    if key in _warned or os.environ.get(TRUST_WORKSPACE_PRICING_ENV):
        return
    _warned.add(key)
    print(
        f"tine: note: pricing from unsigned workspace overlay {plain_text(path)}, which "
        f"outranks your user overlay (set {TRUST_WORKSPACE_PRICING_ENV}=1 to silence)",
        file=sys.stderr,
    )


def guarded_dispatch(run: Callable[[], None]) -> None:
    """Run one verb; turn any uncaught exception into one sanitized line."""
    from opentine.billing import catalog

    previous, catalog.workspace_overlay_hook = catalog.workspace_overlay_hook, _warn_overlay
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


__all__ = ["DEBUG_ENV", "TRUST_WORKSPACE_PRICING_ENV", "guarded_dispatch"]
