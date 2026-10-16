"""A private key printed base64-wrapped (``base64 id_rsa``), across raw lines.

The record's scrubber recognises a base64-wrapped PEM only when the wrapped
lines sit in one string; a harness records each raw text or stderr line as its
own step, so every continuation line reached the record verbatim and the key
was recoverable from them (final pass 2, #7). :class:`~opentine.harnesses.
_key_mask.KeyLines` uses these helpers to open a block on the first wrapped
line and mask the base64 lines that follow it.
"""

from __future__ import annotations

import base64
import binascii
import re

#: ``-----BEGIN`` base64-encoded, at any of the three alignments a wrapped
#: document starts with (it starts at offset 0, so only this one).
_START = re.compile(r"LS0tLS1CRUdJTi[A-Za-z0-9+/]{16,}={0,2}")
_BODY = re.compile(r"[A-Za-z0-9+/]{4,}={0,2}")


def wrapped_key(line: str) -> tuple[int, bool] | None:
    """Where a base64-wrapped private key starts in *line*, and whether it ends there.

    ``None`` unless the base64 run decodes to a ``-----BEGIN … PRIVATE KEY``
    marker. The second value is True when the whole key fits on the line
    (``base64 -w0``): the run is masked and no block stays open.
    """
    match = _START.search(line)
    if match is None:
        return None
    run = match.group(0)
    try:
        decoded = base64.b64decode(run[: len(run) - len(run) % 4], validate=True)
    except (binascii.Error, ValueError):
        return None
    head = decoded[:96]
    if not head.startswith(b"-----BEGIN ") or b"PRIVATE KEY" not in head:
        return None
    return match.start(), b"-----END " in decoded


def is_wrapped_body(body: str) -> bool:
    """Whether *body* (decoration already stripped) is one base64 continuation line."""
    return bool(body) and _BODY.fullmatch(body) is not None


__all__ = ["is_wrapped_body", "wrapped_key"]
