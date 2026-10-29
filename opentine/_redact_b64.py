"""Credentials wrapped in base64: decoded, scanned, and redacted whole on a hit.

A stdlib-only leaf of ``redaction`` (the module line cap). ``_redact_forms``
already unwraps base64 of a PEM block; this is the general case -- a tool
argument holding base64 of ``Authorization: Bearer ...`` or of a ``.env`` file.
A heuristic with fixed bounds, so it stays cheap and quiet on ordinary content:

* only a padded-to-four run of the standard alphabet, 24 to 8192 characters,
  standing alone (not the middle of a longer word or path);
* only one that decodes to printable UTF-8 text -- images, hashes and random
  identifiers decode to binary and are skipped untouched;
* at most ``MAX_CANDIDATES`` runs per value, so a blob of many short base64
  strings costs a bounded number of decodes;
* the decoded text goes through the caller's whole scan, so the run is
  replaced only when that scan would have removed something from the plain text.

Known limit: URL-safe base64, unpadded runs and double encodings split across
several runs are not unwrapped.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable

from opentine._redact_edits import Edit, Step

MIN_CHARS = 24
MAX_CHARS = 8192
MAX_CANDIDATES = 64
_R = b"[REDACTED]"
_RUN = re.compile(
    rb"(?<![A-Za-z0-9+/_.-])[A-Za-z0-9+/]{%d,%d}={0,2}(?![A-Za-z0-9+/=_.-])"
    % (MIN_CHARS - 2, MAX_CHARS)
)
_TEXT_CONTROLS = frozenset("\t\r\n")


def _as_text(run: bytes) -> bytes | None:
    """*run* decoded, when it is base64 of printable UTF-8 text; else ``None``."""
    if len(run) % 4:
        return None
    try:
        decoded = base64.b64decode(run, validate=True)
        text = decoded.decode("utf-8")
    except (binascii.Error, ValueError):  # UnicodeDecodeError is a ValueError
        return None
    if not all(ch.isprintable() or ch in _TEXT_CONTROLS for ch in text):
        return None
    return decoded


def b64_text_step(scan: Callable[[bytes], bytes]) -> Step:
    """A scan step redacting base64 runs whose decoded text *scan* would change."""

    def step(value: bytes) -> list[Edit]:
        edits: list[Edit] = []
        for count, match in enumerate(_RUN.finditer(value)):
            if count >= MAX_CANDIDATES:
                break
            decoded = _as_text(match.group(0))
            if decoded is not None and scan(decoded) != decoded:
                edits.append((match.start(), match.end(), _R))
        return edits

    return step


__all__ = ["b64_text_step"]
