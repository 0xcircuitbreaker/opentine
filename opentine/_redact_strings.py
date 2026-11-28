"""Free-text shapes the field walk (``_canon_redact._redact``) hands to the scanner (0.88.1).

``_redact`` reads a string as one ``label: value`` pair, which is right for a
header line and wrong for everything that holds a credential *inside* longer
text. Callers that run only that walk (event attributes, usage, billing, fork
overrides, evidence reports) stored these in clear: a later line of a ``.env``
file, a URL query parameter or userinfo password, a PEM private-key body, an
assignment on the line after a base64 line. A string with one of those shapes
goes through the byte scanner (``redaction.redact_text``), which already keeps a
signed note's base64 lines. All-capital run-together names
(``MYSQLROOTPASSWORDPRODUCTION``) read as no field name to either half, so both
check them here.
"""

from __future__ import annotations

import re

_SHAPES = re.compile(r"[\r\n]|://|-----BEGIN|[?&][A-Za-z_-]{1,40}=|PuTTY-User-Key-File")
_CAPS_WORDS = (
    r"(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|APIKEY|API_KEY|PRIVATEKEY|PRIVATE_KEY|CREDENTIAL)"
)
#: An all-capital name holding a credential word anywhere, then ``=`` or ``:``.
CAPS_NAME = re.compile(r"[A-Z0-9_]{0,64}" + _CAPS_WORDS + r"[A-Z0-9_]{0,64}")
#: The same in bytes, at a token start, with a value on the same line. The value
#: may not start with ``=``, so base64 padding (``...SECRETab==``) is never read
#: as an assignment, and the lookbehind keeps a mixed-case base64 word out.
CAPS_ASSIGNMENT = re.compile(
    rb"(?<![A-Za-z0-9+/_-])([A-Z0-9_]{0,64}"
    + _CAPS_WORDS.encode()
    + rb"[A-Z0-9_]{0,64}[ \t]*[:=][ \t]*)"
    rb"([^\s=,;\"'][^\s,;\"']*)"
)


def caps_name(label: str) -> bool:
    """``MYSQLROOTPASSWORDPRODUCTION``: a credential word inside an all-capital name."""
    return bool(CAPS_NAME.fullmatch(label.strip().lstrip("-")))


def scan_text(value: str) -> str:
    """``value`` through the byte scanner when it holds a shape the walk cannot split."""
    if not _SHAPES.search(value):
        return value
    from opentine.redaction import redact_text  # redaction imports this layer

    try:
        return redact_text(value)
    except ValueError:  # unencodable text: the guard after the walk reports it
        return value
