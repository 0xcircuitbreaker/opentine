"""The private-key markers and label shared by the harness key maskers.

Three armors open a key block: PEM (``-----BEGIN … PRIVATE KEY-----``), RFC 4716
/ ssh.com (``---- BEGIN SSH2 … PRIVATE KEY ----``) and a PuTTY key file, whose
``PuTTY-User-Key-File-N: <algorithm>`` header line is its opener and whose
``Private-MAC`` line closes it. The record's scrubber knows all three, so a line
a harness keeps raw for it (see ``_key_mask.buffered``) is still removed whole.
"""

from __future__ import annotations

import re

PLACEHOLDER = "[REDACTED PRIVATE KEY]"
BEGIN = re.compile(
    r"-----BEGIN [A-Z ]{0,64}PRIVATE KEY(?: BLOCK)?-----"
    r"|---- BEGIN SSH2 [A-Z ]{0,64}PRIVATE KEY ----"
    r"|PuTTY-User-Key-File-\d{1,2}:[ \t]*[A-Za-z0-9@._-]{0,64}"
)
END = re.compile(
    r"-----END [A-Z ]{0,64}PRIVATE KEY(?: BLOCK)?-----"
    r"|---- END SSH2 [A-Z ]{0,64}PRIVATE KEY ----"
    r"|Private-MAC:[ \t]*[0-9A-Fa-f]{0,128}"
)

__all__ = ["BEGIN", "END", "PLACEHOLDER"]
