"""The patterns of :mod:`opentine._redact_publish` (Unreleased).

Separators match ``/``, any run of backslashes (JSON-escaped, or JSON inside
JSON) and their URL encodings (``%2F``, ``%5C``); ``@`` also matches ``%40``,
the JSON escape ``\\u0040`` and the fullwidth ``＠``. A user segment never holds
``%``, so an encoded separator ends it.
"""

from __future__ import annotations

import re

_SL = r"(?:/|%2[Ff])"
_SEP = r"(?:\\+|/|%2[Ff]|%5[Cc])"
_SEG = r"[^\\/\s\"'`:*?<>|,;()\[\]{}%&#]+"
_USER = r"(?:" + _SEG + r"(?: " + _SEG + r"){1,3}(?=" + _SEP + r")|" + _SEG + r")"
_END = r"(?=[/\\\s\"'`:,;)\]}%?&#]|$)"
_UNIX = (
    r"(?:(?<=file://)|(?<![\w.~/\\-]))(?:/var|/mnt/[A-Za-z]|/System/Volumes/Data)?"
    + _SL + r"(?:root|home" + _SL + _SEG + r"|Users" + _SL + _SEG + r")" + _END
)  # fmt: skip
_DRIVE = (
    r"(?<![\w])[A-Za-z](?::|%3[Aa])" + _SEP + r"(?i:users|documents and settings)"
    + _SEP + _USER + _END
)  # fmt: skip
_UNC = (
    r"(?<![\w\\])\\{2,}[^\\/\s\"'`]+\\+(?:[^\\/\s\"'`$]+\$\\+)?"
    r"(?i:users|(?:home|homes|profiles)\$?)\\+" + _USER + _END
)
#: ``~/`` or ``~user/`` only, and only where a path can start (line start, space,
#: quote, ``=``, ``:``, an opening bracket, a shell operator ``<>|&``, a JSON
#: ``\n``/``\t``/``\r`` escape): a lone ``~`` and one inside an identifier, regex
#: or string (``foo#!~bar``) is content, not a home.
_TILDE = (
    r"(?:(?<![^\s\"'`=:(\[{,;<>|&])|(?<=\\[ntr]))"
    r"~(?:[a-z_][a-z0-9_-]{0,31})?(?=/|\\)"
)
PATH = re.compile("|".join((_UNIX, _DRIVE, _UNC, _TILDE)))

AT = r"(?:@|＠|\\u0040|%40)"
EMAIL = re.compile(
    r"(?<![\w.%+@/-])([A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9_-])?)" + AT
    + r"((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24}))"
    r"(?![\w-]|\.[A-Za-z0-9])(:)?"
)  # fmt: skip
#: The user of a URL's userinfo (``scheme://user[:password]@host``).
URL_USER = re.compile(r"(?<=://)([A-Za-z0-9._~!$+-]{1,64})(?=(?::[^\s@/]*)?" + AT + ")")


def login_at(login: str) -> re.Pattern[str]:
    """``<login>@host``: a prompt or an scp target naming this machine's login."""
    return re.compile(r"(?<![\w.%+-])" + re.escape(login) + AT + r"(?=[A-Za-z0-9])")


__all__ = ["AT", "EMAIL", "PATH", "URL_USER", "login_at"]
