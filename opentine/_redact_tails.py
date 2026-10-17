"""Where a capped form value really ends, so a redaction never cuts a token in half.

A stdlib-only leaf of ``_redact_forms``. Every form value is a bounded run
(``{1,512}``, ``{1,4096}``) to keep the scan linear, and a value longer than its
bound used to be cut where the bound fell: ``cookie: <4093 bytes> ghp_...`` became
``cookie: [REDACTED]p_...``, the vendor prefix gone with the bounded part and the
rest of the token written out. Each tail here is the same run class as the value it
continues, unbounded but anchored at the end of the match, so extending an edit
over it costs one pass over bytes that the edit then removes.
"""

from __future__ import annotations

import re
from collections.abc import Callable

Tail = Callable[[re.Match[bytes]], "re.Pattern[bytes] | None"]

_HEADER_RUN = re.compile(rb"[^\r\n'\"\\]*")
# A bare pwd or CLI value: whole escape pairs, never a raw quote (see _redact_forms).
_PWD_RUN = re.compile(rb"(?:[^\s,;\"'\\]|\\[^\s\"'])*")
_CLI_RUN = re.compile(rb"(?:[^\s'\"\\]|\\[^\s\"'])*")
# A ``\\"``-quoted value inside a JSON string whose closing ``\\"`` the bound cut off.
_JSON_QUOTED_RUN = re.compile(rb"(?:[^\\\"\r\n]|\\(?!\")[^\"\r\n])*")
_NETRC_JSON_RUN = re.compile(rb"(?:\\\\(?:\\\\|\\\")|[^\\\"\r\n]|\\(?!\")[^\"\r\n])*")
_SINGLE_RUN = re.compile(rb"[^'\"\\\r\n]*")
_NETRC_RUN = re.compile(rb"[^\s'\"\\]*")
#: A bare netrc value may stop *before* a closer (``,;]}``) on purpose; only a value
#: that used its whole bound is cut, so only that one is extended.
_NETRC_BOUND = 512


def header_tail(_match: re.Match[bytes]) -> re.Pattern[bytes]:
    return _HEADER_RUN


def pwd_tail(match: re.Match[bytes]) -> re.Pattern[bytes] | None:
    groups = match.groupdict()
    if groups.get("bare") is not None:
        return _PWD_RUN
    if groups.get("qj") is not None and groups.get("cj") is None:
        return _JSON_QUOTED_RUN
    if groups.get("qs") is not None and groups.get("cs") is None:
        return _SINGLE_RUN
    return None


def cli_tail(match: re.Match[bytes]) -> re.Pattern[bytes] | None:
    groups = match.groupdict()
    return _CLI_RUN if groups.get("bare") is not None or groups.get("buser") is not None else None


def netrc_tail(match: re.Match[bytes]) -> re.Pattern[bytes] | None:
    groups = match.groupdict()
    bare = groups.get("bare")
    if bare is not None:
        return _NETRC_RUN if len(bare) >= _NETRC_BOUND else None
    if groups.get("oj") is not None and groups.get("cj") is None:
        return _NETRC_JSON_RUN
    return None


__all__ = ["Tail", "cli_tail", "header_tail", "netrc_tail", "pwd_tail"]
