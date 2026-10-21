"""Paths and hosts a recorded tool call named (see :mod:`opentine._actions_parse`)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from opentine._actions_parse import MAX_FIELD_CHARS, _tokens

MAX_PATHS = 64
MAX_HOSTS = 32
_PATH_KEYS = (
    "path file_path filepath file filename target_file notebook_path source destination "
    "dest target paths files absolute_path relative_path"
).split()
_URL_KEYS = ("url", "uri", "href", "endpoint", "link")
#: ``scheme://[userinfo@]host`` -- the host class excludes everything a host
#: cannot contain, so the scan is a single linear pass.
_URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{0,15}://([^\s/?#'\"<>`]{1,253})")
_SCP = re.compile(r"\b[A-Za-z0-9._-]{1,64}@([A-Za-z0-9.-]{1,253}):")
_PATCH_FILE = re.compile(
    r"^(?:\*\*\* (?:Add|Update|Delete) File: |\+\+\+ (?:b/)?)(\S[^\n]{0,1023})$"
)


def _strings(value: Any, limit: int = 256) -> Iterable[str]:
    stack, seen = [value], 0
    while stack and seen < limit:
        item = stack.pop()
        seen += 1
        if isinstance(item, str):
            yield item
        elif isinstance(item, list):
            stack.extend(item[:limit])
        elif isinstance(item, dict):
            stack.extend(list(item.values())[:limit])


def arg_paths(arguments: Any) -> list[str]:
    found: list[str] = []
    if isinstance(arguments, dict):
        for key in _PATH_KEYS:
            if key in arguments:
                found.extend(_strings(arguments[key]))
        patch = arguments.get("patch") or arguments.get("input") or arguments.get("diff")
        if isinstance(patch, str) and ("*** " in patch or "+++ " in patch):
            for line in patch[: 1 << 20].splitlines()[:100_000]:
                if match := _PATCH_FILE.match(line):
                    found.append(match.group(1).strip())
    return _clean_paths(found)


def command_paths(command: str) -> list[str]:
    """Path-looking operands of a command line (``/x``, ``./x``, ``~/x``, ``a/b``)."""
    found = [
        token
        for token in _tokens(command)[1:]
        if not token.startswith("-")
        and "://" not in token
        and (token.startswith(("/", "./", "../", "~")) or "/" in token)
    ]
    return _clean_paths(found)


def _clean_paths(paths: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for path in paths:
        cleaned = path.strip().strip("'\"")[:MAX_FIELD_CHARS]
        if cleaned and "\n" not in cleaned and "\0" not in cleaned:
            seen.setdefault(cleaned, None)
        if len(seen) >= MAX_PATHS:
            break
    return list(seen)


def hosts(*texts: str, arguments: Any = None) -> list[str]:
    found: dict[str, None] = {}
    sources = [text[: 1 << 20] for text in texts if text]
    if isinstance(arguments, dict):
        sources.extend(
            value[:4096] for key in _URL_KEYS for value in _strings(arguments.get(key), 16)
        )
    for text in sources:
        for match in _URL.finditer(text):
            host = _host_of(match.group(0))
            if host:
                found.setdefault(host, None)
        for match in _SCP.finditer(text):
            found.setdefault(match.group(1).lower().rstrip("."), None)
        if len(found) >= MAX_HOSTS:
            break
    return list(found)[:MAX_HOSTS]


def _host_of(url: str) -> str:
    """The host of ``scheme://[userinfo@]host[:port]``, parsed by hand.

    ``urlsplit`` rejects ``u:[REDACTED]@host`` -- the redaction label looks
    like an IPv6 bracket -- so a URL with a password lost its host, and with
    it every ``host=`` policy rule. The host is the authority after its last
    ``@``; a bracketed IPv6 address only counts at the start of the host.
    """
    authority = url.split("://", 1)[-1]
    for stop in "/?#":
        authority = authority.split(stop, 1)[0]
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    else:
        host = host.split(":", 1)[0]
    return host.lower().rstrip(".")[:253]


__all__ = ["arg_paths", "command_paths", "hosts"]
