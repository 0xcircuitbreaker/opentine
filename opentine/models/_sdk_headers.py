"""Headers the provider SDKs add on their own from the environment.

Anthropic's and OpenAI's Python SDKs parse ``ANTHROPIC_CUSTOM_HEADERS`` and
``OPENAI_CUSTOM_HEADERS`` ("Name: value" per line) into headers sent on every
request, and OpenAI's also sends ``OPENAI_ORG_ID``/``OPENAI_PROJECT_ID``. Those
variables commonly carry gateway credentials meant for the first-party API or the
operator's own ``*_BASE_URL`` gateway, so a client built for a compatible server,
a local preset or an explicit ``--base-url`` cancels every one of them (the SDKs
drop a header whose value is ``Omit``). Where they are still sent, they obey the
cleartext rule an API key does.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlsplit

from opentine.models._endpoint_security import require_key_transport

ANTHROPIC = "ANTHROPIC_CUSTOM_HEADERS"
OPENAI = "OPENAI_CUSTOM_HEADERS"
#: What the OpenAI SDK fills from ``OPENAI_ORG_ID`` / ``OPENAI_PROJECT_ID``.
OPENAI_IDENTITY = ("OpenAI-Organization", "OpenAI-Project")
_OPENAI_HOST = re.compile(r"(?:(?:us|eu|au|ca|jp|in|sg|kr|gb|ae)\.)?api\.openai\.com")


def parsed(variable: str) -> dict[str, str]:
    """The headers the SDK parses from *variable*, with the SDK's own parser."""
    raw = os.environ.get(variable)
    headers: dict[str, str] = {}
    for line in (raw or "").split("\n"):
        colon = line.find(":")
        if colon >= 0:
            headers[line[:colon].strip()] = line[colon + 1 :].strip()
    return headers


def cancelled(variable: str, omit: Any, extra: tuple[str, ...] = ()) -> dict[str, Any]:
    """``default_headers`` that cancel every header the SDK would add from *variable*."""
    return {name: omit for name in (*parsed(variable), *extra)}


def require_transport(variable: str, url: str | None) -> None:
    """Refuse to send *variable*'s header values in cleartext to another machine."""
    for value in parsed(variable).values():
        require_key_transport(url, value)


def openai_first_party(url: str | None) -> bool:
    """Whether *url* is OpenAI's own API (or unset: the SDK's default or the env pairing)."""
    if not url:
        return True
    host = (urlsplit(url.strip()).hostname or "").lower().rstrip(".")
    return bool(_OPENAI_HOST.fullmatch(host))


def openai_headers(omit: Any, url: str | None, *, keep_env: bool) -> dict[str, Any] | None:
    """``default_headers`` for an OpenAI SDK client aimed at *url*."""
    if keep_env:
        require_transport(OPENAI, url)
        return None
    return cancelled(OPENAI, omit, OPENAI_IDENTITY)


__all__ = [
    "ANTHROPIC",
    "OPENAI",
    "OPENAI_IDENTITY",
    "cancelled",
    "openai_first_party",
    "openai_headers",
    "parsed",
    "require_transport",
]
