"""What ``tine publish zenodo`` and ``tine publish hf`` share (0.49).

Both refuse unredacted content with the 0.45 push gate (:mod:`opentine._push_gate`)
before any request is built, and both record what they published in the op log
(:func:`record`). A token comes only from an environment variable and travels
only in a request header to the configured API host; a URL the server hands
back is checked against that host before the token is sent to it. A failure
names the step and the HTTP status, never a header, a body or a token.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlsplit

from opentine.redaction import redact_blob


class PublishError(RuntimeError):
    """A publish step failed; the message names the step and HTTP status only."""


def client() -> Any:
    """The HTTP session (tests replace this with an in-process fake server)."""
    import httpx

    return httpx.Client(timeout=120, follow_redirects=False)


def token(env_name: str) -> str:
    value = os.environ.get(env_name, "")
    if not value.strip():
        raise PublishError(f"no token: set the {env_name} environment variable")
    return value.strip()


def api_base(url: str) -> str:
    """An https API root with a host and no credentials, query, fragment or dot segment."""
    parts = urlsplit(url.strip())
    if (
        parts.scheme != "https"
        or not parts.hostname
        or "@" in parts.netloc
        or parts.query
        or parts.fragment
        or any(seg in (".", "..") for seg in parts.path.split("/"))
        or any(ch.isspace() or ord(ch) < 32 for ch in url)
    ):
        raise PublishError("--api-url must be an https URL with no credentials, query or '..'")
    return url.strip().rstrip("/")


def same_host(url: Any, base: str, step: str) -> str:
    """*url* (from a server answer) when it is https on *base*'s host: the token goes there."""
    if not isinstance(url, str):
        raise PublishError(f"{step} failed: the answer names no URL")
    parts, home = urlsplit(url), urlsplit(base)
    if parts.scheme != "https" or parts.netloc != home.netloc or "@" in parts.netloc:
        raise PublishError(f"{step} failed: the server named a URL off its own host")
    return url


def expect(answer: Any, step: str, codes: tuple[int, ...] = (200, 201)) -> Any:
    if answer.status_code not in codes:
        raise PublishError(f"{step} failed: HTTP {answer.status_code}")
    try:
        return answer.json() if answer.content else None
    except ValueError as exc:
        raise PublishError(f"{step} failed: the answer is not JSON") from exc


def file_name(name: str) -> str:
    """A plain file name for a deposited file (no directories, no leading dot)."""
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", name) or ".." in name:
        raise PublishError(f"not a plain file name: {name!r}")
    return name


def bundle_objects(repo: Any, tips: list[str]) -> set[str]:
    """Every object a bundle of *tips* carries (what the gate scans)."""
    from opentine.repository._pack_fit import fitted_pack

    return set(fitted_pack(repo, sorted(set(tips)), [])[1])


def gated_bundle(repo: Any, refs: list[str], allow_reason: str | None) -> tuple[bytes, Any]:
    """Bundle *refs*, refusing (``ValueError``) when its objects fail the push gate."""
    from opentine import _bundle
    from opentine._push_gate import Gate

    data = _bundle.create(repo, refs or None)
    checked = _bundle.verify(data)
    Gate(repo, allow_reason)(bundle_objects(repo, list(checked.refs.values())))
    return data, checked


def gated_file(repo: Any, name: str, data: bytes, allow_reason: str | None) -> None:
    """Refuse an attached file the current ruleset would still redact, unless overridden."""
    if redact_blob(data) == data:
        return
    if allow_reason is None:
        raise ValueError(
            f"publish refused: {name} fails the redaction scan; redact it, or pass "
            "--allow-unredacted REASON to publish anyway"
        )
    record(repo, f"allow-unredacted: {allow_reason.strip()} (attachment {name})")


def record(repo: Any, text: str) -> None:
    """Log *text* (redacted, like any stored string) as an op-log entry of its own."""
    from opentine.repository._oplog import note

    note(redact_blob(text.encode("utf-8")).decode("utf-8", "replace"), base=repo.path)


__all__ = [
    "PublishError",
    "api_base",
    "bundle_objects",
    "client",
    "expect",
    "file_name",
    "gated_bundle",
    "gated_file",
    "record",
    "same_host",
    "token",
]
