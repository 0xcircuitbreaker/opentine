"""Format v5 ``.tine``: format v4 with text blobs spelled as JSON strings (SPEC Part 10).

A v5 document is a v4 document (SPEC Part 9) with ``format_version`` 5 and kind
``tine-artifact/5``, in which every raw blob whose bytes are well-formed UTF-8
(RFC 3629) is spelled ``{"encoding": "text", "schema": N, "type": "blob",
"text": S}`` instead of ``{"encoding": "raw", ..., "data": <base64>}``. The
spelling is transport only: the stored envelope is unchanged (its header still
says ``"encoding": "raw"`` and its body is ``S`` encoded as UTF-8), so every
oid, the root and every ``tine-sig/3`` signature (which signs the v4 view) are
identical in both formats. Exactly one spelling is legal per blob: ``text``
when the bytes decode, ``raw`` (canonical base64) only when they do not.

Readers convert a v5 document to its v4 form with :func:`to_v4` and run the v4
reader on it. Standard library only: the offline ``tine-verify.pyz`` vendors
this module verbatim.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

ARTIFACT_V5_VERSION = 5
ARTIFACT_V5_KIND = "tine-artifact/5"
_V4_VERSION, _V4_KIND = 4, "tine-artifact/4"
_TEXT_KEYS = frozenset({"encoding", "schema", "type", "text"})


def is_v5_artifact(data: Any) -> bool:
    """Detect a v5 bundle by its version *and* kind, never by one alone."""
    return (
        isinstance(data, dict)
        and type(data.get("format_version")) is int
        and data.get("format_version") == ARTIFACT_V5_VERSION
        and data.get("kind") == ARTIFACT_V5_KIND
    )


def utf8_text(body: bytes) -> str | None:
    """*body* as text when it is well-formed UTF-8 (no surrogates, no overlongs)."""
    try:
        return body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _entry_to_v4(entry: Any, where: str) -> Any:
    if not isinstance(entry, dict):
        return entry  # the v4 reader names the malformed envelope
    if entry.get("encoding") == "text":
        if set(entry) != _TEXT_KEYS or entry.get("type") != "blob":
            raise ValueError(f"{where}: a v5 text envelope is encoding, schema, type=blob and text")
        text = entry["text"]
        if not isinstance(text, str):
            raise ValueError(f"{where}: v5 blob text must be a string")
        try:
            body = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError(f"{where}: v5 blob text holds a lone surrogate") from exc
        data = base64.b64encode(body).decode("ascii")
        return {"data": data, "encoding": "raw", "schema": entry["schema"], "type": "blob"}
    if entry.get("encoding") == "raw" and isinstance(entry.get("data"), str):
        try:
            body = base64.b64decode(entry["data"].encode("ascii"), validate=True)
        except (binascii.Error, UnicodeError, ValueError):
            return entry  # the v4 reader refuses non-canonical base64 itself
        if utf8_text(body) is not None:
            raise ValueError(f"{where}: UTF-8 text must be spelled as v5 text, not base64")
    return entry


def to_v4(data: dict[str, Any]) -> dict[str, Any]:
    """The v4 document a v5 document spells; ``ValueError`` if a spelling is not v5's."""
    if not is_v5_artifact(data):
        raise ValueError(f"not a format v5 artifact (kind {ARTIFACT_V5_KIND!r})")
    objects = data.get("objects")
    if isinstance(objects, dict):
        objects = {oid: _entry_to_v4(e, f"objects[{oid}]") for oid, e in objects.items()}
    return {**data, "format_version": _V4_VERSION, "kind": _V4_KIND, "objects": objects}


def as_v4(data: Any) -> Any:
    """*data* unchanged unless it is a v5 document, which is converted to v4."""
    return to_v4(data) if is_v5_artifact(data) else data


def _entry_to_v5(entry: dict[str, Any]) -> dict[str, Any]:
    if entry.get("encoding") != "raw" or entry.get("type") != "blob":
        return entry
    text = utf8_text(base64.b64decode(entry["data"], validate=True))
    if text is None:
        return entry
    return {"encoding": "text", "schema": entry["schema"], "text": text, "type": "blob"}


def to_v5(data: dict[str, Any]) -> dict[str, Any]:
    """The v5 spelling of a (valid) v4 document; signatures carry over unchanged."""
    if data.get("format_version") != _V4_VERSION or data.get("kind") != _V4_KIND:
        raise ValueError("to_v5 converts format v4 artifacts only")
    objects = {oid: _entry_to_v5(entry) for oid, entry in data["objects"].items()}
    version = {"format_version": ARTIFACT_V5_VERSION, "kind": ARTIFACT_V5_KIND}
    return {**data, **version, "objects": objects}


__all__ = [
    "ARTIFACT_V5_KIND",
    "ARTIFACT_V5_VERSION",
    "as_v4",
    "is_v5_artifact",
    "to_v4",
    "to_v5",
    "utf8_text",
]
