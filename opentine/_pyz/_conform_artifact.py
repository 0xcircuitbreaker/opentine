"""The text, ``.tine`` reader and stored-object ops the pyz answers case by case (0.50).

``text.validate`` (SPEC 0.1), ``artifact.parse``, ``integrity.digest`` and
``integrity.verify`` (Part 3, Part 9). Before 0.50
the pyz checked these only as whole files; each op here uses the reader the
pyz's file check uses (:mod:`._load`, :mod:`._artifact`) and returns the
fields the vector pins.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .. import _tine_v5
from . import _artifact, _load, _sig


def parse(raw: bytes) -> Any:
    """``_artifact_io.parse_artifact_json``: the strict reader, v5 read as v4."""
    return _tine_v5.as_v4(_load.parse(raw))


def text_validate(raw: Any, value: Any, args: dict) -> dict:
    parsed = json.loads(raw)
    if _load.SURROGATE_BYTES.search(raw):
        _load._refuse_surrogates(parsed)
    return {}


def artifact_parse(raw: Any, value: Any, args: dict) -> dict:
    parsed = parse(raw)
    return {"top_level_keys": sorted(parsed) if isinstance(parsed, dict) else []}


def integrity_digest(raw: Any, value: Any, args: dict) -> dict:
    data = parse(raw)
    body = {k: v for k, v in data.items() if k != "metadata"}
    return {"digest": hashlib.sha256(_sig.canon_v2(body)).hexdigest()}


def _verdict(ok: bool, algorithm: Any, expected: Any, actual: Any, reason: str) -> dict:
    return {"ok": ok, "algorithm": algorithm, "expected": expected, "actual": actual,
            "reason": reason}  # fmt: skip


def integrity(data: Any) -> dict:
    """``_graph_serde.verify_integrity`` over a parsed document."""
    if not isinstance(data, dict):
        return _verdict(False, None, None, None, "artifact root is not an object")
    if _artifact.is_v4(data):
        root = data.get("root") if isinstance(data.get("root"), str) else None
        try:
            _artifact.read_v4(data)
        except (KeyError, RecursionError, TypeError, ValueError) as exc:
            return _verdict(False, "sha256", root, None, f"invalid v4 artifact: {exc}")
        return _verdict(True, "sha256", root, root, "ok")
    version = data.get("format_version")
    if type(version) is not int or version not in _artifact.SUPPORTED:
        found = version if version is not None else "missing"
        reason = f"unsupported .tine format_version={found!r}; supported {_artifact.SUPPORTED}"
        if isinstance(version, int) and not isinstance(version, bool) and version > 2:
            reason = f"unsupported .tine format_version={found}; written by a newer opentine"
        return _verdict(False, None, None, None, reason)
    meta = data.get("metadata")
    block = meta.get("integrity") if isinstance(meta, dict) else None
    if not isinstance(block, dict):
        return _verdict(False, None, None, None, "missing integrity digest")
    algorithm, expected = block.get("algorithm"), block.get("digest")
    if algorithm != "sha256":
        return _verdict(False, str(algorithm), expected, None, "unsupported algorithm")
    try:
        well_formed = isinstance(expected, str) and len(expected) == 64 and int(expected, 16) >= 0
    except ValueError:
        well_formed = False
    if not well_formed:
        return _verdict(False, "sha256", expected, None, "malformed digest")
    try:
        body = {k: v for k, v in data.items() if k != "metadata"}
        actual: Any = hashlib.sha256(_sig.canon_v2(body)).hexdigest()
    except (AttributeError, RecursionError, TypeError, ValueError):
        actual = None
    ok = actual == expected
    return _verdict(ok, "sha256", expected, actual, "ok" if ok else "digest mismatch")


def integrity_verify(raw: Any, value: Any, args: dict) -> dict:
    return integrity(parse(raw))


OPS = {
    "text.validate": text_validate,
    "artifact.parse": artifact_parse,
    "integrity.digest": integrity_digest,
    "integrity.verify": integrity_verify,
}

__all__ = ["OPS", "integrity", "parse"]
