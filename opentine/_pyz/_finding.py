"""Review findings with the standard library (0.48, SPEC 4.25).

An independent port, for ``tine-verify.pyz``, of ``opentine._review_finding.check``:
exactly the kind's fields, then a ``tine-sig/3`` Ed25519 block over
``opentine.review-finding.v1:`` + JCS of ``{"body", "header"}``. ``tine-verify.pyz
FILE`` takes one finding or a list of them (what ``.tine/review-findings/<id>.json``
holds); each one gets its own check row.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ._artifact import check as row
from ._gitobj import Refused
from ._project import _signed, digest

KIND = "opentine.review-finding"
_FIELDS = ("kind", "finding_version", "review_id", "finding_id", "severity", "path", "line",
           "message", "reviewer", "run", "created_at")  # fmt: skip
_SEVERITIES = ("info", "low", "medium", "high", "critical")
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_PATH = re.compile(r"[A-Za-z0-9_.@+-][A-Za-z0-9_.@+/ -]{0,1023}")
_NAME = re.compile(r"[A-Za-z0-9_.:/@+-]{1,256}")
_RUN = re.compile(r"run:sha256:[0-9a-f]{64}")
_WHEN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _is(value: Any, pattern: re.Pattern) -> bool:
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def _path_ok(value: Any) -> bool:
    return _is(value, _PATH) and all(p not in ("", ".", "..") for p in value.split("/"))


def _text_ok(value: Any) -> bool:
    return (isinstance(value, str) and bool(value.strip())
            and len(value.encode("utf-8", "surrogatepass")) <= 1024
            and not _CONTROL.search(value))  # fmt: skip


def finding_verify(record: Any, public_key: bytes | None = None, reviewers: Any = ()) -> dict:
    """SPEC 4.25: ``{review_id, finding_id, severity, path, line, digest, signer, state}``."""
    if not isinstance(record, dict) or record.get("kind") != KIND:
        raise Refused(
            "review-finding.malformed", f"review finding is malformed: kind is not {KIND}"
        )
    if set(record) - {*_FIELDS, "signature"} or set(_FIELDS) - set(record):
        raise Refused(
            "review-finding.malformed", "review finding is malformed: wrong set of fields"
        )
    body = {name: record[name] for name in _FIELDS}
    path, line, run = body["path"], body["line"], body["run"]
    checks = (
        (type(body["finding_version"]) is int and body["finding_version"] == 1, "finding_version"),
        (_is(body["review_id"], _ID) and _is(body["finding_id"], _ID), "ids"),
        (body["severity"] in _SEVERITIES, "severity"),
        (path is None or _path_ok(path), "path"),
        (line is None or (type(line) is int and 1 <= line <= 2**31 - 1 and path is not None),
         "line"),
        (_text_ok(body["message"]), "message"),
        (_is(body["reviewer"], _NAME), "reviewer"),
        (run is None or _is(run, _RUN), "run"),
        (_is(body["created_at"], _WHEN), "created_at must be an RFC 3339 UTC time"),
    )  # fmt: skip
    for ok, message in checks:
        if not ok:
            raise Refused("review-finding.malformed", f"review finding is malformed: {message}")
    signer = _signed(record, body, b"opentine.review-finding.v1:", "review-finding",
                     "review finding", public_key)  # fmt: skip
    members = set(reviewers or ())
    if members and signer not in members:
        raise Refused(
            "review-finding.untrusted-signer", "the review finding's signer is not a reviewer"
        )
    state = "verified" if public_key is not None or members else "verified-tofu"
    return {"review_id": body["review_id"], "finding_id": body["finding_id"],
            "severity": body["severity"], "path": path, "line": line,
            "digest": digest(record), "signer": signer, "state": state}  # fmt: skip


def _load(path: Path) -> Any:
    return json.loads(path.read_text("utf-8"))


def is_finding(path: Path) -> bool:
    """*path* holds one review finding, or a non-empty list of them."""
    if path.suffix != ".json" or not path.is_file() or path.stat().st_size > 16 << 20:
        return False
    try:
        value = _load(path)
    except (OSError, ValueError, RecursionError):
        return False
    first = value[0] if isinstance(value, list) and value else value
    return isinstance(first, dict) and first.get("kind") == KIND


def verify(path: Path, public_key: bytes | None) -> list[dict[str, Any]]:
    value = _load(path)
    rows = []
    for record in value if isinstance(value, list) else [value]:
        try:
            found = finding_verify(record, public_key)
        except Refused as exc:
            rows.append(row("review-finding", "fail", exc.code, str(exc)))
            continue
        rows.append(row("review-finding", "pass", "review-finding.verified", KIND, **found))
    return rows


__all__ = ["finding_verify", "is_finding", "verify"]
