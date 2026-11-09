"""``opentine.forge-check``: what ``tine forge publish`` posts to a forge (0.48, SPEC 4.24).

One unsigned, canonical-JSON record per commit, the same for every forge::

    {"kind": "opentine.forge-check", "check_version": 1,
     "forge": "github"|"gitlab"|"forgejo"|"entire", "forge_repo_id": ID,
     "project_id": ID|null, "commit": 40|64 hex,
     "verify": {"state": "verified"|"failed"|"unverified", "runs": N},
     "ai": {"ai_lines": N, "total_lines": N, "share_ppm": N},
     "bundle": {"url": "https://..."|null, "digest": "sha256:<hex>"|null},
     "overlay": [{"path", "start_line", "end_line", "run"}, ...],
     "conclusion": "success"|"failure"|"neutral"}

The record carries no authority of its own: the forge shows it, and a reader
who wants proof downloads the bundle, checks it against ``digest`` and runs
``tine bundle verify`` (or the pyz / TS verifier) offline. ``share_ppm`` is
``ai_lines * 1_000_000 // total_lines`` (0 when there are no lines), so no
float crosses the wire. ``conclusion`` follows ``verify.state`` alone:
verified -> success, failed -> failure, unverified -> neutral.

:func:`check` refuses, with the first applicable code: ``forge-check.malformed``,
``forge-check.share-mismatch``, ``forge-check.conclusion-mismatch`` and
``forge-check.bundle-mismatch`` (bundle bytes given that do not hash to
``digest``). Reference for ``forge-check.verify`` (``vectors/73-forge-check.json``).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from opentine._signed_record import RecordError
from opentine.kernel import canonical_json

KIND = "opentine.forge-check"
FIELDS = (
    "kind",
    "check_version",
    "forge",
    "forge_repo_id",
    "project_id",
    "commit",
    "verify",
    "ai",
    "bundle",
    "overlay",
    "conclusion",
)
FORGES = ("github", "gitlab", "forgejo", "entire")
CONCLUSIONS = {"verified": "success", "failed": "failure", "unverified": "neutral"}
MAX_OVERLAY = 50
_REPO_ID = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_URL = re.compile(r"https://[A-Za-z0-9._~:/?#@!$&*+,;=%-]{1,2040}")
_RUN = re.compile(r"[A-Za-z0-9_.:-]{1,128}")


def _refuse(code: str, message: str) -> RecordError:
    return RecordError(f"forge-check.{code}", message)


def _bad(what: str) -> RecordError:
    return _refuse("malformed", f"forge check is malformed: {what}")


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 1 << 53


def share_ppm(ai_lines: int, total_lines: int) -> int:
    return ai_lines * 1_000_000 // total_lines if total_lines else 0


def _keys(value: Any, keys: tuple[str, ...], what: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise _bad(f"wrong set of {what} fields")
    return value


def _overlay(rows: Any) -> None:
    if not isinstance(rows, list) or len(rows) > MAX_OVERLAY:
        raise _bad("overlay is not a list of at most 50 ranges")
    for row in rows:
        row = _keys(row, ("path", "start_line", "end_line", "run"), "overlay")
        path = row["path"]
        if (
            not isinstance(path, str)
            or not 0 < len(path) <= 1024
            or path.startswith("/")
            or "\\" in path
            or ".." in path.split("/")
            or "\0" in path
        ):
            raise _bad("overlay path is not a relative posix path")
        start, end = row["start_line"], row["end_line"]
        if not (_count(start) and _count(end) and 1 <= start <= end):
            raise _bad("overlay lines are not 1 <= start_line <= end_line")
        if row["run"] is not None and not (
            isinstance(row["run"], str) and _RUN.fullmatch(row["run"])
        ):
            raise _bad("overlay run is not a run id")


def body(record: Any) -> dict[str, Any]:
    """*record* after the field rules, or ``forge-check.malformed``."""
    if not isinstance(record, dict) or record.get("kind") != KIND or set(record) != set(FIELDS):
        raise _bad("wrong kind or set of fields")
    version = record["check_version"]
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        raise _bad("check_version is not 1")
    if record["forge"] not in FORGES:
        raise _bad("unknown forge")
    for name, pattern in (("forge_repo_id", _REPO_ID), ("commit", _COMMIT)):
        if not isinstance(record[name], str) or not pattern.fullmatch(record[name]):
            raise _bad(f"bad {name}")
    project = record["project_id"]
    if project is not None and not (isinstance(project, str) and _ID.fullmatch(project)):
        raise _bad("bad project_id")
    verify = _keys(record["verify"], ("state", "runs"), "verify")
    if verify["state"] not in CONCLUSIONS or not _count(verify["runs"]):
        raise _bad("bad verify state or run count")
    ai = _keys(record["ai"], ("ai_lines", "total_lines", "share_ppm"), "ai")
    if not all(_count(ai[name]) for name in ai):
        raise _bad("ai counts are not non-negative integers")
    bundle = _keys(record["bundle"], ("url", "digest"), "bundle")
    url, digest = bundle["url"], bundle["digest"]
    if digest is not None and not (isinstance(digest, str) and _DIGEST.fullmatch(digest)):
        raise _bad("bundle digest is not sha256:<64 hex>")
    if url is not None and not (isinstance(url, str) and _URL.fullmatch(url)):
        raise _bad("bundle url is not an https URL")
    if url is not None and digest is None:
        raise _bad("a bundle url without a digest cannot be checked offline")
    _overlay(record["overlay"])
    if record["conclusion"] not in ("success", "failure", "neutral"):
        raise _bad("unknown conclusion")
    return {name: record[name] for name in FIELDS}


def check(record: Any, bundle: bytes | None = None) -> dict[str, Any]:
    """``{commit, forge, forge_repo_id, project_id, conclusion, share_ppm, bundle}``.

    ``bundle`` in the result is ``matched`` (bytes given and they hash to the
    digest), ``unchecked`` (a digest, no bytes) or ``absent`` (neither).
    """
    found = body(record)
    ai = found["ai"]
    if ai["ai_lines"] > ai["total_lines"]:
        raise _refuse(
            "share-mismatch", "forge check share does not match: more AI lines than lines"
        )
    if ai["share_ppm"] != share_ppm(ai["ai_lines"], ai["total_lines"]):
        raise _refuse("share-mismatch", "forge check share does not match its line counts")
    if found["conclusion"] != CONCLUSIONS[found["verify"]["state"]]:
        raise _refuse(
            "conclusion-mismatch", "forge check conclusion does not follow its verify state"
        )
    digest = found["bundle"]["digest"]
    state = "absent" if digest is None else "unchecked"
    if bundle is not None:
        if digest != "sha256:" + hashlib.sha256(bundle).hexdigest():
            raise _refuse("bundle-mismatch", "forge check bundle does not hash to its digest")
        state = "matched"
    return {
        "commit": found["commit"],
        "forge": found["forge"],
        "forge_repo_id": found["forge_repo_id"],
        "project_id": found["project_id"],
        "conclusion": found["conclusion"],
        "share_ppm": ai["share_ppm"],
        "bundle": state,
    }


def build(
    *,
    forge: str,
    forge_repo_id: str,
    project_id: str | None,
    commit: str,
    verify_state: str,
    runs: int,
    ai_lines: int,
    total_lines: int,
    bundle_url: str | None = None,
    bundle_digest: str | None = None,
    overlay: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    record = {
        "kind": KIND,
        "check_version": 1,
        "forge": forge,
        "forge_repo_id": forge_repo_id,
        "project_id": project_id,
        "commit": commit,
        "verify": {"state": verify_state, "runs": runs},
        "ai": {
            "ai_lines": ai_lines,
            "total_lines": total_lines,
            "share_ppm": share_ppm(ai_lines, total_lines),
        },
        "bundle": {"url": bundle_url, "digest": bundle_digest},
        "overlay": list(overlay or [])[:MAX_OVERLAY],
        "conclusion": CONCLUSIONS.get(verify_state, "neutral"),
    }
    check(record)
    return record


def encode(record: dict[str, Any]) -> bytes:
    return canonical_json(body(record)) + b"\n"


def percent(ppm: int) -> str:
    """``share_ppm`` as a percentage with two decimals, without floats."""
    return f"{ppm // 10000}.{ppm // 100 % 100:02d}%"


__all__ = [
    "CONCLUSIONS",
    "FIELDS",
    "FORGES",
    "KIND",
    "MAX_OVERLAY",
    "body",
    "build",
    "check",
    "encode",
    "percent",
    "share_ppm",
]
