"""Forge checks with the standard library (0.48, SPEC 4.24).

An independent port, for ``tine-verify.pyz``, of ``opentine._forge_check.check``:
the unsigned ``opentine.forge-check`` record ``tine forge publish`` posts, its
share and conclusion rules, and the linked bundle's digest when its bytes are
given.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from ._gitobj import Refused

KEYS = {
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
}
CONCLUSION = {"verified": "success", "failed": "failure", "unverified": "neutral"}
_URL = r"https://[A-Za-z0-9._~:/?#@!$&*+,;=%-]{1,2040}"


def _no(code: str, message: str) -> Refused:
    return Refused("forge-check." + code, message)


def _bad(what: str) -> Refused:
    return _no("malformed", "forge check is malformed: " + what)


def _n(value: Any) -> bool:
    return type(value) is int and 0 <= value < 2**53


def _obj(value: Any, keys: set, what: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise _bad("wrong set of " + what + " fields")
    return value


def _text(value: Any, pattern: str) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _overlay(rows: Any) -> None:
    if not isinstance(rows, list) or len(rows) > 50:
        raise _bad("overlay is not a list of at most 50 ranges")
    for row in rows:
        row = _obj(row, {"path", "start_line", "end_line", "run"}, "overlay")
        path = row["path"]
        if (
            not isinstance(path, str)
            or not 0 < len(path) <= 1024
            or path[0] == "/"
            or "\\" in path
            or "\0" in path
            or ".." in path.split("/")
        ):
            raise _bad("overlay path is not a relative posix path")
        if not (
            _n(row["start_line"])
            and _n(row["end_line"])
            and 1 <= row["start_line"] <= row["end_line"]
        ):
            raise _bad("overlay lines are not 1 <= start_line <= end_line")
        if row["run"] is not None and not _text(row["run"], r"[A-Za-z0-9_.:-]{1,128}"):
            raise _bad("overlay run is not a run id")


def _shape(c: Any) -> None:
    if not isinstance(c, dict) or c.get("kind") != "opentine.forge-check" or set(c) != KEYS:
        raise _bad("wrong kind or set of fields")
    if type(c["check_version"]) is not int or c["check_version"] != 1:
        raise _bad("check_version is not 1")
    if c["forge"] not in ("github", "gitlab", "forgejo", "entire"):
        raise _bad("unknown forge")
    if not _text(c["forge_repo_id"], r"[A-Za-z0-9_.:/-]{1,128}"):
        raise _bad("bad forge_repo_id")
    if not _text(c["commit"], r"[0-9a-f]{40}|[0-9a-f]{64}"):
        raise _bad("bad commit")
    if c["project_id"] is not None and not _text(c["project_id"], r"[a-z0-9][a-z0-9._-]{0,63}"):
        raise _bad("bad project_id")
    verify = _obj(c["verify"], {"state", "runs"}, "verify")
    if verify["state"] not in CONCLUSION or not _n(verify["runs"]):
        raise _bad("bad verify state or run count")
    ai = _obj(c["ai"], {"ai_lines", "total_lines", "share_ppm"}, "ai")
    if not all(_n(v) for v in ai.values()):
        raise _bad("ai counts are not non-negative integers")
    bundle = _obj(c["bundle"], {"url", "digest"}, "bundle")
    if bundle["digest"] is not None and not _text(bundle["digest"], r"sha256:[0-9a-f]{64}"):
        raise _bad("bundle digest is not sha256:<64 hex>")
    if bundle["url"] is not None and not _text(bundle["url"], _URL):
        raise _bad("bundle url is not an https URL")
    if bundle["url"] is not None and bundle["digest"] is None:
        raise _bad("a bundle url without a digest cannot be checked offline")
    _overlay(c["overlay"])
    if c["conclusion"] not in ("success", "failure", "neutral"):
        raise _bad("unknown conclusion")


def forge_check_verify(check: Any, bundle: bytes | None = None) -> dict:
    _shape(check)
    ai = check["ai"]
    if ai["ai_lines"] > ai["total_lines"]:
        raise _no("share-mismatch", "forge check share does not match: more AI lines than lines")
    want = ai["ai_lines"] * 1000000 // ai["total_lines"] if ai["total_lines"] else 0
    if ai["share_ppm"] != want:
        raise _no("share-mismatch", "forge check share does not match its line counts")
    if check["conclusion"] != CONCLUSION[check["verify"]["state"]]:
        raise _no("conclusion-mismatch", "forge check conclusion does not follow its verify state")
    digest = check["bundle"]["digest"]
    state = "absent" if digest is None else "unchecked"
    if bundle is not None:
        if digest != "sha256:" + hashlib.sha256(bundle).hexdigest():
            raise _no("bundle-mismatch", "forge check bundle does not hash to its digest")
        state = "matched"
    return {
        "commit": check["commit"],
        "forge": check["forge"],
        "forge_repo_id": check["forge_repo_id"],
        "project_id": check["project_id"],
        "conclusion": check["conclusion"],
        "share_ppm": ai["share_ppm"],
        "bundle": state,
    }


__all__ = ["forge_check_verify"]
