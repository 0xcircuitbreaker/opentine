"""SPEC 4.24 forge checks (0.48): what ``tine forge publish`` shows on a forge.

The record is unsigned; a verifier checks its shape, that the share and the
conclusion follow from its own fields, and, given the linked bundle's bytes,
that they hash to its digest. Only ``adapter_project`` answers.
"""

from __future__ import annotations

import base64
import hashlib

from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V
from tests.conformance.cases_project import VERIFIER

BUNDLE = b"TINEBNDL" + bytes(range(64))
DIGEST = "sha256:" + hashlib.sha256(BUNDLE).hexdigest()
COMMIT = "3f" * 20
CHECK = {
    "kind": "opentine.forge-check",
    "check_version": 1,
    "forge": "github",
    "forge_repo_id": "123456",
    "project_id": "app",
    "commit": COMMIT,
    "verify": {"state": "verified", "runs": 2},
    "ai": {"ai_lines": 37, "total_lines": 120, "share_ppm": 308333},
    "bundle": {"url": "https://example.com/evidence/app.tbundle", "digest": DIGEST},
    "overlay": [{"path": "src/app.py", "start_line": 3, "end_line": 9, "run": "run-1"}],
    "conclusion": "success",
}


def _with(**changes) -> dict:
    return {**CHECK, **changes}


def _f(name, expect, intent, check, reason=None, *, bundle: bytes | None = None) -> Case:
    value = {
        "check": check,
        "bundle_b64": None if bundle is None else base64.b64encode(bundle).decode(),
    }
    return Case(
        id=f"forge-check.{name}",
        section="4.24",
        checklist=(8,),
        op="forge-check.verify",
        profile=VERIFIER,
        expect=expect,
        intent=intent,
        input=V(value),
        reason=reason,
    )


FORGE_CHECK = Family(
    "73-forge-check.json",
    "4.24",
    "forge-check",
    (
        _f("verified", ACCEPT, "a verified commit with its bundle digest (bytes not given)", CHECK),
        _f(
            "bundle-matched",
            ACCEPT,
            "the linked bundle's bytes hash to the digest",
            CHECK,
            bundle=BUNDLE,
        ),
        _f(
            "unverified-neutral",
            ACCEPT,
            "no verify output: neutral, never success",
            _with(
                verify={"state": "unverified", "runs": 0},
                conclusion="neutral",
                bundle={"url": None, "digest": None},
            ),
        ),
        _f(
            "failed-failure",
            ACCEPT,
            "a failed verify: failure",
            _with(
                verify={"state": "failed", "runs": 1},
                conclusion="failure",
                forge="gitlab",
                project_id=None,
            ),
        ),
        _f(
            "no-lines",
            ACCEPT,
            "no lines at the commit: share 0, no division",
            _with(
                ai={"ai_lines": 0, "total_lines": 0, "share_ppm": 0},
                overlay=[],
                forge="entire",
                commit="ab" * 32,
            ),
        ),
        _f(
            "bundle-mismatch",
            REJECT,
            "bytes that are not the linked bundle",
            CHECK,
            "forge-check.bundle-mismatch",
            bundle=BUNDLE + b"!",
        ),
        _f(
            "share-rounded-up",
            REJECT,
            "share_ppm is the floor, not a rounding",
            _with(ai={"ai_lines": 37, "total_lines": 120, "share_ppm": 308334}),
            "forge-check.share-mismatch",
        ),
        _f(
            "share-over-total",
            REJECT,
            "more AI lines than lines",
            _with(ai={"ai_lines": 5, "total_lines": 4, "share_ppm": 1250000}),
            "forge-check.share-mismatch",
        ),
        _f(
            "unverified-success",
            REJECT,
            "an unverified commit shown as a success",
            _with(verify={"state": "unverified", "runs": 0}),
            "forge-check.conclusion-mismatch",
        ),
        _f(
            "failed-neutral",
            REJECT,
            "a failed verify softened to neutral",
            _with(verify={"state": "failed", "runs": 1}, conclusion="neutral"),
            "forge-check.conclusion-mismatch",
        ),
        _f(
            "url-without-digest",
            REJECT,
            "a link that cannot be checked offline",
            _with(bundle={"url": "https://example.com/b", "digest": None}),
            "forge-check.malformed",
        ),
        _f(
            "http-url",
            REJECT,
            "a bundle link is https",
            _with(bundle={"url": "http://example.com/b", "digest": DIGEST}),
            "forge-check.malformed",
        ),
        _f(
            "overlay-escape",
            REJECT,
            "an overlay path that leaves the repository",
            _with(overlay=[{"path": "../etc/passwd", "start_line": 1, "end_line": 1, "run": None}]),
            "forge-check.malformed",
        ),
        _f(
            "overlay-reversed",
            REJECT,
            "an overlay range whose end precedes its start",
            _with(overlay=[{"path": "a.py", "start_line": 9, "end_line": 3, "run": None}]),
            "forge-check.malformed",
        ),
        _f(
            "signed",
            REJECT,
            "a forge check is unsigned: extra fields are refused",
            {**CHECK, "signature": {"alg": "ed25519"}},
            "forge-check.malformed",
        ),
        _f(
            "bad-version",
            REJECT,
            "check_version is 1",
            _with(check_version=2),
            "forge-check.malformed",
        ),
        _f(
            "unknown-forge",
            REJECT,
            "a forge outside the four",
            _with(forge="bitbucket"),
            "forge-check.malformed",
        ),
        _f(
            "short-commit",
            REJECT,
            "a commit is a full 40 or 64 hex id",
            _with(commit="3f3f3f3"),
            "forge-check.malformed",
        ),
        _f(
            "bool-count",
            REJECT,
            "a count is an integer, not a boolean",
            _with(verify={"state": "verified", "runs": True}),
            "forge-check.malformed",
        ),
    ),
)

FAMILIES = (FORGE_CHECK,)
