"""An evidence folder (``tine evidence export``): manifest, custody and every run.

The checks and reason codes are ``docs/conformance/minimal_verifier.py``'s:
``MANIFEST.sha256`` lists every file but itself and ``custody.jsonl``;
the custody record names the manifest's SHA-256 and may carry an Ed25519
signature over ``b"opentine.custody.v1:"`` + JCS of the record without it;
each ``runs/*.tine`` gets the artifact checks.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .. import kernel
from .._ed25519_order import weak_public_key
from . import _ed25519, _load
from ._artifact import check

CUSTODY_DOMAIN = b"opentine.custody.v1:"
UNLISTED = ("MANIFEST.sha256", "custody.jsonl")


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest(root: Path) -> tuple[list[dict[str, Any]], bytes]:
    try:
        text = (root / "MANIFEST.sha256").read_bytes()
        listed: dict[str, str] = {}
        for line in text.decode("utf-8").splitlines():
            digest, rel = line.split("  ", 1)
            listed[rel] = digest
    except (OSError, ValueError) as exc:
        return [check("manifest", "fail", "evidence.manifest-unreadable", str(exc))], b""
    files = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    on_disk = files - set(UNLISTED)
    bad = sorted(
        rel
        for rel, digest in listed.items()
        if rel not in on_disk or ".." in rel.split("/") or _sha(root / rel) != digest
    )
    extra = sorted(on_disk - set(listed))
    ok = not bad and not extra
    detail = f"{len(listed)} file(s); changed or missing: {bad or 'none'}; unlisted: {extra}"
    reason = "evidence.manifest-match" if ok else "evidence.manifest-mismatch"
    return [check("manifest", "pass" if ok else "fail", reason, detail)], text


def _custody(root: Path, manifest: bytes) -> list[dict[str, Any]]:
    try:
        record = _load.parse((root / "custody.jsonl").read_bytes().splitlines()[0])
        if not isinstance(record, dict):
            raise ValueError("custody record is not an object")
    except (OSError, ValueError, IndexError) as exc:
        return [check("custody", "fail", "evidence.custody-unreadable", str(exc))]
    linked = record.get("manifest_sha256") == hashlib.sha256(manifest).hexdigest()
    reason = "evidence.custody-linked" if linked else "evidence.custody-manifest-mismatch"
    first = check("custody", "pass" if linked else "fail", reason, "manifest_sha256 vs MANIFEST")
    block = record.get("signature")
    if not isinstance(block, dict):
        return [first, check("custody-signature", "not-applicable", "signature.unsigned", "-")]
    body = {k: v for k, v in record.items() if k != "signature"}
    try:
        public = bytes.fromhex(block["public_key"])
        good = not weak_public_key(public) and _ed25519.verify(
            public, CUSTODY_DOMAIN + kernel.canonical_json(body), bytes.fromhex(block["value"])
        )
    except (KeyError, TypeError, ValueError):
        good = False
    if not good:
        return [first, check("custody-signature", "fail", "signature.mismatch", "does not verify")]
    detail = f"under its own key {block['public_key'][:16]}... (compare trust/custody-signer.pub)"
    return [first, check("custody-signature", "pass", "signature.verified-tofu", detail)]


def verify_evidence(root: Path, verify_run: Callable[[Path], dict[str, Any]]) -> dict[str, Any]:
    """Every evidence check, then each run's own report under ``runs``."""
    checks, manifest = _manifest(root)
    checks += _custody(root, manifest)
    runs = []
    for path in sorted(p for p in (root / "runs").rglob("*.tine") if p.is_file()):
        report = verify_run(path)
        rel = path.relative_to(root).as_posix()
        runs.append({**report, "path": rel})
        outcome = "pass" if report["ok"] else "fail"
        checks.append(check(f"run:{rel}", outcome, "evidence.run", report["verdict"]))
    if not runs:
        checks.append(check("runs", "fail", "evidence.no-runs", "runs/ holds no .tine file"))
    return {"checks": checks, "runs": runs}


__all__ = ["verify_evidence"]
