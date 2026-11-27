"""The signed region pin and its check (0.87): what an optimizer may not edit.

``tine integrity region-pin --glob G... --key KEY`` lays out every file under
the globs (:func:`opentine._regions.layout`) and files an existing
``attestation`` at ``.tine/integrity/regions.json`` whose claim follows
``opentine.integrity.regions/1``::

    {"schema": "opentine.integrity.regions/1", "globs": [...],
     "files": {PATH: {"sha256": HEX, "regions": N, "segments": [HEX, ...]}},
     "baseline_sha256": HEX}

It is signed with Ed25519 by a ``policy``-role key from the owner-pinned trust
bundle that is not an ``optimizer`` key (the same rule as the protected list);
any other signer pins nothing (``fail:regions-pin-unsigned``), and no pin is
``fail:regions-pin-missing``. :func:`check` lays out the working tree again and
reports edits outside regions, added or removed files and marker tampering.

``tine promote`` reads the policy key ``regions``: ``"advisory"`` (default:
findings are the advisory ``advisory:regions.outside-modified``, D12) or
``"required"`` (the default under ``profile = "rsi"``, which cannot lower it):
any finding refuses ``promote.region-modified``, and a missing or unsigned pin
refuses ``promote.regions-unpinned`` (fail closed).
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

from opentine._regions import compare, finding, layout

PIN = Path(".tine") / "integrity" / "regions.json"
SCHEMA = "opentine.integrity.regions/1"
MISSING = "fail:regions-pin-missing"
UNSIGNED = "fail:regions-pin-unsigned"
MODES = ("advisory", "required")
MAX_FILES = 100_000
_HEX = re.compile(r"[0-9a-f]{64}")
_SKIP = {".git", ".tine"}


def _files(root: Path, globs: list[str]) -> dict[str, bytes]:
    from opentine._integrity import matches

    out: dict[str, bytes] = {}
    for top, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP)
        for name in sorted(names):
            full = Path(top) / name
            rel = full.relative_to(root).as_posix()
            if not any(matches(g, rel) for g in globs):
                continue
            if full.is_symlink():  # a link is its target text, never followed
                out[rel] = b"symlink:" + os.fsencode(os.readlink(full))
            else:
                out[rel] = full.read_bytes()
            if len(out) > MAX_FILES:
                raise ValueError(f"the region globs cover more than {MAX_FILES} files")
    return out


def layouts(root: Path, globs: list[str]) -> dict[str, dict[str, Any]]:
    return {path: layout(path, data) for path, data in _files(Path(root), globs).items()}


def _allowed(root: Path) -> tuple[set[str], str | None]:
    """Signers that may pin: pinned ``policy`` keys that are not ``optimizer`` keys."""
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import UNPINNED, resolve

    try:
        found = resolve(Path(root) / ".tine")
    except KeyRoleError as exc:
        return set(), str(exc)
    if found["status"] != "pinned":
        return set(), f"{UNPINNED}, so no policy-role key may pin regions"
    roles = found["roles"] or {}
    allowed = set(roles.get("policy", [])) - set(roles.get("optimizer", []))
    return allowed, None if allowed else "no policy-role (non-optimizer) key is pinned"


def pin(root: Path, globs: list[str], key: Any, at: str) -> dict[str, Any]:
    """Sign and file the baseline; refused for a bad marker or a key that cannot pin."""
    from opentine._integrity import normalize
    from opentine._integrity_run import _dump, _sign
    from opentine._promote import _who
    from opentine.kernel import canonical_json

    globs = sorted({normalize(g) for g in globs if g})
    if not globs:
        raise ValueError("region-pin needs at least one --glob")
    allowed, why = _allowed(root)
    if _who(key) not in allowed:
        raise ValueError(why or f"{_who(key)} is not a policy-role (non-optimizer) key")
    found = layouts(root, globs)
    bad = [f"{p}: {e}" for p, row in found.items() for e in row["errors"]]
    if bad:
        raise ValueError("marker errors: " + "; ".join(bad[:5]))
    files = {p: {k: row[k] for k in ("sha256", "regions", "segments")} for p, row in found.items()}
    baseline = hashlib.sha256(canonical_json(files)).hexdigest()
    claim = {"schema": SCHEMA, "globs": globs, "files": files, "baseline_sha256": baseline}
    document = _sign(key, claim, f"sha256:{baseline}", at)
    _dump(Path(root) / PIN, document)
    return {"ok": True, "baseline_sha256": baseline, "files": len(files),
            "regions": sum(r["regions"] for r in files.values()),
            "signer": document["signer"], "pin": (Path(root) / PIN).as_posix()}  # fmt: skip


def _claim(doc: Any) -> dict[str, Any] | None:
    """The pin's claim when its shape holds (the file is untrusted JSON)."""
    claim = doc.get("claim") if isinstance(doc, dict) else None
    if not isinstance(claim, dict) or claim.get("schema") != SCHEMA:
        return None
    globs, files = claim.get("globs"), claim.get("files")
    if not (isinstance(globs, list) and globs and all(isinstance(g, str) and g for g in globs)):
        return None
    if not isinstance(files, dict) or len(files) > MAX_FILES:
        return None
    for row in files.values():
        n = row.get("regions") if isinstance(row, dict) else None
        segs = row.get("segments") if isinstance(row, dict) else None
        if type(n) is not int or n < 0 or not isinstance(segs, list) or len(segs) != n + 1:
            return None
        if not all(isinstance(s, str) and _HEX.fullmatch(s) for s in segs):
            return None
    return claim


def load(root: Path) -> tuple[dict | None, list[dict[str, str]]]:
    """``(claim, findings)``: the pin's claim when a pinned key signed it, else findings."""
    from opentine import _json_shallow
    from opentine._integrity_run import _signer

    path = PIN.as_posix()
    try:
        raw = (Path(root) / PIN).read_bytes()
    except FileNotFoundError:
        return None, [finding(MISSING, path, "no signed region pin")]
    try:
        doc = _json_shallow.loads(raw)
    except (ValueError, UnicodeDecodeError):
        doc = None
    claim = _claim(doc)
    allowed, why = _allowed(root)
    who = _signer(doc) if claim is not None else None
    if claim is None:
        why = f"not an {SCHEMA} attestation"
    elif who is None:
        why = "the signature does not verify under its signer"
    elif who not in allowed:
        why = why or f"signed by {who}, not a policy-role (non-optimizer) key"
    else:
        return claim, []
    return None, [finding(UNSIGNED, path, why)]


def check(root: Path) -> dict[str, Any]:
    """``{ok, baseline_sha256, files, findings, blocking}`` for the working tree."""
    claim, findings = load(root)
    if claim is not None:
        findings = compare(claim["files"], layouts(root, claim["globs"]))
    return {"ok": not findings, "baseline_sha256": claim and claim["baseline_sha256"],
            "files": len(claim["files"]) if claim else 0, "findings": findings,
            "blocking": len(findings)}  # fmt: skip


def check_policy(policy: dict[str, Any]) -> None:
    """Settle ``regions`` in a loaded ``[promote]`` table: rsi requires it."""
    rsi = policy.get("profile") == "rsi"
    mode = policy.get("regions", "required" if rsi else "advisory")
    if mode not in MODES:
        raise ValueError(f"regions is one of {', '.join(MODES)}")
    if rsi and mode != "required":
        raise ValueError('the rsi profile requires regions = "required"')
    policy["regions"] = mode


def promote_findings(policy: dict[str, Any], root: Path | None) -> tuple[list, list]:
    """``(refusals, advisories)`` of the region pin for ``tine promote``."""
    from opentine._promote_checks import refusal

    required = policy.get("regions", "advisory") == "required"
    if root is None or not (Path(root) / PIN).is_file():
        if not required:
            return [], []  # D12: no pin and no rule, nothing changes
        return [refusal("promote.regions-unpinned", "the policy requires a signed region "
                        "pin (tine integrity region-pin) and none is filed")], []  # fmt: skip
    row = check(Path(root))
    if row["ok"]:
        return [], []
    codes = sorted({f["code"] for f in row["findings"]})
    detail = f"{len(row['findings'])} region finding(s): {', '.join(codes)}"
    if not required:
        return [], [{"code": "advisory:regions.outside-modified", "detail": detail}]
    if {MISSING, UNSIGNED} & set(codes):
        return [refusal("promote.regions-unpinned", detail)], []
    return [refusal("promote.region-modified", detail)], []


__all__ = ["MISSING", "MODES", "PIN", "SCHEMA", "UNSIGNED", "check", "check_policy", "layouts",
           "load", "pin", "promote_findings"]  # fmt: skip
