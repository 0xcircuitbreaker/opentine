"""``tine audit-kit verify``: re-check an audit kit with the network refused (0.49).

Every in-process check runs inside :func:`opentine._offline_guard.no_network`,
so a check that tried to reach the network would fail rather than pass:

``sums``       every file matches ``SHA256SUMS`` and no file is unlisted;
``summary``    ``kit.json`` is a ``tine-cli-audit-kit-build-1`` document;
``evidence``   the evidence folder, by the pyz's own code run in this process
               (manifest, custody, each run's digest and signature, pinned to
               ``evidence/trust/pubkey.pub`` when the kit carries one);
``run:FILE``   each run's digest is the one ``kit.json`` and the page name;
``crate:FILE`` each Provenance Run Crate validates and names that digest;
``replay``     the ``replay/v1`` envelope: signature, subject and verdict;
``witnesses``  the pinned witness set parses and matches its quorum;
``pyz``        the root and evidence copies are identical and, built by this
               same tine version, byte-equal to a fresh reproducible build;
``page``       ``verify.html`` embeds every run and references nothing outside.

``--pyz`` additionally runs ``python -I -S tine-verify.pyz evidence`` as a
separate process (the pyz refuses the network itself). A ``.zip`` kit is
unpacked to a temporary directory first, refusing unsafe member names.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from opentine._audit_kit import SUMMARY, SUMS, sums_text
from opentine._audit_kit_guard import safe_run_file, tree_problems, unpack
from opentine._audit_kit_parts import check, check_witnesses, verify_replay

_EXTERNAL = re.compile(r"""\b(?:src|href)\s*=\s*["']?(?!#)""", re.I)


def _sums(kit: Path) -> dict[str, str]:
    path = kit / SUMS
    if not path.is_file():
        return check("sums", False, f"{SUMS} is missing")
    odd = tree_problems(kit)
    if odd:
        return check("sums", False, "links or special files: " + ", ".join(odd[:10]))
    stated, actual = path.read_bytes(), sums_text(kit)
    if stated == actual:
        return check("sums", True, f"{len(actual.splitlines())} file(s) match {SUMS}")
    want = set(stated.decode("utf-8", "replace").splitlines())
    got = set(actual.decode("utf-8").splitlines())
    names = sorted({line.partition("  ")[2] for line in want ^ got})
    return check("sums", False, "changed, missing or unlisted: " + ", ".join(names[:10]))


def _summary(kit: Path) -> tuple[dict[str, Any] | None, dict[str, str]]:
    try:
        doc = json.loads((kit / SUMMARY).read_text(encoding="utf-8"))
        if doc.get("command") != "audit-kit-build" or doc.get("kit_version") != 1:
            raise ValueError("not a tine-cli-audit-kit-build-1 document")
        for row in doc["runs"]:
            if not safe_run_file(row["file"]) or not isinstance(row["digest"], str):
                raise ValueError(f"unsafe run entry {row['file']!r}")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        return None, check("summary", False, f"{SUMMARY}: {exc}")
    return doc, check("summary", True, f"built by tine {doc['tine_version']}")


def _evidence(kit: Path, anchor: Path | None) -> list[dict[str, str]]:
    from opentine._pyz import _cli, _evidence

    root = kit / "evidence"
    if not (root / "MANIFEST.sha256").is_file():
        return [check("evidence", False, "evidence/MANIFEST.sha256 is missing")]
    key = root / "trust" / "pubkey.pub"
    pubkey = _cli.public_key(str(key)) if key.is_file() else None
    if anchor is None:
        rows = [check("anchor", None, "no --pubkey: the kit vouches for itself (integrity only)")]
    else:
        outside = _cli.public_key(str(anchor))
        same = pubkey is not None and outside == pubkey
        rows = [check("anchor", same, "the kit's pubkey.pub is the --pubkey key" if same else
                      "the kit's pubkey.pub is not the --pubkey key")]  # fmt: skip
        pubkey = outside
    found = _evidence.verify_evidence(root, lambda p: _cli.verify_file(p, pubkey=pubkey))
    failed = [c["name"] for c in found["checks"] if c["outcome"] == "fail"]
    pinned = "pinned key" if pubkey else "embedded keys (no pubkey.pub)"
    detail = f"failed: {', '.join(failed)}" if failed else f"{len(found['runs'])} run(s), {pinned}"
    return [*rows, check("evidence", not failed, detail)]


def _runs(kit: Path, doc: dict[str, Any]) -> list[dict[str, str]]:
    from opentine._audit_kit_parts import run_digest

    out = []
    for row in doc["runs"]:
        path = kit / "evidence" / row["file"]
        ok = path.is_file() and bool(row["digest"]) and run_digest(path) == row["digest"]
        out.append(check(f"run:{row['file']}", ok, row["digest"] if ok else "digest differs"))
        crate = kit / "crate" / Path(row["file"]).stem / "ro-crate-metadata.json"
        out.append(_crate(crate, row))
    return out


def _crate(path: Path, row: dict[str, Any]) -> dict[str, str]:
    from opentine._run_crate_check import validate

    name = f"crate:{Path(row['file']).name}"
    try:
        crate = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return check(name, False, f"unreadable: {exc}")
    errors = validate(crate)
    hex_digest = row["digest"].rsplit(":", 1)[-1]
    named = any(
        isinstance(e.get("identifier"), str) and e["identifier"].rsplit(":", 1)[-1] == hex_digest
        for e in crate.get("@graph", [])
    )
    if not named:
        errors.append("the crate does not name the run's digest")
    return check(name, not errors, "; ".join(errors) or "valid; names the run digest")


def _pyz(kit: Path, doc: dict[str, Any]) -> dict[str, str]:
    from opentine._pyz_build import build_bytes
    from opentine._version import __version__

    top, inner = kit / "tine-verify.pyz", kit / "evidence" / "tine-verify.pyz"
    if not top.is_file() or not inner.is_file() or top.read_bytes() != inner.read_bytes():
        return check("pyz", False, "tine-verify.pyz is missing or differs from evidence/")
    if doc["tine_version"] != __version__:
        return check("pyz", True, f"present; built by tine {doc['tine_version']}, not rebuilt")
    same = top.read_bytes() == build_bytes()
    return check("pyz", same, "byte-equal to a fresh reproducible build" if same else
                 "differs from this tine version's reproducible build")  # fmt: skip


def _page(kit: Path, doc: dict[str, Any]) -> dict[str, str]:
    from opentine._audit_kit_page import SCRIPT_START

    try:
        text = (kit / "verify.html").read_text(encoding="utf-8")
    except OSError as exc:
        return check("page", False, f"verify.html: {exc}")
    if SCRIPT_START not in text:
        return check("page", False, "verify.html carries no verifier")
    if _EXTERNAL.search(text):
        return check("page", False, "verify.html references an outside resource")
    missing = [r["file"] for r in doc["runs"] if json.dumps(r["digest"])[1:-1] not in text]
    if missing:
        return check("page", False, f"runs not embedded: {', '.join(missing)}")
    return check("page", True, f"{len(doc['runs'])} run(s) embedded, nothing loaded")


def offline_checks(kit: Path, anchor: Path | None = None) -> list[dict[str, str]]:
    from opentine._offline_guard import no_network

    with no_network():
        checks = [_sums(kit)]
        doc, summary = _summary(kit)
        checks.append(summary)
        if doc is None:
            return checks
        checks += _evidence(kit, anchor)
        checks += _runs(kit, doc)
        if len(doc["runs"]) == 1:
            checks.append(verify_replay(kit, kit / "evidence" / doc["runs"][0]["file"]))
        checks += [check_witnesses(kit), _pyz(kit, doc), _page(kit, doc)]
    return checks


def run_pyz(kit: Path, anchor: Path | None = None) -> dict[str, str]:
    command = [sys.executable, "-I", "-S", str(kit / "tine-verify.pyz"), str(kit / "evidence")]
    key = kit / "evidence" / "trust" / "pubkey.pub"
    key = anchor or key
    command += ["--pubkey", str(key)] if key.is_file() else []
    done = subprocess.run(command, capture_output=True, text=True, check=False, timeout=600)
    detail = "python -I -S tine-verify.pyz evidence: exit " + str(done.returncode)
    return check("pyz-run", done.returncode == 0, detail)


def verify_kit(
    target: Path, *, with_pyz: bool = False, anchor: Path | None = None
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="tine-kit-") as room:
        kit = unpack(target, Path(room)) if target.is_file() else target
        checks = offline_checks(kit, anchor)
        if with_pyz and (kit / "tine-verify.pyz").is_file():
            checks.append(run_pyz(kit, anchor))
    ok = all(c["outcome"] != "fail" for c in checks)
    return {"command": "audit-kit-verify", "kit": target.name, "ok": ok, "checks": checks}


__all__ = ["offline_checks", "run_pyz", "unpack", "verify_kit"]  # unpack: re-export
