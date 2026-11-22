"""Inputs for ``scripts/verify_everywhere.py``: the cases one repository, folder or bundle asks.

Each object of a repository becomes ``envelope.decode`` (under its own oid)
and ``links.extract`` (against the store); each signed record -- an
``attestation`` or ``annotation`` object with a ``tine-attest`` signature
block, or a ``*.json`` record file with one -- becomes ``sig.verify`` (the
attestation family, embedded key). Untrusted JSON is read through
``opentine._json_shallow``.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from opentine import _json_shallow
from tests.conformance.cases import Case
from tests.conformance.engine import observe

SIGNED = ("attestation", "annotation")


def _case(cid: str, op: str, raw: bytes, args: dict[str, Any]) -> Case:
    return Case(id=cid, section="x", checklist=(), op=op, profile="verifier", expect="accept",
                intent="verify_everywhere", input={"bytes": raw}, args=args)  # fmt: skip


def _signed(raw: bytes) -> bool:
    try:
        value = _json_shallow.loads(raw)
    except ValueError:
        return False
    block = value.get("signature") if isinstance(value, dict) else None
    return isinstance(block, dict) and str(block.get("scheme", "")).startswith("tine-attest/")


def repo_cases(tine_dir: Path) -> list[Case]:
    """``envelope.decode`` + ``links.extract`` for every object, ``sig.verify`` for signed ones."""
    from opentine.repository import Repo

    repo = Repo(tine_dir)
    oids = sorted(repo.iter_oids())
    everything = {"present": oids}
    cases: list[Case] = []
    for oid in oids:
        raw = repo.raw(oid)
        cases.append(_case(f"{oid}#decode", "envelope.decode", raw, {"expected_oid": oid}))
        seen = observe(_case(oid, "links.extract", raw, everything))
        links = (seen.output or {}).get("links") if seen.exception is None else None
        cases.append(_case(f"{oid}#links", "links.extract", raw,
                           {"present": links} if links is not None else everything))  # fmt: skip
        body = raw.split(b"\n", 1)[1] if b"\n" in raw else b""
        if oid.split(":", 1)[0] in SIGNED and _signed(body):
            cases.append(_case(f"{oid}#sig", "sig.verify", body, {"trust_embedded": True}))
    return cases


def file_cases(folder: Path) -> list[Case]:
    """``sig.verify`` for every signed ``*.json`` record under *folder* (or *folder* itself)."""
    paths = [folder] if folder.is_file() else sorted(folder.rglob("*.json"))
    cases = []
    for path in paths:
        raw = path.read_bytes()
        if _signed(raw):
            name = path.relative_to(folder).as_posix() if folder.is_dir() else path.name
            cases.append(_case(f"file:{name}#sig", "sig.verify", raw, {"trust_embedded": True}))
    return cases


def bundle_cases(path: Path, scratch: Path, problems: list[str], cli: Path) -> list[Case]:
    """Whole-bundle agreement (python, ts), then the bundle's objects as a scratch repository."""
    from opentine import _bundle
    from opentine.repository import Repo

    data = _bundle.read_file(path)
    try:
        _bundle.verify(data)
        python_ok = True
    except _bundle.BundleError:
        python_ok = False
    node = shutil.which("node")
    if node is not None and cli.is_file():
        done = subprocess.run([node, str(cli), str(path), "--trust-embedded"],
                              capture_output=True, timeout=600, check=False)  # fmt: skip
        if (done.returncode == 0) != python_ok:
            problems.append(f"ts disagrees: bundle {path.name} (exit {done.returncode})")
    if not python_ok:
        problems.append(f"bundle {path.name} does not verify")
        return []
    repo = Repo.init(scratch / "unbundled")
    _bundle.unbundle(repo, data, "bundle")
    return repo_cases(repo.path)


def tine_dir(path: Path) -> Path | None:
    for candidate in (path, path / ".tine"):
        if (candidate / "objects").is_dir():
            return candidate
    return None
