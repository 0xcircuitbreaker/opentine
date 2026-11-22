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


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in pairs:
        if name in out:
            raise ValueError(f"duplicate key {name!r}")
        out[name] = value
    return out


def _constant(literal: str) -> Any:
    raise ValueError(f"non-finite number {literal}")


def _strict(raw: bytes) -> Any:
    """Parse a record strictly: no duplicate keys, NaN, Infinity or overflowing floats."""

    def _finite(text: str) -> float:
        value = float(text)
        if value in (float("inf"), float("-inf")):
            raise ValueError(f"non-finite number {text}")
        return value

    return _json_shallow.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                               parse_constant=_constant, parse_float=_finite)  # fmt: skip


def _block_ok(value: Any) -> bool:
    block = value.get("signature") if isinstance(value, dict) else None
    return isinstance(block, dict) and str(block.get("scheme", "")).startswith("tine-attest/")


def _signed(raw: bytes) -> bool:
    try:
        return _block_ok(_json_shallow.loads(raw))
    except ValueError:
        return False


def _policy_signer(value: Any) -> str | None:
    """Python-only check of a signed policy document (``tine-sig/3``, not the attestation family).

    The pyz and TS verifiers do not implement policy documents, so these are
    verified by the reference alone and reported as such; an unknown schema or
    a signature that does not verify is a problem.
    """
    from opentine import _budget_policy

    if value.get("schema") == "opentine-budget-policy/1":
        return _budget_policy.signer(value)
    return None


def _is_policy(value: Any) -> bool:
    block = value.get("signature") if isinstance(value, dict) else None
    return isinstance(block, dict) and str(block.get("scheme", "")).startswith("tine-sig/")


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


def file_cases(folder: Path, problems: list[str] | None = None,
               python_only: list[str] | None = None) -> list[Case]:  # fmt: skip
    """``sig.verify`` for every signed ``*.json`` record under *folder* (or *folder* itself).

    Fail closed: a file that does not parse strictly (duplicate keys, NaN,
    Infinity, bad JSON) is reported ``unreadable``, and one that looks like a
    record (a ``claim`` or a ``signature`` key) without a ``tine-attest`` block
    is reported ``unsigned``, rather than silently leaving the check. A signed
    policy document (``tine-sig/``) is checked by the Python verifier only and
    named in *python_only*.
    """
    problems = [] if problems is None else problems
    python_only = [] if python_only is None else python_only
    paths = [folder] if folder.is_file() else sorted(folder.rglob("*.json"))
    cases = []
    for path in paths:
        raw = path.read_bytes()
        name = path.relative_to(folder).as_posix() if folder.is_dir() else path.name
        try:
            value = _strict(raw)
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            problems.append(f"unreadable record: file:{name} ({exc})")
            continue
        if _block_ok(value):
            cases.append(_case(f"file:{name}#sig", "sig.verify", raw, {"trust_embedded": True}))
        elif _is_policy(value):
            if _policy_signer(value) is None:
                problems.append(f"policy does not verify: file:{name}")
            else:
                python_only.append(f"file:{name}")
        elif isinstance(value, dict) and ("claim" in value or "signature" in value):
            problems.append(f"unsigned record: file:{name}")
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
