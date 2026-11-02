"""``tine verify --offline DIR|REPO``: one ``tine-verify-dataset/1`` report.

A **directory** is searched (recursively, sorted, symlinks skipped) for
``*.tine`` files and each one gets the full single-run offline report. A
**repository** (a directory holding ``.tine/config.json``, or a bare one) gets
one ``repository`` check from ``fsck`` -- every object rehashed against its id --
and one entry per run a ref points at (unreferenced runs are not listed), keyed
by its ``run:`` object id, whose digest is the ``tine-actions/1`` ``run_digest``
(SHA-256 of the run id and its redacted step graph), since repository runs have
no artifact digest.

The dataset is summarised by a Merkle root over the entries sorted by
``(run_id, digest)``:

* leaf  = SHA-256( 0x00 || canonical_json([run_id, digest]) )
* node  = SHA-256( 0x01 || left || right )
* each level pairs nodes left to right; an odd last node is carried up
  unchanged; the root of zero leaves is SHA-256 of the empty string.

A run whose digest cannot be computed contributes ``digest: ""``. The verdict
fails if any run's verdict fails (``--strict`` applies to each run).
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any

from opentine.kernel import canonical_json

SCHEMA = "tine-verify-dataset/1"


def leaf_hash(run_id: str, digest: str) -> bytes:
    return hashlib.sha256(b"\x00" + canonical_json([run_id, digest])).digest()


def merkle_root(pairs: list[tuple[str, str]]) -> str:
    level = [leaf_hash(run_id, digest) for run_id, digest in sorted(pairs)]
    if not level:
        return hashlib.sha256(b"").hexdigest()
    while len(level) > 1:
        paired = [
            hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest()
            for i in range(0, len(level) - 1, 2)
        ]
        level = paired + ([level[-1]] if len(level) % 2 else [])
    return level[0].hex()


def is_repository(root: Path) -> bool:
    inner = root / ".tine"
    if (inner / "config.json").is_file():
        return True
    return (root / "config.json").is_file() and (root / "objects").is_dir()


class DatasetReport:
    def __init__(self, root: Path, kind: str, strict: bool) -> None:
        self.root, self.kind, self.strict = root, kind, strict
        self.runs: list[dict[str, Any]] = []
        self.checks: list[dict[str, Any]] = []

    @property
    def ok(self) -> bool:
        return all(r["ok"] for r in self.runs) and all(c["ok"] for c in self.checks)

    def as_json(self) -> dict[str, Any]:
        runs = sorted(self.runs, key=lambda r: (r["run_id"], r["digest"]))
        return {
            "schema": SCHEMA,
            "command": "verify",
            "offline": True,
            "path": str(self.root),
            "kind": self.kind,
            "strict": self.strict,
            "verdict": "pass" if self.ok else "fail",
            "ok": self.ok,
            "count": len(runs),
            "merkle": {
                "algorithm": "sha256; leaf 0x00||canonical_json([run_id,digest]); "
                "node 0x01||left||right; odd node carried up",
                "root": merkle_root([(r["run_id"], r["digest"]) for r in runs]),
            },
            "checks": self.checks,
            "runs": runs,
        }

    def lines(self) -> list[str]:
        from rich.markup import escape

        doc = self.as_json()
        out = [f"[bold]offline dataset verification[/] {escape(str(self.root))} ({self.kind})"]
        for check in self.checks:
            mark = "[green]pass[/]" if check["ok"] else "[red]fail[/]"
            out.append(f"  {mark} {escape(check['name'])}: {escape(check['detail'])}")
        for run in doc["runs"]:
            mark = "[green]pass[/]" if run["ok"] else "[red]fail[/]"
            out.append(f"  {mark} {escape(run['run_id'])} {escape(run['digest'][:12] or '-')}")
        out.append(f"[dim]merkle root:[/] {doc['merkle']['root']} over {doc['count']} run(s)")
        out.append("[green]VERIFIED (offline)[/]" if self.ok else "[red]FAILED (offline)[/]")
        return out


def _directory(args: argparse.Namespace, root: Path, report: DatasetReport) -> None:
    from opentine._verify_chain import build_report

    files = sorted(p for p in root.rglob("*.tine") if p.is_file() and not p.is_symlink())
    for path in files:
        single = build_report(args, path, str(path)).as_json()
        digest = next(c for c in single["checks"] if c["name"] == "digest")
        actual = digest["detail"][7:] if digest["outcome"] == "pass" else ""
        report.runs.append(
            {
                "run_id": _run_id(path) or str(path.relative_to(root)),
                "path": path.relative_to(root).as_posix(),
                "digest": actual,
                "ok": single["ok"],
                "failed": [c["name"] for c in single["checks"] if c["outcome"] == "fail"],
                "report": single,
            }
        )


def _run_id(path: Path) -> str | None:
    from opentine._artifact_io import read_artifact_json

    try:
        data = read_artifact_json(path)
    except (OSError, RecursionError, ValueError):
        return None
    value = data.get("run_id") if isinstance(data, dict) else None
    return value if isinstance(value, str) else None


def _repository(root: Path, report: DatasetReport) -> None:
    from opentine._actions_manifest import run_digest
    from opentine.repository import Repo
    from opentine.repository.verify import fsck

    repo = Repo.open(root)
    result = fsck(repo)
    detail = f"{result.objects} object(s), {result.refs} ref(s) rehashed"
    if not result.ok:
        detail += ": " + "; ".join(result.errors[:5])
    report.checks.append({"name": "repository", "ok": result.ok, "detail": detail})
    oids = sorted({oid for oid in repo.list_refs().values() if oid.startswith("run:")})
    for oid in oids:
        try:
            digest, ok, reason = run_digest(repo.load_run(oid)), True, "ok"
        except Exception as exc:
            digest, ok, reason = "", False, f"run does not load: {exc}"
        report.runs.append({"run_id": oid, "digest": digest, "ok": ok, "reason": reason})


def build_dataset(args: argparse.Namespace, root: Path) -> DatasetReport:
    from opentine._offline_guard import no_network

    repo = is_repository(root)
    report = DatasetReport(root, "repository" if repo else "directory", bool(args.strict))
    with no_network():
        if repo:
            _repository(root, report)
        else:
            _directory(args, root, report)
    return report


__all__ = ["SCHEMA", "DatasetReport", "build_dataset", "leaf_hash", "merkle_root"]
