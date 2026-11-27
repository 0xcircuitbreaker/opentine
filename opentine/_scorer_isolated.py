"""Isolated ``python:`` scorer execution (0.85): ``tine eval run --isolate``.

The scorer runs in a child interpreter (:mod:`opentine._scorer_child`) started
with ``-I -B``, an empty environment, a fresh empty working directory, its own
process group (a kill-on-close job on Windows) and bounded output, and is killed
with its whole tree at the timeout. The child holds no key: it returns scores
and what it loaded, and the parent hashes the closure (:mod:`._scorer_closure`)
and signs. A breach (a socket, a subprocess, an environment read, a file read
outside the scorer's import paths and ``--scorer-input`` files, any write, a
blown limit) refuses the eval: ``scorer.isolation-breach``, nothing signed.
"""

from __future__ import annotations

import json
import secrets
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from opentine import _scorer_closure as closure
from opentine._eval_scorers import Scorer, ScorerError

CHILD = Path(__file__).with_name("_scorer_child.py")
LIMITS = {"cpu_seconds": 60, "memory_mb": 2048, "timeout_seconds": 120, "output_bytes": 8 << 20}


class ScorerRefused(ScorerError):
    """A named refusal: ``scorer.isolation-breach``, ``scorer.closure-mismatch``, ..."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail

    def refusals(self) -> list[dict[str, str]]:
        return [{"code": self.code, "detail": self.detail}]


def _env() -> dict[str, str]:
    if sys.platform == "win32":  # the interpreter cannot start without it
        import os

        return {"SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows")}
    return {}


def import_paths(target: str) -> tuple[list[str], Path]:
    """Directories the child may import from, and the root closure paths display under."""
    location = target.partition(":")[2].rpartition(":")[0]
    if location.endswith(".py"):
        where = Path(location).resolve()
        if not where.is_file():
            raise ScorerError(f"python scorer file {location} does not exist")
        return [str(where.parent)], Path.cwd().resolve()
    found = [str(Path(p or ".").resolve()) for p in sys.path]
    return [p for p in dict.fromkeys(found) if Path(p).is_dir()], Path.cwd().resolve()


def run_child(target: str, pairs: list[tuple[dict[str, Any], Any]], *, inputs: list[Path],
              limits: dict[str, int]) -> dict[str, Any]:  # fmt: skip
    """The child's report for *pairs*; refuses on any breach."""
    from opentine.tools._process import run_bounded

    paths, _root = import_paths(target)
    nonce = secrets.token_hex(16)
    location, _, func = target.partition(":")[2].rpartition(":")
    if location.endswith(".py"):  # the child runs in an empty directory
        location = str(Path(location).resolve())
    request = {"nonce": nonce, "target": f"{location}:{func}", "paths": paths,
               "inputs": [str(p.resolve()) for p in inputs], "limits": limits,
               "pairs": [[item, output] for item, output in pairs]}  # fmt: skip
    work = Path(tempfile.mkdtemp(prefix="tine-scorer-"))
    try:
        (work / "request.json").write_bytes(json.dumps(request).encode("utf-8"))
        result = run_bounded(
            [sys.executable, "-I", "-B", str(CHILD), str(work / "request.json")],
            timeout=limits["timeout_seconds"], max_chars=4096,
            max_bytes=limits["output_bytes"], cwd=str(work), env=_env(),
        )  # fmt: skip
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if result.timed_out:
        raise ScorerRefused("scorer.isolation-breach",
                            f"timeout: no result in {limits['timeout_seconds']} s")  # fmt: skip
    if result.stdout_truncated:
        raise ScorerRefused("scorer.isolation-breach", "output-limit: the child wrote too much")
    report = _framed(result.stdout, nonce)
    if report is None:
        detail = f"limit: the child exited {result.returncode} with no result"
        raise ScorerRefused("scorer.isolation-breach", detail)
    breaches = report.get("breaches") or []
    if breaches:
        kinds = sorted({str(b.get("kind")) for b in breaches if isinstance(b, dict)})
        first = breaches[0].get("detail") if isinstance(breaches[0], dict) else ""
        raise ScorerRefused("scorer.isolation-breach", f"{', '.join(kinds)}: {first}")
    if report.get("error"):
        raise ScorerError(f"isolated scorer failed: {report['error']}")
    scores = report.get("scores")
    if not isinstance(scores, list) or len(scores) != len(pairs):
        raise ScorerError("isolated scorer returned the wrong number of scores")
    return report


def _framed(stdout: bytes, nonce: str) -> dict[str, Any] | None:
    from opentine._json_shallow import loads

    for line in reversed(stdout.decode("utf-8", "replace").splitlines()):
        if line.startswith(nonce):
            try:
                doc = loads(line[len(nonce) :])
            except ValueError:
                return None
            return doc if isinstance(doc, dict) else None
    return None


def describe(target: str, report: dict[str, Any], *, inputs: list[Path], limits: dict[str, int],
             lockfile: Path | None, contract: str | None) -> dict[str, Any]:  # fmt: skip
    """The ``opentine.scorer-closure/1`` document; the parent hashes every file itself."""
    _paths, root = import_paths(target)
    modules = report.get("modules") if isinstance(report.get("modules"), dict) else {}
    data = report.get("data") if isinstance(report.get("data"), list) else []
    full = report.get("network") == "namespace" and report.get("limits") is True
    version = ".".join(str(n) for n in sys.version_info[:3])
    spec = _posix(target) if target.partition(":")[2].rpartition(":")[0].endswith(".py") else target
    given = {str(p.resolve()) for p in inputs}
    data = [d for d in data if str(d) not in given]
    return {
        "convention": closure.CONVENTION, "target": spec, "python": version,
        "modules": [{"name": str(name), "sha256": closure.file_sha256(Path(where))}
                    for name, where in sorted(modules.items())],
        "data": [{"file": closure.display(Path(p), root), "sha256": closure.file_sha256(Path(p))}
                 for p in sorted(str(d) for d in data)],
        "inputs": [{"file": closure.display(p.resolve(), root),
                    "sha256": closure.file_sha256(p)} for p in inputs],
        "lockfile": "sha256:" + closure.file_sha256(lockfile) if lockfile else None,
        "contract": contract,
        "isolation": {"level": "full" if full else "partial",
                      "network": "namespace" if report.get("network") == "namespace" else "audit",
                      "limits": report.get("limits") is True, "env": "empty"},
        "limits": dict(limits),
    }  # fmt: skip


def _posix(target: str) -> str:
    kind, _, rest = target.partition(":")
    location, _, name = rest.rpartition(":")
    return f"{kind}:{Path(location).as_posix()}:{name}"


def _unbatched(_item: dict[str, Any], _output: Any) -> tuple[float, str]:
    raise ScorerError("an isolated scorer scores every item in one batch")


def isolated(spec: str, *, inputs: list[Path] | None = None, limits: dict[str, int] | None = None,
             lockfile: Path | None = None, expect: str | None = None) -> Scorer:  # fmt: skip
    """A ``python:`` scorer whose batch runs in the child; its version is the closure pin."""
    if not spec.startswith("python:") or spec.count(":") < 2:
        raise ScorerError("--isolate runs python:MODULE:FUNC or python:FILE.py:FUNC scorers")
    files = [Path(p) for p in inputs or []]
    for path in files:
        if not path.is_file():
            raise ScorerError(f"--scorer-input {path} is not a file")
    bounds = {**LIMITS, **(limits or {})}
    scorer = Scorer("python", "pending", _unbatched)

    def batch(pairs: list[tuple[dict[str, Any], Any]]) -> list[float]:
        report = run_child(spec, pairs, inputs=files, limits=bounds)
        doc = describe(spec, report, inputs=files, limits=bounds, lockfile=lockfile,
                       contract=scorer.config.get("contract"))  # fmt: skip
        found = closure.closure_digest(doc)
        if expect is not None and found != expect:
            detail = f"the scorer's closure is {found}, the pin says {expect}"
            raise ScorerRefused("scorer.closure-mismatch", detail)
        scorer.version, scorer.config["closure"] = closure.pin(doc), doc
        return [float(s) for s in report["scores"]]

    scorer.batch = batch
    return scorer


__all__ = ["LIMITS", "ScorerRefused", "describe", "import_paths", "isolated", "run_child"]
