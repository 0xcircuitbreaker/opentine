"""``docs/conformance/compat/index.json``: the golden fixtures, exposed not copied.

SPEC 5.1's read guarantee is already backed by eight released versions of real
bytes under ``tests/fixtures/compat/``. Copying them into the suite would create
a second set that can drift from the set that *is* the evidence, so this index
copies zero bytes: it points at each fixture by repository-root-relative path,
pins its SHA-256, and records the verdicts the current build must reach.

The single source of truth for which releases exist is
``tests.test_backwards_compat.GOLDEN`` -- the same tuple the compatibility gate
iterates -- so the two can never disagree about the fixture set.

Reflog bytes are deliberately excluded: ``scripts/gen_compat_fixtures.py``'s own
docstring records them as the only non-reproducible bytes in a fixture set.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from pathlib import Path
from typing import Any

from opentine import Repo, Run
from opentine._fork_identity import verify_fork_id
from tests.test_backwards_compat import ARTIFACTS, COMPAT, GOLDEN, HMAC_KEY, Golden

ROOT = Path(__file__).resolve().parents[2]
#: Reflog rows embed ``time.time_ns()`` and are the one non-reproducible part of
#: a fixture, so their bytes are described but never pinned.
EXCLUDED = ("/logs/",)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _files(golden: Golden) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in sorted(golden.path.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        if any(marker in f"/{relative}" for marker in EXCLUDED):
            continue
        rows.append({"path": relative, "sha256": _digest(path)})
    return rows


def _refs(repo_root: Path) -> dict[str, str]:
    base = repo_root / ".tine" / "refs"
    found: dict[str, str] = {}
    for path in sorted(base.rglob("*")):
        if path.is_file():
            name = path.relative_to(base).as_posix()
            found[name] = path.read_text("ascii").strip()
    return found


def _release(golden: Golden) -> dict[str, Any]:
    artifacts: dict[str, Any] = {}
    for name in ARTIFACTS:
        path = golden.artifact(name)
        result = Run.verify_integrity(path)
        row: dict[str, Any] = {
            "integrity_ok": bool(result.ok),
            "digest": result.actual,
        }
        if name == "artifact_signed.tine":
            signature = Run.verify_signature(path, hmac_key=HMAC_KEY)
            row["signature"] = {
                "state": signature.state,
                "ok": bool(signature.ok),
                "algorithm": signature.algorithm,
                "key_id": signature.key_id,
                "signer": signature.signer,
                "signed_at": signature.signed_at,
            }
        if name == "fork.tine":
            run = Run.load(path)
            verdict = verify_fork_id(run)
            row["run_id"] = run.id
            row["fork_id_verdict"] = (
                "abstain" if verdict is None else ("confirm" if verdict else "tampered")
            )
        artifacts[name] = row
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch) / "repo"
        shutil.copytree(golden.path / "repo", work)
        repo = Repo.open(work)
        repo_row = {
            "main_oid": golden.repo_main_oid,
            "fork_oid": golden.repo_fork_oid,
            "refs": _refs(work),
            "fsck_ok": bool(repo.fsck().ok),
            "main_run_id": repo.load_run("heads/main").id,
        }
    return {
        "version": golden.version,
        "path": (golden.path.relative_to(ROOT)).as_posix(),
        "hmac_key_ascii": HMAC_KEY.decode("ascii"),
        "fork_records_identity": golden.fork_records_identity,
        "artifacts": artifacts,
        "repo": repo_row,
        "files": _files(golden),
    }


def build_index() -> dict[str, Any]:
    return {
        "note": (
            "These bytes live in tests/fixtures/compat/ and are never copied here: the "
            "fixtures written by the real published releases ARE the evidence, and a "
            "second copy could drift from them. Clone the repository, or fetch the "
            "listed paths, and check each SHA-256 before reading. Reflog files are "
            "excluded because their rows embed a wall-clock timestamp."
        ),
        "source": "tests/test_backwards_compat.py::GOLDEN",
        "root": str(COMPAT.relative_to(ROOT).as_posix()),
        "releases": [_release(golden) for golden in GOLDEN],
    }
