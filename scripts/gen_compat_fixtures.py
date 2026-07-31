#!/usr/bin/env python3
"""Generate one release's golden cross-version compat fixtures.

``tests/test_backwards_compat.py`` gates every release on reading data written
by older releases. Those fixtures must come from the PUBLISHED release they are
named for -- never from the working tree -- so this generator uses only public
API that has existed since 0.3.0, and runs under an installed wheel:

    uv venv /tmp/gen040
    uv pip install --python /tmp/gen040/bin/python opentine==0.4.0
    /tmp/gen040/bin/python scripts/gen_compat_fixtures.py v0_4_0
    git add -f tests/fixtures/compat/v0_4_0

It writes ``tests/fixtures/compat/<version_dir>/`` (replacing it if present):
the four ``ARTIFACTS`` below and a v3 ``repo/``. The stable identities the gate
asserts on are printed as JSON on stdout; copy them into the test module.

Determinism: run ids, prompts, step content, the signing key/time, the run
``created_at`` and every step timestamp are fixed, and the fork nonce is pinned
to "" where the API accepts one (0.4.0+), so all artifact bytes, repository
object ids and refs are byte-stable across runs. The only non-reproducible bytes
are the v3 reflogs under ``repo/.tine/logs/``, which record a wall-clock
``time_ns`` no public API can pin; no object or id derives from them.
"""

from __future__ import annotations

import argparse
import inspect
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import opentine
from opentine import Repo, Run, RunStatus, StepKind

ROOT = Path(__file__).resolve().parents[1]
COMPAT = ROOT / "tests" / "fixtures" / "compat"
VERSION_DIR = re.compile(r"v\d+_\d+_\d+")

#: Documented in the gate; a test key, published on purpose.
HMAC_KEY = b"compat-golden-signing-key-000001"
KEY_ID = "compat-golden"
SIGNER = "release-bot"
SIGNED_AT = "2026-01-01T00:00:00Z"

#: 2026-01-01T00:00:00Z. Every wall clock the fixtures would otherwise record.
EPOCH = 1767225600.0

#: Every artifact the golden set is made of; the gate loads all four.
ARTIFACTS = (
    "artifact.tine",
    "artifact_signed.tine",
    "artifact_signed_fork_reason.tine",
    "fork.tine",
)

SYSTEM_PROMPT = "You are a careful release assistant."
USER_PROMPT = "Summarize what shipped in this release."
TAGS = ["release", "compat", "golden"]
MODEL = "anthropic/claude-sonnet-5"


def _stabilized(run: Run) -> Run:
    """``run`` with every wall-clock stamp replaced by a fixed one.

    ``Step`` is frozen and ``add_step``/``fork`` stamp ``time.time()``, so the
    only public way to pin the clock is to rewrite the serialized form and read
    it back -- which also proves the release can load what it just built.
    """
    data = run.to_dict()
    data["created_at"] = EPOCH
    for offset, step_id in enumerate(data["graph"]["order"]):
        data["graph"]["steps"][step_id]["timestamp"] = EPOCH + offset
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / "stabilize.tine"
        path.write_text(json.dumps(data), encoding="utf-8")
        return Run.load(path)


def _golden_run(run_id: str, version: str) -> Run:
    """The four-kind run every artifact fixture is a view of."""
    run = Run(
        id=run_id,
        created_at=EPOCH,
        system_prompt=SYSTEM_PROMPT,
        user_prompt=USER_PROMPT,
        tags=list(TAGS),
        metadata={"project": "opentine", "note": f"golden {version} cross-version fixture"},
        transcript=[{"role": "user", "content": USER_PROMPT}],
    )
    run.add_step(
        StepKind.model,
        {"text": "draft the summary"},
        {"text": f"v{version} shipped a golden compatibility fixture"},
        model_info=MODEL,
        cost=0.012,
        usage={"input": 120, "output": 60},
    )
    run.add_step(
        StepKind.tool,
        {"query": "changelog lookup"},
        {"result": "release notes"},
        tool_info={"name": "search", "arguments": {"q": "changelog"}},
    )
    run.add_step(StepKind.think, {"text": "reconcile the notes"})
    run.add_step(
        StepKind.done,
        {"text": "final summary"},
        {"text": "Summary complete."},
        cost=0.004,
        usage={"input": 30, "output": 15},
    )
    run.status = RunStatus.completed
    return _stabilized(run)


def _fork_reason_run(version_dir: str) -> Run:
    """A signed run carrying ``metadata.fork_reason`` -- and a *bare* signature
    block (no key_id/signer/signed_at), the second stored signature shape."""
    run = Run(
        id=f"compat-fork-reason-{version_dir}",
        created_at=EPOCH,
        metadata={
            "forked_from": f"compat-fork-reason-source-{version_dir}",
            "fork_point": "step-0",
            "fork_reason": "explored approach A",
        },
    )
    run.add_step(StepKind.model, {"prompt": "start"}, {"out": "a"})
    run.add_step(StepKind.tool, {"q": "go"}, {"rows": [1, 2]})
    run.status = RunStatus.completed
    return _stabilized(run)


def _fork(source: Run) -> Run:
    """Fork ``source`` at its tool step, pinning the nonce where supported.

    0.4.0 gave the fork act a recorded identity (``metadata.fork``) seeded by a
    random nonce; ``nonce=""`` makes the act idempotent, so the fixture id is
    stable. Pre-0.4.0 releases take no such parameter and derive the id from
    ``(parent, point)``, already deterministic. The source is saved and reloaded
    first so it carries an integrity digest for ``source_digest`` to cite.
    """
    with tempfile.TemporaryDirectory() as scratch:
        stored = Path(scratch) / "fork_source.tine"
        source.save(stored)
        source = Run.load(stored)
    fork_point = source.steps[1].id
    supported = inspect.signature(type(source).fork).parameters
    extra: dict[str, Any] = {"nonce": ""} if "nonce" in supported else {}
    return _stabilized(source.fork(fork_point, **extra))


def _write_artifacts(out: Path, version_dir: str, version: str) -> dict[str, str]:
    _golden_run(f"compat-artifact-{version_dir}", version).save(out / "artifact.tine")
    _golden_run(f"compat-artifact-signed-{version_dir}", version).save(
        out / "artifact_signed.tine",
        sign_key=HMAC_KEY,
        key_id=KEY_ID,
        signer=SIGNER,
        signed_at=SIGNED_AT,
    )
    _fork_reason_run(version_dir).save(out / "artifact_signed_fork_reason.tine", sign_key=HMAC_KEY)
    fork = _fork(_golden_run(f"compat-fork-source-{version_dir}", version))
    fork.save(out / "fork.tine")
    return {"fork_id": fork.id, "fork_records_identity": "fork" in fork.metadata}


def _write_repo(out: Path, version_dir: str, version: str) -> dict[str, str]:
    """A v3 repository with heads/main and a heads/experiment fork of it."""
    repo = Repo.init(out / "repo")
    source = _golden_run(f"compat-repo-source-{version_dir}", version)
    stored = repo.put_run(source, ref="heads/main")
    # Fork at the tool step, addressed by the event the tool step became.
    fork_point = stored.event_map[source.steps[1].id]
    fork = repo.fork(stored.run_id, fork_point, ref="heads/experiment")
    report = repo.fsck()
    if not report.ok:
        raise SystemExit(f"generated repository does not verify: {report.errors}")
    return {"repo_main_oid": stored.run_id, "repo_fork_oid": fork}


def _check_release(version: str, allow_mismatch: bool) -> None:
    """The fixtures are evidence about a *published* release, so refuse to write
    them from this checkout — whose version string can equal a released one —
    and refuse a release that is not the one the directory is named for."""
    package = Path(opentine.__file__).resolve().parent
    if package == ROOT / "opentine":
        raise SystemExit(
            f"refusing to generate fixtures from the working tree ({package}): install the "
            "published wheel in a scratch venv and run this with that interpreter"
        )
    if opentine.__version__ != version and not allow_mismatch:
        raise SystemExit(
            f"refusing to write v{version} fixtures under opentine {opentine.__version__}: "
            "compat fixtures must come from the published release they are named for "
            "(pass --allow-version-mismatch only to experiment)"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("version_dir", help="fixture directory name, e.g. v0_4_0")
    parser.add_argument("--out", type=Path, default=COMPAT, help="compat fixture root")
    parser.add_argument(
        "--allow-version-mismatch",
        action="store_true",
        help="write fixtures even though the running opentine is a different release",
    )
    args = parser.parse_args(argv)

    version_dir = args.version_dir
    if not VERSION_DIR.fullmatch(version_dir):
        raise SystemExit(f"version_dir must look like v0_4_0, got {version_dir!r}")
    version = version_dir[1:].replace("_", ".")
    _check_release(version, args.allow_version_mismatch)

    out = Path(args.out) / version_dir
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    identities: dict[str, Any] = {
        "version_dir": version_dir,
        "generated_under": opentine.__version__,
    }
    identities.update(_write_artifacts(out, version_dir, version))
    identities.update(_write_repo(out, version_dir, version))

    for name in ARTIFACTS:
        result = Run.verify_integrity(out / name)
        if not result.ok:
            raise SystemExit(f"{name}: integrity digest does not verify as written")
    signed = Run.verify_signature(out / "artifact_signed.tine", hmac_key=HMAC_KEY)
    if not signed.ok:
        raise SystemExit(f"artifact_signed.tine: signature does not verify as written ({signed})")

    print(json.dumps(identities, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
