"""0.42: Entire's per-checkpoint refs, ``import --all`` and ``export --format entire``.

``tests/fixtures/entire/git-refs/`` holds one checkpoint tree in the layout the
current entireio/cli git-refs backend writes (see the fixture's SOURCE.txt);
each test commits it under ``refs/entire/checkpoints/<id[-2:]>/<id>``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from opentine import cli
from opentine.core import Run
from opentine.repo import Repo
from opentine.trace import _entire_git, _entire_refs
from opentine.trace._import_entire import entire_events

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

FIXTURES = Path(__file__).parent / "fixtures"
ULID = "01JD5Z8K3QX7M2N4P6R8T0V9WA"
HEX = "a3b2c4d5e6f7"


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    return done.stdout


def _wrapped(out: str) -> dict:
    """``export`` has the generic ``--json`` wrapper; the receipt is its output."""
    return json.loads(json.loads(out)["output"])


def _init(root: Path) -> Path:
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.name", "T")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "commit.gpgsign", "false")
    (root / "README").write_text("x")
    _git(root, "add", "README")
    _git(root, "commit", "-q", "-m", "init")
    return root


def _commit_tree(root: Path, files: dict[str, bytes], branch: str) -> str:
    _git(root, "checkout", "-q", "--orphan", branch)
    _git(root, "rm", "-rfq", ".")
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", f"Checkpoint: {branch}")
    sha = _git(root, "rev-parse", "HEAD").strip()
    _git(root, "checkout", "-q", "-f", "main")
    return sha


def _fixture_files(prefix: str = "") -> dict[str, bytes]:
    base = FIXTURES / "entire" / "git-refs" / ULID
    return {
        prefix + path.relative_to(base).as_posix(): path.read_bytes()
        for path in sorted(base.rglob("*"))
        if path.is_file()
    }


def _add_ref_checkpoint(root: Path) -> None:
    sha = _commit_tree(root, _fixture_files(), "tmp-ref")
    _git(root, "update-ref", _entire_refs.ref_name(ULID), sha)
    _git(root, "branch", "-q", "-D", "tmp-ref")


def _add_branch_checkpoint(root: Path) -> None:
    meta = json.loads(_fixture_files()["0/metadata.json"])
    meta.update(checkpoint_id=HEX, agent="Cursor")
    base = f"{HEX[:2]}/{HEX[2:]}"
    summary = {"checkpoint_id": HEX, "sessions": [{"metadata": f"/{base}/0/metadata.json"}]}
    files = {
        f"{base}/metadata.json": json.dumps(summary).encode(),
        f"{base}/0/metadata.json": json.dumps(meta).encode(),
        f"{base}/0/prompt.txt": b"old layout prompt",
    }
    _commit_tree(root, files, _entire_git.BRANCH)


@pytest.fixture
def source(tmp_path):
    root = _init(tmp_path / "proj")
    _add_ref_checkpoint(root)
    return root


def test_ref_naming_matches_entire():
    assert _entire_refs.ref_name(ULID) == f"refs/entire/checkpoints/WA/{ULID}"
    assert _entire_refs.parse_ref(f"refs/entire/checkpoints/wa/{ULID}") == ULID
    assert _entire_refs.parse_ref(f"refs/entire/checkpoints/XX/{ULID}") is None
    assert _entire_refs.parse_ref(f"refs/entire/checkpoints/WA/x/{ULID}") is None
    with pytest.raises(ValueError, match="checkpoint id"):
        _entire_refs.ref_name("../../heads/main")


def test_per_checkpoint_ref_imports_through_the_claude_importer(source):
    events = entire_events(str(source))
    assert [event.kind for event in events] == ["human", "model", "tool"]
    assert events[1].model == "claude-sonnet-4-5"
    assert events[1].usage["input"] == 1200
    entire = events[0].attributes["entire"]
    assert entire["checkpoint_id"] == ULID
    assert entire["layout"] == "refs"
    assert entire["transcript_format"] == "claude-code-transcript"
    assert entire_events(f"{source}::01JD/0")[0].attributes["entire"]["session_index"] == 0


def test_v1_branch_is_the_fallback_and_both_layouts_list(source):
    _add_branch_checkpoint(source)
    found = _entire_refs.all_locations(source)
    assert [(item.checkpoint, item.base) for item in found] == [(ULID, ""), (HEX, "a3/b2c4d5e6f7")]
    old = entire_events(f"{source}::{HEX}")
    assert old[0].attributes["entire"]["layout"] == "branch"
    assert old[0].inputs == {"prompt": "old layout prompt"}


def test_no_checkpoints_is_refused(tmp_path):
    with pytest.raises(ValueError, match="refs/entire/checkpoints"):
        entire_events(str(_init(tmp_path / "empty")))


def test_import_all_records_one_run_per_session(source, tmp_path, capsys):
    _add_branch_checkpoint(source)
    target = tmp_path / "tine"
    Repo.init(target)
    cli.main(["import", str(source), "--all", "--repo", str(target), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["all"] is True
    refs = [row["ref"] for row in payload["runs"]]
    assert refs == [f"heads/entire/{ULID.lower()}/0", f"heads/entire/{HEX}/0"]
    assert all(row["run_id"] and row["events_imported"] for row in payload["runs"])


def test_import_all_refuses_without_repo(source, tmp_path):
    with pytest.raises(SystemExit):
        cli.main(["import", str(source), "--all", "--save", str(tmp_path / "x.tine")])
    with pytest.raises(SystemExit):
        cli.main(["import", str(source), "--all", "--format", "jsonl", "--repo", str(tmp_path)])


def test_export_entire_round_trips(source, tmp_path, capsys):
    saved = tmp_path / "run.tine"
    cli.main(["import", str(source), "--save", str(saved)])
    original = Run.load(saved)
    dest = _init(tmp_path / "dest")
    capsys.readouterr()
    cli.main(["export", str(saved), "--format", "entire", "--output", str(dest), "--json"])
    written = _wrapped(capsys.readouterr().out)
    assert written["ref"].startswith("refs/entire/checkpoints/")
    assert _git(dest, "log", "-1", "--format=%s", written["ref"]).strip() == (
        f"Checkpoint: {written['checkpoint_id']}"
    )
    trailers = _git(dest, "log", "-1", "--format=%b", written["ref"])
    assert "Entire-Agent: Claude Code" in trailers
    assert "Entire-Strategy: manual-commit" in trailers
    back = entire_events(str(dest))
    kinds = [s.v3_kind or s.kind.value for s in original.steps]
    assert [event.kind for event in back] == kinds
    models = [e for e in back if e.kind == "model"]
    assert models[0].model == "claude-sonnet-4-5"
    assert models[0].usage == {"input": 1200, "output": 80, "cache_read": 300}
    assert back[0].attributes["entire"]["layout"] == "refs"
    hash_line = _git(dest, "show", f"{written['ref']}:0/content_hash.txt")
    assert hash_line.startswith("sha256:")
    # Exporting again is idempotent: same ref, same commit.
    cli.main(["export", str(saved), "--format", "entire", "--output", str(dest), "--json"])
    assert _wrapped(capsys.readouterr().out)["commit"] == written["commit"]


def test_export_entire_refuses_non_repo_and_unusable_flags(source, tmp_path):
    saved = tmp_path / "run.tine"
    cli.main(["import", str(source), "--save", str(saved)])
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(SystemExit):
        cli.main(["export", str(saved), "--format", "entire", "--output", str(plain)])
    with pytest.raises(SystemExit):
        cli.main(["export", str(saved), "--format", "entire", "--output", str(plain), "--force"])
    with pytest.raises(SystemExit):
        cli.main(["export", str(saved), "--format", "entire"])
