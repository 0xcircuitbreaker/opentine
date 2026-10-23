"""0.12 git integration: Tine-Run trailers, refs/notes/tine, commit → runs, blame, bisect."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import opentine
from opentine import cli
from opentine._bisect import BisectError, exit_verdict, score_verdict, start
from opentine._blame import inserted_lines
from opentine._git_link import RUN_ID, GitLinkError, checked_revision, run_ids
from opentine._git_link_hook import MARKER, matches
from opentine.graph import Run, StepKind

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

WORKTREE = Path(opentine.__file__).resolve().parents[1]


def _git(cwd: Path, *args: str) -> str:
    env = {**os.environ, "PYTHONPATH": str(WORKTREE)}
    done = subprocess.run(
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True
    )
    return done.stdout


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "commit.gpgsign", "false")
    monkeypatch.chdir(root)
    monkeypatch.setattr(cli, "RUNS_DIR", Path(".tine_runs"))
    monkeypatch.setenv("PYTHONPATH", str(WORKTREE))
    return root


def _write_run(root: Path, run_id: str, path: str, content: str, *, tool: str = "Write") -> Run:
    run = Run(id=run_id, model_info="claude-opus-5-5")
    key = "content" if tool == "Write" else "new_string"
    run.add_step(
        StepKind.tool,
        {"name": tool, "arguments": {"file_path": str(root / path), key: content}},
    )
    (root / ".tine_runs").mkdir(exist_ok=True)
    run.save(root / ".tine_runs" / f"{run_id}.tine")
    return run


def _json(capsys, argv: list[str]) -> dict:
    capsys.readouterr()
    cli.main([*argv, "--json"])
    return json.loads(capsys.readouterr().out)


def _isolated_python_sees_this_tree() -> bool:
    # The hook runs `python -I`, which ignores PYTHONPATH: it can only reach this
    # tree when the interpreter's own site has it installed (as CI does).
    done = subprocess.run(
        [sys.executable, "-I", "-c", "import opentine; print(opentine.__file__)"],
        cwd=WORKTREE.parent,
        capture_output=True,
        text=True,
    )
    return done.returncode == 0 and Path(done.stdout.strip()).resolve().is_relative_to(WORKTREE)


def test_the_hook_adds_a_trailer_for_the_run_that_wrote_a_staged_file(repo, capsys):
    if not _isolated_python_sees_this_tree():
        pytest.skip("the interpreter's installed opentine is not this tree (hook runs python -I)")
    (repo / "seed.txt").write_text("seed\n")
    _git(repo, "add", "seed.txt")
    _git(repo, "commit", "-q", "-m", "seed")
    (repo / "src").mkdir()
    (repo / "src" / "a.py").write_text("print('agent wrote this')\n")
    run = _write_run(repo, "runaaaa1", "src/a.py", "print('agent wrote this')\n")
    _write_run(repo, "runbbbb2", "other/b.py", "x = 1\n")
    _json(capsys, ["git", "install-hook"])
    _git(repo, "add", "src/a.py")
    _git(repo, "commit", "-q", "-m", "add a")
    message = _git(repo, "log", "-1", "--format=%B")
    assert f"Tine-Run: {run.id}" in message
    assert "runbbbb2" not in message


def test_install_hook_chains_an_existing_hook_instead_of_replacing_it(repo, capsys):
    hooks = Path(_git(repo, "rev-parse", "--git-path", "hooks").strip())
    hooks = hooks if hooks.is_absolute() else repo / hooks
    hooks.mkdir(parents=True, exist_ok=True)
    mine = hooks / "prepare-commit-msg"
    mine.write_text('#!/bin/sh\necho mine > "$(git rev-parse --show-toplevel)/chained.flag"\n')
    mine.chmod(0o755)
    _json(capsys, ["git", "install-hook"])
    assert MARKER in mine.read_text()
    assert (hooks / "prepare-commit-msg.tine-chained").exists()
    _json(capsys, ["git", "install-hook"])  # idempotent: does not chain itself
    assert "mine" in (hooks / "prepare-commit-msg.tine-chained").read_text()
    if sys.platform != "win32":
        (repo / "f.txt").write_text("f\n")
        _git(repo, "add", "f.txt")
        _git(repo, "commit", "-q", "-m", "f")
        assert (repo / "chained.flag").exists()


def test_note_and_log_link_a_commit_to_its_runs(repo, capsys):
    run = _write_run(repo, "runnote01", "n.py", "n = 1\n")
    (repo / "n.py").write_text("n = 1\n")
    _git(repo, "add", "n.py")
    _git(repo, "commit", "-q", "-m", "n")
    noted = _json(capsys, ["git", "note", "HEAD", run.id])
    assert noted["runs"] == [run.id]
    assert "Tine-Model: claude-opus-5-5" in _git(repo, "notes", "--ref=refs/notes/tine", "show")
    logged = _json(capsys, ["git", "log", "--commit", "HEAD"])
    (row,) = logged["runs"]
    assert row["run"] == run.id and row["source"] == "note" and row["found"]
    assert row["model"] == "claude-opus-5-5"


def test_blame_finds_the_step_that_wrote_a_line(repo, capsys):
    (repo / "m.py").write_text("a = 1\nsecret_sauce = 42\n")
    _write_run(repo, "runwrite1", "m.py", "a = 1\n")
    edit = _write_run(repo, "runedit02", "m.py", "secret_sauce = 42", tool="Edit")
    result = _json(capsys, ["blame", "m.py:2"])
    (hit,) = result["hits"]
    assert hit["run_id"] == edit.id and hit["match"] == "line" and hit["tool"] == "Edit"
    writers = _json(capsys, ["blame", "m.py"])
    assert {item["run_id"] for item in writers["hits"]} == {"runwrite1", "runedit02"}


def test_blame_git_goes_commit_to_trailer_to_step(repo, capsys):
    run = _write_run(repo, "rungit001", "g.py", "value = 'from agent'\n")
    (repo / "g.py").write_text("value = 'from agent'\n")
    _git(repo, "add", "g.py")
    _git(repo, "commit", "-q", "-m", f"g\n\nTine-Run: {run.id}")
    result = _json(capsys, ["blame", "g.py:1", "--git"])
    assert result["commit"] and result["linked_runs"] == [run.id]
    assert [hit["run_id"] for hit in result["hits"]] == [run.id]


def test_bisect_run_finds_the_first_bad_fork(repo, capsys, tmp_path):
    names = [f"lin{index:05d}" for index in range(8)]
    for index, name in enumerate(names):
        run = Run(id=name, metadata={"forked_from": names[index - 1]} if index else {})
        run.add_step(StepKind.done, {"text": name})
        (repo / ".tine_runs").mkdir(exist_ok=True)
        run.save(repo / ".tine_runs" / f"{name}.tine")
    _json(capsys, ["bisect", "start", names[-1], names[0]])
    bad = {name for name in names[5:]}
    script = tmp_path / "eval.py"
    script.write_text(
        "import os, sys\n"
        f"sys.exit(1 if os.environ['OPENTINE_BISECT_RUN'] in {sorted(bad)!r} else 0)\n"
    )
    result = _json(capsys, ["bisect", "run", "--eval", f'"{sys.executable}" "{script}"'])
    assert result["done"] and result["first_bad"] == names[5]
    cli.main(["bisect", "reset"])
    with pytest.raises(SystemExit):
        cli.main(["bisect", "log"])


def test_bisect_by_recorded_score_over_an_explicit_run_list(repo, capsys):
    names = []
    for index, accuracy in enumerate([0.9, 0.95, 0.91, 0.4, 0.3]):
        name = f"model{index:03d}"
        run = Run(id=name, metadata={"scores": {"accuracy": accuracy}})
        run.add_step(StepKind.done, {"text": name})
        (repo / ".tine_runs").mkdir(exist_ok=True)
        run.save(repo / ".tine_runs" / f"{name}.tine")
        names.append(name)
    _json(capsys, ["bisect", "start", names[-1], names[0], "--runs", *names])
    result = _json(capsys, ["bisect", "run", "--score", "accuracy>=0.8"])
    assert result["first_bad"] == "model003"


def test_bisect_records_verdicts_as_repository_annotations(tmp_path, capsys, monkeypatch):
    from opentine.repository import Repo
    from opentine.repository._annotations import load_run_annotation

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "RUNS_DIR", Path(".tine_runs"))
    store = Repo.init(tmp_path / "r")
    oids = []
    for index in range(3):
        run = Run(id=f"rr{index:04d}")
        run.add_step(StepKind.done, {"text": str(index)})
        oids.append(store.put_run(run, ref=f"heads/r{index}").run_id)
    repo_args = ["--repo", str(store.path)]
    _json(capsys, ["bisect", "start", oids[2], oids[0], "--runs", *oids, *repo_args])
    result = _json(capsys, ["bisect", "bad", *repo_args])
    assert result["first_bad"] == oids[1]
    assert "bisect:bad" in load_run_annotation(Repo.open(store.path), oids[1])[1]


def test_values_from_git_are_checked_before_use():
    assert RUN_ID.match("run:sha256:" + "a" * 64)
    assert not RUN_ID.match("--upload-pack=x") and not RUN_ID.match("a b")
    with pytest.raises(GitLinkError):
        checked_revision("--output=/tmp/x")
    text = "subject\n\nTine-Run: good1234\nTine-Run: --evil\nTine-Run: good1234\n"
    assert run_ids(text) == ["good1234"]


def test_bisect_verdict_rules():
    assert [exit_verdict(code) for code in (0, 1, 125, 127)] == ["good", "bad", "skip", "bad"]
    with pytest.raises(BisectError):
        exit_verdict(130)
    assert score_verdict({"acc": 0.5}, "acc>=0.8") == "bad"
    assert score_verdict({}, "acc>=0.8") == "skip"
    with pytest.raises(BisectError):
        start(["a", "b", "c"], "c", "a", mode="runs")


def test_inserted_lines_reads_patches_for_the_target_file_only():
    class Step:
        inputs = {
            "name": "apply_patch",
            "arguments": {
                "input": "*** Begin Patch\n*** Update File: src/x.py\n@@\n-old\n+new line\n"
                "*** Update File: src/y.py\n@@\n+not this one\n*** End Patch\n"
            },
        }

    assert inserted_lines(Step(), "src/x.py") == {"new line"}
    assert matches("/abs/proj/src/x.py", Path("/abs/proj"), "src/x.py")
    assert not matches("/abs/other/src/x.py", Path("/abs/proj"), "src/x.py")


def test_hooks_run_python_isolated():
    # Audit 0.12 #1: git and agent hooks run inside project directories, where a
    # cloned repo could ship its own `opentine/` package.
    from opentine._cli_hook_agents import AGENTS, _tine, command
    from opentine._git_link_hook import _script

    assert " -I -m opentine.cli" in _script()
    argv = _tine()
    assert len(argv) == 1 or argv[1] == "-I"
    for agent in AGENTS.values():
        assert "-I" in command(agent, Path("/r")) or len(argv) == 1


def test_a_planted_opentine_package_in_the_repo_is_not_run_on_commit(repo, capsys, tmp_path):
    marker = tmp_path / "PWNED"
    (repo / "opentine").mkdir()
    (repo / "opentine" / "__init__.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    (repo / "opentine" / "cli.py").write_text("")
    _json(capsys, ["git", "install-hook"])
    (repo / "f.txt").write_text("a\n")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    subprocess.run(["git", "add", "f.txt"], cwd=repo, env=env, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "x"], cwd=repo, env=env, check=True)
    assert not marker.exists()


# -- 0.12 audit round 2: where the hook reads runs, future stamps, chaining ------


def _trailers_in(repo: Path, staged: str) -> str:
    _git(repo, "add", staged)
    message = repo / "MSG"
    message.write_text("subject\n")
    cli.main(["git", "trailers", str(message)])
    return message.read_text()


def test_the_hook_never_reads_a_cloned_working_trees_own_runs(repo):
    # A cloned project ships .tine_runs/ claiming it wrote the user's files; with
    # nothing configured by the user, the hook must credit no run at all.
    (repo / "a.py").write_text("x = 1\n")
    _write_run(repo, "runplant1", "a.py", "x = 1\n")
    assert "Tine-Run" not in _trailers_in(repo, "a.py")


def test_the_hook_reads_the_runs_the_user_configured_at_install(repo, capsys):
    (repo / "a.py").write_text("x = 1\n")
    run = _write_run(repo, "runconf01", "a.py", "x = 1\n")
    installed = _json(capsys, ["git", "install-hook"])
    assert Path(installed["runs_dir"]).is_absolute()
    # git may store the path with forward slashes on Windows: compare as paths.
    stored = _git(repo, "config", "--get", "tine.runsDir").strip()
    assert Path(stored) == Path(installed["runs_dir"])
    assert f"Tine-Run: {run.id}" in _trailers_in(repo, "a.py")


def test_writes_stamped_in_the_future_are_never_credited(repo, capsys, monkeypatch):
    import opentine._git_link_hook as hook

    (repo / "a.py").write_text("x = 1\n")
    _write_run(repo, "runfutur1", "a.py", "x = 1\n")
    _json(capsys, ["git", "install-hook"])
    # Seen from 1970, every recorded write lies in the future: none may count.
    monkeypatch.setattr(hook.time, "time", lambda: 0.0)
    monkeypatch.setattr(hook, "last_commit_time", lambda _cwd: 0.0)
    assert "Tine-Run" not in _trailers_in(repo, "a.py")


def test_the_global_hook_also_runs_the_repositorys_own_hook():
    from opentine._git_link_hook import _CLIENT_HOOKS, _script

    script = _script()
    assert "--git-common-dir" in script and '"$own" "$@"' in script
    assert f'grep -q "{MARKER}"' in script  # never re-runs itself
    for name in ("reference-transaction", "post-index-change", "sendemail-validate"):
        assert name in _CLIENT_HOOKS


# -- 0.12 audit round 4: git-link never runs a repository's own filter/textconv -------


def test_git_blame_never_runs_repo_defined_filters_or_textconv(repo, tmp_path):
    from opentine._blame import git_line

    (repo / "f.txt").write_text("one\ntwo\n")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "c1")
    marker = tmp_path / "filter-ran"
    command = f"{sys.executable} -c \"open({str(marker)!r}, 'w').write('x')\" #"
    (repo / ".gitattributes").write_text("* filter=evil diff=evil\n")
    _git(repo, "config", "filter.evil.clean", command)
    _git(repo, "config", "diff.evil.textconv", command)
    (repo / "f.txt").write_text("one\nTWO changed\n")  # uncommitted: work-tree blame would clean it
    sha, text = git_line(repo, "f.txt", 2)
    assert not marker.exists()
    assert sha and text == "two"


def test_a_run_id_with_a_newline_never_adds_a_forged_trailer(repo):
    from opentine._git_link_hook import add_trailers

    message = repo / "MSG"
    message.write_text("subject\n", encoding="utf-8")
    forged = "abcd\nSigned-off-by: Evil <e@x>"
    assert not RUN_ID.fullmatch(forged)
    add_trailers(repo, message, [forged, "run:sha256:" + "a" * 64])
    text = message.read_text(encoding="utf-8")
    assert "Signed-off-by" not in text and "Tine-Run: run:sha256:" + "a" * 64 in text


def test_tineignore_applies_when_capturing_from_a_subdirectory(repo):
    from opentine.trace.capture import code_manifest

    (repo / "secrets").mkdir()
    (repo / "secrets" / "k").write_text("TOKEN=old\n", encoding="utf-8")
    (repo / "sub").mkdir()
    (repo / "sub" / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    (repo / ".tineignore").write_text("secrets/\n", encoding="utf-8")
    (repo / "secrets" / "k").write_text("TOKEN=abc\n", encoding="utf-8")
    (repo / "sub" / "a.txt").write_text("b\n", encoding="utf-8")
    manifest = json.dumps(code_manifest(repo / "sub"))
    assert "TOKEN=abc" not in manifest and "+b" in manifest
