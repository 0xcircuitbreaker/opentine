"""0.11 audit round 3: git rev:path containment, action-index trust and links,
stale pack sets, and cached media in OpenAI usage."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from opentine.graph import Run, StepKind
from opentine.models._usage import openai_usage
from opentine.repository import Repo
from opentine.tools._git_guard import refusal


@pytest.fixture(autouse=True)
def _private_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


# --- git: rev:path is contained as a path too --------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ["diff", "f", "ab:c/../../../outside/s.txt"],
        ["show", "HEAD:../../etc/passwd"],
        ["diff", "C:/Users/x"],
        ["diff", "a\\b"],
        ["show", "HEAD:/etc/passwd"],
        ["log", ":(top)x"],
        ["rm", "x:y"],
    ],
)
def test_rev_path_tokens_cannot_leave_the_root(tmp_path, args):
    assert refusal(args, root=tmp_path) is not None


@pytest.mark.parametrize(
    "args",
    [["show", "HEAD:src/a.py"], ["diff", "HEAD~1:a", "HEAD:a"], ["log", "main"], ["blame", "x.py"]],
)
def test_ordinary_rev_paths_still_work(tmp_path, args):
    assert refusal(args, root=tmp_path) is None


# --- action index: links, foreign files and shipped rows -----------------------


def _runs(tmp_path: Path) -> Path:
    runs = tmp_path / "runs"
    runs.mkdir()
    run = Run(run_id="r1", model_info="m")
    run.add_step(StepKind.tool, {"name": "bash", "arguments": {"command": "rm -rf /tmp/x"}})
    run.add_step(StepKind.done, {"text": "ok"})
    run.save(runs / "r1.tine")
    return runs


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks needed")
def test_a_symlinked_index_is_refused_and_its_target_untouched(tmp_path):
    from opentine._actions_source import open_runs_dir

    runs = _runs(tmp_path)
    victim = tmp_path / "victim.db"
    db = sqlite3.connect(victim)
    db.execute("CREATE TABLE sources (x)")
    db.execute("INSERT INTO sources VALUES (1)")
    db.commit()
    db.close()
    try:
        (runs / "actions.sqlite").symlink_to(victim)
    except OSError:
        pytest.skip("cannot create symlinks here")
    with pytest.raises(ValueError, match="link"):
        open_runs_dir(runs)
    db = sqlite3.connect(victim)
    assert db.execute("SELECT count(*) FROM sources").fetchone()[0] == 1
    assert {row[0] for row in db.execute("SELECT name FROM sqlite_master")} == {"sources"}


def test_a_foreign_database_is_replaced_not_emptied_in_place(tmp_path):
    from opentine._actions_source import open_runs_dir

    runs = _runs(tmp_path)
    foreign = runs / "actions.sqlite"
    db = sqlite3.connect(foreign)
    db.execute("CREATE TABLE mine (x)")
    db.commit()
    db.close()
    index, report = open_runs_dir(runs)
    assert report.indexed == 1
    names = {row[0] for row in index.db.execute("SELECT name FROM sqlite_master")}
    index.close()
    assert "mine" not in names


def test_a_shipped_index_with_forged_rows_is_rebuilt(tmp_path):
    from opentine._actions_query import ActionQuery, find
    from opentine._actions_source import open_runs_dir

    runs = _runs(tmp_path)
    index, _ = open_runs_dir(runs)
    index.db.execute("DELETE FROM actions")  # a shipped copy that hides the action
    index.db.commit()
    stamp = index.db.execute("SELECT value FROM meta WHERE key='stamp'").fetchone()[0]
    index.close()
    # Same file, but this machine's key changes (another user's clone).
    key = Path(os.environ["XDG_CONFIG_HOME"], "opentine", "actions-index.key")
    key.write_text("f" * 64)
    index, _ = open_runs_dir(runs)
    assert index.db.execute("SELECT value FROM meta WHERE key='stamp'").fetchone()[0] != stamp
    assert find(index, ActionQuery(program="rm"))
    index.close()


# --- packs: another process repacked -------------------------------------------


def test_a_stale_pack_set_recovers_after_a_repack_elsewhere(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENTINE_COMPRESS", "zlib")
    from opentine.repository._gc import gc
    from opentine.repository._packs import _CACHE

    repo = Repo.init(tmp_path / "r")
    oids = [repo.put("blob", f"payload {i}".encode() * 40) for i in range(8)]
    gc(repo)
    assert repo.get(oids[0]).body  # this process caches the first pack set
    stale = _CACHE[str(repo.path)]
    first = dict(stale.where)
    _CACHE.pop(str(repo.path))
    extra = repo.put("blob", b"later object " * 40)
    gc(Repo.open(repo.path))  # a "second process" repacks everything
    _CACHE[str(repo.path)] = stale  # the first process still holds its old view
    assert stale.where == first
    for oid in [*oids, extra]:
        assert repo.get(oid).body


# --- OpenAI usage: cached audio does not move text into the audio bucket ------


def test_cached_audio_is_not_carved_out_of_fresh_text():
    usage = openai_usage(
        {
            "input_tokens": 1000,
            "output_tokens": 10,
            "input_tokens_details": {
                "cached_tokens": 900,
                "audio_tokens": 950,
                "text_tokens": 50,
                "cached_tokens_details": {"audio_tokens": 880, "text_tokens": 20},
            },
        }
    )
    assert usage.cache_read == 900
    assert usage.extra.get("input_audio") == 70
    assert usage.input == 30
