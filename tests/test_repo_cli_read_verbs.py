"""The v3 read verbs: ``repo-show``, ``context``, and ``repo-log --json``.

Phase 2 of the Surface Release exposes engines that already existed and were only
reachable over MCP. Three properties have to hold for that exposure to be safe:

  * **Backwards compatibility is a release gate.** Every read verb runs over the
    committed golden repositories of every release >= 0.3.0
    (``tests/fixtures/compat/vX_Y_Z/repo``), copied out read-only, because a read
    verb that only works on a repository this build wrote is not a read verb.
  * **Repository content is untrusted.** A v3 payload records whatever the agent
    saw, including text an attacker supplied. Ids, prompts, models, and tool names
    must reach the terminal through ``_terminal``, so no recorded string can emit
    an escape sequence or forge Rich markup.
  * **A refusal is a refusal.** A shallow clone cannot materialize a run; that must
    read as one clean stderr line and exit 1, never a traceback.

Everything runs in-process through ``opentine.cli.main`` — no subprocess, so no
binary needs to exist on PATH.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from opentine import cli
from opentine.repository import Repo
from opentine.repository._run_blobs import json_blob
from opentine.repository.pack import create_pack, install_pack, reachable

COMPAT = Path(__file__).parent / "fixtures" / "compat"
VERSIONS = ("v0_3_0", "v0_4_0", "v0_5_0")

#: Recorded content chosen to be hostile: an OSC-52 clipboard write, a CSI byte, a
#: NUL, a bidi override, and a Rich end-tag that would close styling early.
HOSTILE = "[/bold]\x1b]52;c;pwn\x1b\\ \x9b31m\x00 re‮versed ⁦iso⁩"
CONTROL = {"\x1b", "\x9b", "\x00", "‮", "⁦", "⁩"}


def _invoke(monkeypatch, *args: str) -> None:
    """In-process, with argv monkeypatched exactly as tests/test_cli.py does."""
    import sys

    monkeypatch.setattr(sys, "argv", ["tine", *args])
    cli.main()


def _json_out(capsys) -> dict:
    out = capsys.readouterr().out
    return json.loads(out)


@pytest.fixture(params=VERSIONS, ids=VERSIONS)
def golden_repo(request, tmp_path: Path) -> Path:
    """A released repository copied out of the source tree, never mutated in place.

    Reading a repo writes reflogs and recreates the scratch directories git drops,
    so the committed fixture is copied first; the copy also proves the store is
    relocatable, which is a real cross-version property.
    """
    dest = tmp_path / request.param
    shutil.copytree(COMPAT / request.param / "repo", dest)
    return dest


def _events(repo_path: Path) -> list[str]:
    repo = Repo.open(repo_path)
    payload = repo.get(repo.read_ref("heads/main")).payload()
    return list(payload["events"])


# --- cross-version: every read verb over every released repository -----------


def test_repo_show_renders_every_released_repository(monkeypatch, golden_repo, capsys):
    _invoke(monkeypatch, "repo-show", "heads/main", "--repo", str(golden_repo))
    out = capsys.readouterr().out
    assert "completed" in out and "steps=4" in out
    # The v3 fact the reused compatibility tree cannot know, in short-oid form.
    assert "object: run:" in out


def test_repo_show_json_over_every_released_repository(monkeypatch, golden_repo, capsys):
    _invoke(monkeypatch, "repo-show", "heads/main", "--repo", str(golden_repo), "--json")
    payload = _json_out(capsys)
    assert payload["command"] == "repo-show"
    assert payload["ref"] == "heads/main"
    assert payload["run_object_id"].startswith("run:sha256:")
    assert payload["run"]["step_count"] == len(payload["steps"]) == 4
    assert payload["run"]["status"] == "completed"
    assert {"id", "status", "model", "created_at", "total_cost", "step_count", "tags"} <= set(
        payload["run"]
    )
    # short_id is a 12-character prefix, which on a v3 oid is the constant
    # "event:sha25"; the v3 schema drops it rather than emit a useless field.
    assert "short_id" not in payload["run"] and "short_id" not in payload["steps"][0]
    assert payload["steps"][0]["id"].startswith("event:sha256:")
    assert [step["kind"] for step in payload["steps"]] == ["model", "tool", "think", "done"]


def test_repo_show_accepts_a_run_oid_as_well_as_a_ref(monkeypatch, golden_repo, capsys):
    repo = Repo.open(golden_repo)
    oid = repo.read_ref("heads/main")
    _invoke(monkeypatch, "repo-show", oid, "--repo", str(golden_repo), "--json")
    payload = _json_out(capsys)
    assert payload["ref"] == oid and payload["run_object_id"] == oid


def test_context_over_every_released_repository(monkeypatch, golden_repo, capsys):
    tip = _events(golden_repo)[-1]
    _invoke(monkeypatch, "context", tip, "--repo", str(golden_repo))
    out = capsys.readouterr().out
    assert "# context" in out and f"event:{tip.split(':')[2][:12]}" in out
    assert "model" in out and "tool" in out


def test_context_json_over_every_released_repository(monkeypatch, golden_repo, capsys):
    events = _events(golden_repo)
    _invoke(monkeypatch, "context", events[-1], "--repo", str(golden_repo), "--json")
    payload = _json_out(capsys)
    assert payload["command"] == "context"
    assert payload["event"] == events[-1]
    assert payload["depth"] == 8  # the MCP context_slice default, mirrored
    assert payload["count"] == len(payload["entries"])
    assert [entry["oid"] for entry in payload["entries"]] == events  # oldest first
    assert {entry["object_type"] for entry in payload["entries"]} == {"event"}
    assert [entry["kind"] for entry in payload["entries"]] == ["model", "tool", "think", "done"]
    assert "payload" not in payload["entries"][0]


def test_context_depth_bounds_the_slice(monkeypatch, golden_repo, capsys):
    events = _events(golden_repo)
    repo = str(golden_repo)
    _invoke(monkeypatch, "context", events[-1], "--repo", repo, "--depth", "1", "--json")
    payload = _json_out(capsys)
    assert [entry["oid"] for entry in payload["entries"]] == events[-2:]


def test_repo_log_json_over_every_released_repository(monkeypatch, golden_repo, capsys):
    _invoke(monkeypatch, "repo-log", "heads/main", "--repo", str(golden_repo), "--json")
    payload = _json_out(capsys)
    assert payload["command"] == "repo-log"
    assert payload["ref"] == "heads/main"
    assert payload["count"] == len(payload["entries"]) == 4
    assert set(payload["entries"][0]) == {"oid", "object_type", "kind"}


def test_repo_log_json_mirrors_the_human_line(monkeypatch, golden_repo, capsys):
    _invoke(monkeypatch, "repo-log", "heads/main", "--repo", str(golden_repo))
    # Token comparison, not line comparison: a 77-character oid plus its kind is
    # wider than the 80-column console, so the human line soft-wraps.
    human = capsys.readouterr().out.split()
    _invoke(monkeypatch, "repo-log", "heads/main", "--repo", str(golden_repo), "--json")
    entries = _json_out(capsys)["entries"]
    assert human == [token for entry in entries for token in (entry["oid"], entry["kind"])]


# --- untrusted repository content --------------------------------------------


def _hostile_repo(path: Path) -> tuple[str, str]:
    repo = Repo.init(path)
    prompt = repo.put("blob", HOSTILE.encode())
    # json_blob, not a hand-rolled dump: content blobs are canonical or the reader
    # refuses them, and this fixture must be a run the engine really loads.
    inputs = json_blob(repo, {"text": HOSTILE})
    event = repo.put(
        "event",
        {
            "cost": 1.0,
            "input_blob": inputs,
            "kind": "model",
            "model": HOSTILE,
            "parent_ids": [],
            "tool": {"name": HOSTILE},
        },
    )
    run = repo.put(
        "run",
        {
            "events": [event],
            "model": HOSTILE,
            "prompt_blob": prompt,
            "roots": [event],
            "source_run_id": HOSTILE,
            "status": "completed",
            "system_blob": prompt,
            "tips": [event],
        },
    )
    repo.update_ref("heads/main", run)
    return run, event


def test_repo_show_cannot_be_injected_by_recorded_content(monkeypatch, tmp_path, capsys):
    # Mirrors tests/test_cli.py's .tine sanitization test for the v3 side: a run
    # whose id, model, prompts, and step text are all attacker-chosen.
    _hostile_repo(tmp_path / "repo")

    _invoke(monkeypatch, "repo-show", "heads/main", "--repo", str(tmp_path / "repo"))

    out = capsys.readouterr().out
    assert not CONTROL & set(out), "recorded content emitted a terminal control byte"
    # Escaped, not executed: the closing tag survives as literal text, and the
    # bidi/NUL/CSI bytes are gone while the readable characters remain.
    assert "[/bold]" in out and "52;c;pwn" in out


def test_context_cannot_be_injected_by_recorded_content(monkeypatch, tmp_path, capsys):
    _, event = _hostile_repo(tmp_path / "repo")

    _invoke(monkeypatch, "context", event, "--repo", str(tmp_path / "repo"))

    out = capsys.readouterr().out
    assert not CONTROL & set(out)
    assert "[/bold]" in out  # the model/tool strings reached the line, escaped


def test_repo_log_cannot_be_injected_by_recorded_content(monkeypatch, tmp_path, capsys):
    _hostile_repo(tmp_path / "repo")

    _invoke(monkeypatch, "repo-log", "heads/main", "--repo", str(tmp_path / "repo"))

    assert not CONTROL & set(capsys.readouterr().out)


def test_hostile_content_survives_json_without_escaping(monkeypatch, tmp_path, capsys):
    # --json is not a terminal: the bytes must round-trip verbatim through the
    # single writer, so a consumer sees exactly what was recorded.
    _hostile_repo(tmp_path / "repo")
    _invoke(monkeypatch, "repo-show", "heads/main", "--repo", str(tmp_path / "repo"), "--json")
    payload = _json_out(capsys)
    assert payload["run"]["id"] == HOSTILE and payload["steps"][0]["model"] == HOSTILE


# --- refusals ----------------------------------------------------------------


def _shallow_clone(tmp_path: Path) -> tuple[Path, str]:
    """A depth-1 clone exactly as ``fetch --depth 1`` produces one."""
    src = Repo.init(tmp_path / "src")
    first = src.put("event", {"cost": 1.0, "kind": "model", "parent_ids": []})
    second = src.put("event", {"cost": 2.0, "kind": "model", "parent_ids": [first]})
    run = src.put(
        "run",
        {"events": [first, second], "roots": [first], "status": "completed", "tips": [second]},
    )
    src.update_ref("heads/main", run)
    dst = Repo.init(tmp_path / "dst")
    install_pack(dst, create_pack(src, reachable(src, [run], depth=1)))
    dst.update_ref("heads/main", run)
    return tmp_path / "dst", second


def test_repo_show_on_a_shallow_clone_refuses_cleanly(monkeypatch, tmp_path, capsys):
    shallow, _ = _shallow_clone(tmp_path)

    with pytest.raises(SystemExit) as exited:
        _invoke(monkeypatch, "repo-show", "heads/main", "--repo", str(shallow))

    assert exited.value.code == 1
    captured = capsys.readouterr()
    assert captured.err.startswith("tine repo-show: ")
    assert "deepen the fetch" in captured.err
    assert "Traceback" not in captured.err and captured.err.count("\n") == 1


def test_context_on_a_shallow_clone_stops_at_the_boundary(monkeypatch, tmp_path, capsys):
    # context_slice is a partial read, so unlike repo-show it succeeds — it just
    # stops where the fetch was cut, the way git log does.
    shallow, tip = _shallow_clone(tmp_path)
    _invoke(monkeypatch, "context", tip, "--repo", str(shallow), "--json")
    assert [entry["oid"] for entry in _json_out(capsys)["entries"]] == [tip]


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (("context", "not-an-oid"), "invalid typed object id"),
        (("context", "blob:sha256:" + "0" * 64), "context slices require an event id"),
        (("context", "event:sha256:" + "0" * 64, "--depth", "-1"), "non-negative integer"),
        (("repo-show", "heads/nope"), "no such ref or object"),
    ],
)
def test_engine_refusals_surface_through_the_existing_envelope(
    monkeypatch, tmp_path, capsys, argv, message
):
    Repo.init(tmp_path / "repo")

    with pytest.raises(SystemExit) as exited:
        _invoke(monkeypatch, *argv, "--repo", str(tmp_path / "repo"))

    assert exited.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith(f"tine {argv[0]}: ") and message in err


def test_a_hostile_ref_name_cannot_inject_through_the_error_envelope(monkeypatch, tmp_path, capsys):
    Repo.init(tmp_path / "repo")

    with pytest.raises(SystemExit):
        _invoke(monkeypatch, "context", HOSTILE, "--repo", str(tmp_path / "repo"))

    assert not CONTROL & set(capsys.readouterr().err)
