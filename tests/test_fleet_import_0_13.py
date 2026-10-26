"""0.13 ``tine import --fleet``: subagents as child runs forked at their spawning step.

Fixtures are synthetic Claude Code transcripts in the documented shape (session
file + ``<session>/subagents/agent-<id>.jsonl``).
"""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from opentine import _agent_identity as identity
from opentine import cli
from opentine._import_fleet import fleet_cost, ref_component
from opentine.repo import Repo

MODEL = "claude-opus-4-5"


def _call(uuid, message_id, *, session="s1", tool=None, text="ok"):
    content = [{"type": "text", "text": text}]
    if tool:
        content.append(
            {"type": "tool_use", "id": tool[0], "name": "Agent",
             "input": {"subagent_type": tool[1], "prompt": "look"}}
        )  # fmt: skip
    return {
        "sessionId": session,
        "timestamp": "2026-10-20T00:00:00Z",
        "type": "assistant",
        "uuid": uuid,
        "message": {
            "id": message_id,
            "model": MODEL,
            "role": "assistant",
            "usage": {"input_tokens": 1000, "output_tokens": 100},
            "content": content,
        },
    }


def _result(uuid, call, agent):
    return {
        "sessionId": "s1",
        "timestamp": "2026-10-20T00:00:01Z",
        "type": "user",
        "uuid": uuid,
        "toolUseResult": {"agentId": agent, "status": "completed"},
        "message": {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": call, "content": "done"}],
        },
    }


def _write(path, lines):
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))


def session(tmp_path):
    main = tmp_path / "s1.jsonl"
    prompt = {"sessionId": "s1", "timestamp": "2026-10-20T00:00:00Z", "type": "user",
              "uuid": "u1", "message": {"role": "user", "content": "review it"}}  # fmt: skip
    _write(main, [prompt, _call("a1", "m1", tool=("t1", "Explore")), _result("u2", "t1", "a0")])
    folder = tmp_path / "s1" / "subagents"
    folder.mkdir(parents=True)
    # a0 spawns a nested a1; a2 has no spawning tool result at all (an orphan).
    _write(folder / "agent-a0.jsonl",
           [_call("b1", "m2", tool=("t2", "reviewer")), _result("u3", "t2", "a1")])  # fmt: skip
    _write(folder / "agent-a1.jsonl", [_call("c1", "m3")])
    _write(folder / "agent-a2.jsonl", [_call("d1", "m4")])
    return main


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "repo")


def _import(source, repo, *extra):
    cli.main(["import", str(source), "--format", "claude-code-transcript", "--price",
              "--repo", str(repo.path), *extra])  # fmt: skip


def test_fleet_import_forks_each_subagent_and_costs_the_same(tmp_path, repo, capsys):
    source = session(tmp_path)
    _import(source, repo)
    single = repo.load_run(repo.read_ref("heads/main"))
    _import(source, repo, "--fleet", "--ref", "heads/fleet-root", "--json")
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    manifest = out["fleet"]
    assert manifest["format"] == "opentine-fleet/1"
    members = {m["agent_id"]: m for m in manifest["members"]}
    assert set(members) == {"a0", "a1", "a2"}
    assert members["a0"]["agent_type"] == "Explore" and members["a1"]["agent_type"] == "reviewer"
    assert members["a0"]["parent_run"] == manifest["root"]
    assert members["a1"]["parent_run"] == members["a0"]["run_id"]  # nested: forked from a0
    assert members["a2"]["spawn_step"] == ""  # orphan tolerated
    assert Decimal(out["cost_usd"]) == fleet_cost(repo, manifest)
    assert fleet_cost(repo, manifest) == pytest.approx(Decimal(str(single.total_cost)))
    root = repo.load_run(manifest["root"])
    assert root.metadata["opentine.fleet"]["root"] == manifest["root"]
    child = repo.load_run(members["a1"]["run_id"])
    record = identity.run_identity(child)
    parent = identity.run_identity(repo.load_run(members["a0"]["run_id"]))
    assert record["harness"] == "claude-code/reviewer"
    assert record["parent"] == identity.agent_ref(parent)
    assert record["spawn_step"] == members["a1"]["spawn_step"] != ""
    assert repo.read_ref(members["a0"]["ref"]) == members["a0"]["run_id"]


def test_plain_transcript_import_records_an_agent_identity(tmp_path, repo):
    _import(session(tmp_path), repo)
    run = repo.load_run(repo.read_ref("heads/main"))
    assert identity.run_agent_ref(run).startswith("agt_")
    assert identity.run_identity(run)["harness"] == "claude-code"


def test_fleet_needs_a_repository_and_a_claude_session(tmp_path, repo):
    with pytest.raises(SystemExit):
        cli.main(["import", str(session(tmp_path)), "--fleet", "--save", str(tmp_path / "x")])
    other = tmp_path / "h.jsonl"
    other.write_text(json.dumps({"conversations": [{"from": "human", "value": "hi"}]}) + "\n")
    with pytest.raises(SystemExit):
        cli.main(["import", str(other), "--fleet", "--repo", str(repo.path)])


@pytest.mark.parametrize("hostile", ["../../etc", "A" * 300, "x.lock", "..", "con", "аdmin", "a/b"])
def test_hostile_agent_ids_become_safe_ref_components(hostile):
    from opentine.repository._refs import normalize_ref

    name = ref_component(hostile)
    assert normalize_ref(f"heads/fleet/abc/{name}")
    assert "/" not in name and ".." not in name and len(name) <= 64


def test_fleet_cost_reads_an_imported_fleet(tmp_path, repo, capsys):
    _import(session(tmp_path), repo, "--fleet", "--json")
    manifest = json.loads(capsys.readouterr().out.strip().splitlines()[-1])["fleet"]
    with pytest.raises(SystemExit):
        cli.main(["fleet", "cost", "heads/main", "--repo", str(repo.path), "--json"])
    report = json.loads(capsys.readouterr().out)
    assert report["fleet"] == manifest["root"]
    assert Decimal(report["cost_usd"]) == fleet_cost(repo, manifest)
