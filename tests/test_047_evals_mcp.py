"""0.47: push-triggered evals (``.tine/evals.toml``), MCP ``recall`` memory, MCP tasks.

``tine eval ci`` runs every declared eval, signs its verdicts and gates on each
``min_pass_rate``; a registered judge prompt is pinned into every verdict's
``scorer_version``. ``recall`` returns team-signed notes beside the runs it
finds. A 2025-11-25 ``tools/call`` with ``task`` becomes a task that
``tasks/get``, ``tasks/result``, ``tasks/list`` and ``tasks/cancel`` follow.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _eval_judge, _memory, _prompt, _schemas, cli
from opentine._eval_ci import ConfigError, judge_template, load
from opentine._eval_run import read_verdicts, verify_eval
from opentine._mcp_tasks import MAX_TASKS, TaskError, TaskStore
from opentine.repository import Repo
from opentine.repository import _registry_refs as refs

WHEN = "2026-11-09T00:00:00Z"
SEED = bytes(range(32))
pytestmark = pytest.mark.filterwarnings("ignore:.*plaintext-hex private key")


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    monkeypatch.chdir(tmp_path)
    Repo.init(tmp_path)
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    (tmp_path / "k.key").write_text(key.private_bytes_raw().hex())
    (tmp_path / "k.pub").write_text(key.public_key().public_bytes_raw().hex())
    rows = [
        {
            "id": f"q{i}",
            "input": f"{i}*2",
            "expected": str(i * 2),
            "output": "nope" if i == 0 else str(i * 2),
            "run": "run:fixture",
        }
        for i in range(4)
    ]
    (tmp_path / "evals").mkdir()
    (tmp_path / "evals" / "d.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    return tmp_path


def _ci(capsys, *extra: str) -> tuple[int, dict]:
    capsys.readouterr()
    try:
        cli.main(["eval", "ci", "--key", "k.key", "--created-at", WHEN, "--json", *extra])
        code = 0
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _config(room: Path, body: str) -> None:
    (room / ".tine" / "evals.toml").write_text(body, encoding="utf-8")


def test_eval_ci_runs_every_eval_and_gates_on_the_pass_rate(room, capsys):
    _config(room, '[defaults]\nmin_pass_rate = 0.7\n\n'
                  '[[eval]]\nname = "smoke"\ndataset = "evals/d.jsonl"\nscorer = "exact"\n\n'
                  '[[eval]]\nname = "strict"\ndataset = "evals/d.jsonl"\nscorer = "exact"\n'
                  'min_pass_rate = 1.0\n')  # fmt: skip
    code, row = _ci(capsys)
    assert code == 1 and row["ok"] is False, row
    assert [(e["name"], e["passed"], e["items"], e["ok"]) for e in row["evals"]] == [
        ("smoke", 3, 4, True), ("strict", 3, 4, False)]  # fmt: skip
    assert _schemas.validate_output(row) == []
    smoke = Path(row["evals"][0]["dir"])
    assert verify_eval(smoke, public_key=bytes.fromhex((room / "k.pub").read_text()))["ok"]
    _config(room, '[[eval]]\nname = "smoke"\ndataset = "evals/d.jsonl"\nscorer = "exact"\n'
                  'min_pass_rate = 0.75\n')  # fmt: skip
    code, row = _ci(capsys)
    assert code == 0 and row["ok"] and row["evals"][0]["judge_prompt"] is None


@pytest.mark.parametrize("body", [
    "",  # no [[eval]]
    '[[eval]]\nname = "a"\ndataset = "d"\n',  # no scorer
    '[[eval]]\nname = "a"\ndataset = "d"\nscorer = "exact"\nshell = "rm -rf /"\n',
    '[[eval]]\nname = "A b"\ndataset = "d"\nscorer = "exact"\n',
    '[[eval]]\nname = "a"\ndataset = "d"\nscorer = "exact"\nmin_pass_rate = 2\n',
])  # fmt: skip
def test_a_bad_config_is_refused_before_anything_runs(tmp_path, body):
    path = tmp_path / "evals.toml"
    path.write_text(body)
    with pytest.raises(ConfigError):
        load(path)


def test_a_registered_judge_prompt_is_pinned_into_every_verdict(room, capsys, monkeypatch):
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    text = "Grade {{output}} against {{expected}} for {{input}}. Use {braces}.\nSCORE: <n>"
    record = _prompt.sign(_prompt.build("judge", text, created_at=WHEN), key)
    repo = Repo.open(room)
    refs.push_prompt(repo, record)
    refs.set_label(repo, "judge", "production")
    seen = []

    class Fake:
        async def complete(self, messages, **_):
            seen.append(messages[0]["content"])
            return {"text": "SCORE: 1"}

    monkeypatch.setattr(_eval_judge, "_model", lambda spec: Fake())
    monkeypatch.setattr(cli, "RUNS_DIR", room / "runs")
    _config(
        room,
        '[[eval]]\nname = "judged"\ndataset = "evals/d.jsonl"\n'
        'scorer = "llm-judge:ollama:tiny"\njudge_prompt = "judge@production"\n',
    )
    code, row = _ci(capsys)
    assert code == 0, row
    link = row["evals"][0]["judge_prompt"]
    assert link == {"name": "judge", "version": 1, "digest": _prompt.digest(record)}
    assert seen[0].startswith("Grade nope against 0 for 0*2. Use {braces}.")
    versions = {v["scorer_version"] for v in read_verdicts(Path(row["evals"][0]["dir"]))}
    assert len(versions) == 1  # every verdict pins the same registered template
    assert "Use {{braces}}" in judge_template(record)  # literal braces are escaped


def test_a_judge_prompt_with_other_variables_is_refused():
    record = _prompt.build("judge", "Grade {{answer}}", created_at=WHEN)
    with pytest.raises(ConfigError):
        judge_template(record)


# --- MCP: recall returns team memory ---------------------------------------- #


def test_recall_returns_team_notes_only(room):
    from opentine._mcp_recall import recall_index

    repo = Repo.open(room)
    mine = Ed25519PrivateKey.from_private_bytes(SEED)
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    for key, text in ((mine, "Deploys need the staging flag"), (other, "Deploys skip review")):
        note = _memory.build("team", "deploys", text, author="a", created_at=WHEN)
        refs.add_note(repo, _memory.sign(note, key))
    assert recall_index(repo, "deploys")["memories"] == []  # no team file yet
    team = {"keys": [mine.public_key().public_bytes_raw().hex()]}
    (room / ".tine" / "memory-team.json").write_text(json.dumps(team))
    found = recall_index(repo, "deploys staging")["memories"]
    assert [m["text"] for m in found] == ["Deploys need the staging flag"]
    assert found[0]["state"] == "verified"


# --- MCP: tasks --------------------------------------------------------------- #


def test_the_task_store_clamps_expires_and_never_keeps_a_late_result():
    now = [1000.0]
    store = TaskStore(clock=lambda: now[0])
    task = store.create(10)
    assert task["ttl"] == 1000 and task["status"] == "working"
    store.cancel(task["taskId"])
    store.complete(task["taskId"], {"content": []})
    assert store.wire(task["taskId"])["status"] == "cancelled"
    with pytest.raises(TaskError):
        store.result(task["taskId"])
    now[0] += 2
    with pytest.raises(TaskError):
        store.wire(task["taskId"])  # expired and forgotten
    long = store.create(10**9)
    assert long["ttl"] == 3_600_000
    for _ in range(MAX_TASKS - 1):
        store.create()
    with pytest.raises(TaskError):
        store.create()  # every slot is working: refuse, never drop a live task
    store.fail(long["taskId"], "boom")
    assert store.create()["status"] == "working"  # the finished one makes room
    with pytest.raises(TaskError):
        store.wire(long["taskId"])


def test_cancelling_or_expiring_a_task_stops_its_tool():
    from dataclasses import dataclass

    from opentine._mcp_tasks import TaskMiddleware

    @dataclass
    class Ctx:
        method: str
        protocol_version: str
        params: dict

    now = [1000.0]
    store = TaskStore(clock=lambda: now[0])
    landed: list[str] = []

    async def slow(ctx):
        await asyncio.sleep(3600)
        landed.append(ctx.params["name"])  # a write that must never land

    async def scenario() -> list:
        mw = TaskMiddleware(store)
        ctxs = [Ctx("tools/call", "2025-11-25", {"name": n, "task": {"ttl": 1000}}) for n in "ab"]
        mw_tasks = [await mw(ctx, slow) for ctx in ctxs]
        await asyncio.sleep(0)
        store.cancel(mw_tasks[0]["task"]["taskId"])
        now[0] += 5
        store.list()  # the second one expires
        await asyncio.sleep(0.05)
        return [t["task"]["taskId"] for t in mw_tasks]

    asyncio.run(scenario())
    assert landed == []
    assert store._work == {}


def test_a_task_augmented_tool_call_runs_in_the_background(tmp_path, monkeypatch):
    pytest.importorskip("mcp.server.mcpserver")
    from mcp import Client

    from opentine import mcp_server

    monkeypatch.chdir(tmp_path)
    server = mcp_server.create_server(read_only=True)

    async def scenario() -> tuple:
        async with Client(server, mode="legacy") as client:
            session = client.session
            assert session.protocol_version == "2025-11-25"
            raw = session._dispatcher.send_raw_request
            created = await raw("tools/call", {"name": "list_runs", "arguments": {},
                                               "task": {"ttl": 60000}}, {})  # fmt: skip
            task_id = created["task"]["taskId"]
            for _ in range(200):
                got = await raw("tasks/get", {"taskId": task_id}, {})
                if got["status"] != "working":
                    break
                await asyncio.sleep(0.01)
            result = await raw("tasks/result", {"taskId": task_id}, {})
            listed = await raw("tasks/list", {}, {})
            plain = await client.call_tool("list_runs", {})
            return created, got, result, listed, plain

    created, got, result, listed, plain = asyncio.run(scenario())
    assert created["task"]["status"] == "working" and len(created["task"]["taskId"]) == 32
    assert got["status"] == "completed"
    assert result["isError"] is False and result["structuredContent"] == {"result": []}
    assert [t["taskId"] for t in listed["tasks"]] == [created["task"]["taskId"]]
    assert plain.is_error is False  # without `task`, a call is answered directly


@pytest.mark.parametrize(
    "body",
    [
        '[[eval]]\nname = "a"\ndataset = "../outside.jsonl"\nscorer = "exact"\n',
        '[[eval]]\nname = "a"\ndataset = "/etc/passwd"\nscorer = "exact"\n',
        '[[eval]]\nname = "a"\ndataset = "C:/x.jsonl"\nscorer = "exact"\n',
        '[[eval]]\nname = "a"\ndataset = "d.jsonl"\noutputs = "a\\\\b"\nscorer = "exact"\n',
        '[defaults]\nthreshhold = 0.5\n[[eval]]\nname = "a"\ndataset = "d"\nscorer = "exact"\n',
        'evals = 1\n[[eval]]\nname = "a"\ndataset = "d.jsonl"\nscorer = "exact"\n',
    ],
)
def test_an_eval_config_cannot_leave_the_repository_or_misspell_a_key(tmp_path, body):
    path = tmp_path / "evals.toml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ConfigError):
        load(path)
