"""0.88 acceptance, end to end: one agent tree goes through every new piece.

A scaffold manifest is built for the tree and signed onto a stored run; an MCP
session is recorded and its call carries the pinned ``tool_def_digest``; the
tree is recorded as a ``skill`` lineage variant; a later variant swaps the tool
schema and the prompt; ``tine lineage diff`` signs the structural diff, its tool
digests are the very digests the proxy recorded, and ``--check`` recomputes it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _schemas, cli
from opentine._mcp_tool_pins import CHANGED, tool_def_digest
from opentine._scaffold_manifest import build
from tests.promote_helpers import AT, PROMOTER, key, write_key

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")

SHELL = {"name": "shell", "description": "Run a command",
         "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}}}  # fmt: skip
WIDER = {**SHELL, "inputSchema": {"type": "object", "properties": {"cmd": {}, "env": {}}}}


def _tree(root: Path, tool: dict, rules: str) -> Path:
    files = {
        "CLAUDE.md": "# Agent\n@prompts/system.md\n",
        "prompts/system.md": f"# Role\nYou are careful.\n\n## Rules\n{rules}\n",
        ".claude/skills/s/SKILL.md": "# Skill\nDo the task.\n",
        "tools.json": json.dumps({"tools": [tool]}),
        "agent.py": "def act(x, retries=3):\n    return x\n",
    }
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(text.encode("utf-8"))
    return root


def _tine(capsys, *argv: str):
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    out = capsys.readouterr().out
    document = json.loads(out)
    assert _schemas.validate_output(document) == [], document
    return code, document


def _line(obj) -> bytes:
    return (json.dumps(obj) + "\n").encode()


def test_scaffold_manifest_tool_pins_skill_lineage_and_signed_diff(tmp_path, capsys, monkeypatch):
    from opentine import _containment_records as records
    from opentine._lineage import record as lineage_record
    from opentine._mcp_proxy_record import CLIENT, SERVER, McpRecorder
    from opentine._scaffold_record import record, recorded
    from opentine.core import Run
    from opentine.repo import Repo

    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    old = _tree(tmp_path / "old", SHELL, "Never delete files.")
    new = _tree(tmp_path / "new", WIDER, "Delete files when asked.")

    # 1. A per-run scaffold manifest, signed onto the run and listed for it only.
    manifest = build("claude-code", old)
    paths = [row["path"] for row in manifest["files"]]
    assert "CLAUDE.md" in paths and "prompts/system.md" in paths
    repo = Repo.init(tmp_path / "store")
    run_id = records.anchor(repo, "test", "a run")
    other = records.anchor(repo, "test", "another run")
    record(repo, run_id, manifest, key("5a" * 32))
    [held] = recorded(repo, run_id)
    assert held["signed"] and held["tree_ok"] and held["claim"]["run"] == run_id
    assert recorded(repo, other) == []

    # 2. An MCP session pins tools/list; each call records the definition's digest.
    recorder = McpRecorder(tmp_path / "run.tine", ["server"], "stdio")
    for sender, obj in [
        (CLIENT, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
        (SERVER, {"jsonrpc": "2.0", "id": 1, "result": {"tools": [SHELL]}}),
        (CLIENT, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "shell"}}),
        (SERVER, {"jsonrpc": "2.0", "id": 2, "result": {"content": []}}),
        (CLIENT, {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}),
        (SERVER, {"jsonrpc": "2.0", "id": 3, "result": {"tools": [WIDER]}}),
        (CLIENT, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "shell"}}),
        (SERVER, {"jsonrpc": "2.0", "id": 4, "result": {"content": []}}),
    ]:
        recorder.feed(sender, _line(obj))
    recorder.close(0)
    calls = [
        s.tool_info
        for s in Run.load(tmp_path / "run.tine").steps
        if s.tool_info.get("method") == "tools/call"
    ]
    assert [c["tool_def_digest"] for c in calls] == [tool_def_digest(SHELL), tool_def_digest(WIDER)]
    assert "advisory" not in calls[0] and calls[1]["advisory"] == CHANGED

    # 3. Both trees become skill lineage variants.
    lineage = tmp_path / "lineage"
    variants = []
    for name, root in (("a", old), ("b", new)):
        code, row = _tine(capsys, "lineage", "diff", root.as_posix(), "--tree", "--json")
        assert code == 0
        digest = row["trees"][0]["tree"]
        run = "run:sha256:" + name * 64
        made = lineage_record(
            key(PROMOTER), run=run, artifacts={"skill": digest}, store=lineage, at=AT
        )
        variants.append(made["variant"])

    # 4. The signed structural diff names each change by structure, bound to the variants.
    signer = write_key(tmp_path / "k", PROMOTER)
    code, row = _tine(capsys, "lineage", "diff", old.as_posix(), new.as_posix(),
                      "--from", variants[0], "--to", variants[1], "--key", signer.as_posix(),
                      "--dir", lineage.as_posix(), "--at", AT, "--json")  # fmt: skip
    assert code == 0
    claim = row["claim"]
    assert claim["from"]["bound"] and claim["to"]["bound"]
    changed = {f["path"]: f for f in claim["files"] if f.get("status") == "changed"}
    assert set(changed) == {"prompts/system.md", "tools.json"}
    text = json.dumps(changed["tools.json"])
    assert tool_def_digest(SHELL) in text and tool_def_digest(WIDER) in text
    assert "Rules" in json.dumps(changed["prompts/system.md"])
    code, checked = _tine(capsys, "lineage", "diff", "--check", row["signed"], old.as_posix(),
                          new.as_posix(), "--dir", lineage.as_posix(), "--json")  # fmt: skip
    assert code == 0 and checked["ok"]
    (new / "agent.py").write_bytes(b"def act(x, retries=4):\n    return x\n")
    code, checked = _tine(capsys, "lineage", "diff", "--check", row["signed"], old.as_posix(),
                          new.as_posix(), "--dir", lineage.as_posix(), "--json")  # fmt: skip
    assert code != 0 and not checked["ok"]
