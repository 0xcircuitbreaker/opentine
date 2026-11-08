"""0.46: steer and resume for Codex and Gemini CLI, and the published ``opentine-hook/1``.

A message sent with ``tine fleet send`` reaches a running Codex session as its
``Stop`` hook's ``{"decision": "block", "reason": ...}`` and a Gemini CLI
session as its ``AfterAgent`` hook's ``{"decision": "deny", "reason": ...}``.
``tine hook resume`` continues an ended session with the CLI's own resume
command. The 67-hook vectors are answered by the reference and the pyz.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from opentine import _schemas, cli
from opentine._hook_protocol import session_ref
from opentine._hook_resume import argv
from opentine._pyz import _hook
from opentine._pyz_build import build_bytes
from opentine.coord import _mailbox
from tests.conformance import tagged

ROOT = Path(__file__).resolve().parents[1]
FLEET = "0123456789ab"
CASES = json.loads((ROOT / "docs/conformance/vectors/67-hook.json").read_text("utf-8"))["cases"]


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


def _repo(tmp_path) -> Path:
    from opentine import _porcelain_config as porcelain
    from opentine.repo import Repo

    root = tmp_path / "repo"
    repo = Repo.init(root)
    porcelain.save(Path(repo.path), {"remotes": {}, "config": {"hooks.capture": "true"}})
    return root


def _capture(root: Path, agent: str, payload: dict) -> dict:
    from opentine._hook_protocol import run_capture

    out = io.StringIO()
    assert run_capture(str(root), agent, io.BytesIO(json.dumps(payload).encode()), out) == 0
    return json.loads(out.getvalue())


@pytest.mark.parametrize(
    ("agent", "payload", "decision"),
    [
        ("codex", {"hook_event_name": "Stop", "session_id": "x", "turn_id": "t",
                   "last_assistant_message": "done", "stop_hook_active": False}, "block"),
        ("gemini", {"hook_event_name": "AfterAgent", "session_id": "g", "prompt": "p",
                    "prompt_response": "done", "stop_hook_active": False}, "deny"),
    ],
)  # fmt: skip
def test_a_fleet_message_steers_codex_and_gemini_at_turn_end(
    tmp_path, monkeypatch, agent, payload, decision
):
    from opentine.repo import Repo

    root = _repo(tmp_path)
    _mailbox.send(Repo.open(root), FLEET, "coder-0", "now write the tests")
    monkeypatch.setenv("OPENTINE_FLEET_ID", FLEET)
    monkeypatch.setenv("OPENTINE_FLEET_MEMBER", "coder-0")
    assert _capture(root, agent, payload) == {"decision": decision, "reason": "now write the tests"}
    assert _capture(root, agent, {**payload, "stop_hook_active": True}) == {}  # once only
    repo = Repo.open(root)
    run = repo.get(repo.read_ref(session_ref(agent, payload["session_id"]))).payload()
    steps = [repo.get(oid).payload() for oid in run["events"]]
    assert [s["actor"] for s in steps] == [agent, "steer", agent]
    first = repo.load_run(session_ref(agent, payload["session_id"])).steps[0]
    assert first.outputs == {"message": "done"}  # Gemini: prompt_response is the message


def test_resume_plans_each_clis_documented_command():
    assert argv("codex", "019a-77", "go") == ["codex", "exec", "resume", "019a-77", "go"]
    assert argv("gemini", "abc", "go") == ["gemini", "--resume", "abc", "--prompt", "go"]
    assert argv("claude-code", "abc", "go") == ["claude", "--resume", "abc", "--print", "go"]
    for agent, session, message in (("copilot", "a", "m"), ("codex", "-a", "m"),
                                    ("codex", "a b", "m"), ("codex", "a", "--yolo"),
                                    ("codex", "a", "")):  # fmt: skip
        with pytest.raises(ValueError):
            argv(agent, session, message)


def _tine(capsys, *args: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(args))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


def test_resume_dry_run_prints_a_schema_valid_plan(capsys):
    code, out = _tine(capsys, "hook", "resume", "--agent", "gemini", "--session", "s1",
                      "--message", "continue", "--dry-run")  # fmt: skip
    plan = json.loads(out)
    assert code == 0 and plan["argv"] == ["gemini", "--resume", "s1", "--prompt", "continue"]
    assert _schemas.validate_output(plan) == []
    code, _ = _tine(capsys, "hook", "resume", "--agent", "copilot", "--session", "s1",
                    "--message", "continue")  # fmt: skip
    assert code != 0


def test_resume_records_the_message_on_the_session_run_then_runs_the_cli(
    tmp_path, monkeypatch, capsys
):
    from opentine.repo import Repo

    root = _repo(tmp_path)
    _capture(root, "codex", {"hook_event_name": "Stop", "session_id": "x9",
                             "last_assistant_message": "done"})  # fmt: skip
    ran: list[list[str]] = []

    def fake_run(command, check):
        ran.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("opentine._hook_resume.subprocess.run", fake_run)
    code, _ = _tine(capsys, "hook", "resume", "--agent", "codex", "--session", "x9",
                    "--message", "and the docs", "--repo", str(root))  # fmt: skip
    assert code == 0 and ran == [["codex", "exec", "resume", "x9", "and the docs"]]
    repo = Repo.open(root)
    run = repo.get(repo.read_ref(session_ref("codex", "x9"))).payload()
    last = repo.get(run["events"][-1]).payload()
    assert last["actor"] == "steer" and last["attributes"]["opentine.steer.from"] == "resume"
    assert repo.load_run(session_ref("codex", "x9")).steps[-1].inputs == {"prompt": "and the docs"}


def test_hook_events_and_responses_validate_against_the_published_schema():
    event = {"protocol": "opentine-hook/1", "event": "tool", "session": "s",
             "tool": {"name": "Bash", "input": {}, "output": "x"}}  # fmt: skip
    assert _schemas.validate(event) == ("opentine-hook-1", [])
    response = {"protocol": "opentine-hook/1", "ok": True, "event": "turn_end", "ref": "r",
                "run": "x", "steps": 2, "steer": ["m"]}  # fmt: skip
    assert _schemas.validate(response) == ("opentine-hook-1", [])
    assert _schemas.validate({"protocol": "opentine-hook/1", "event": "nope", "session": "s"})[1]


def _case_value(case: dict) -> dict:
    return tagged.decode(case["input"]["value"])


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_the_pyz_answers_every_hook_vector(case):
    value = _case_value(case)
    answer = (
        _hook.normalize_case(value) if case["op"] == "hook.normalize" else _hook.respond_case(value)
    )
    assert answer == case["output"]


def test_the_built_pyz_carries_the_hook_port(tmp_path):
    (tmp_path / "tine-verify.pyz").write_bytes(build_bytes())
    with zipfile.ZipFile(tmp_path / "tine-verify.pyz") as archive:
        assert "tine_verify/_pyz/_hook.py" in archive.namelist()
    vectors = tmp_path / "hook.json"
    vectors.write_text(json.dumps([[c["op"], _case_value(c)] for c in CASES]), encoding="utf-8")
    script = (
        "import json, sys\nsys.path.insert(0, sys.argv[1])\n"
        "from tine_verify._pyz import _hook\n"
        "cases = json.load(open(sys.argv[2], encoding='utf-8'))\n"
        "print(json.dumps([_hook.normalize_case(v) if op == 'hook.normalize' "
        "else _hook.respond_case(v) for op, v in cases]))\n"
    )
    done = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, (tmp_path / "tine-verify.pyz").as_posix(),
         vectors.as_posix()], capture_output=True, text=True, timeout=300,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == [case["output"] for case in CASES]


def test_the_spec_document_names_its_vectors_and_every_vendor_event():
    text = (ROOT / "docs" / "spec" / "hook-1.md").read_text("utf-8")
    from opentine._hook_dialects import EXTRA_EVENTS
    from opentine._hook_protocol import EVENTS

    assert "67-hook.json" in text and "opentine-hook/1" in text
    for name in (*EVENTS, *EXTRA_EVENTS):
        assert f"`{name}`" in text
    assert '<a id="s-8.16"></a>' in (ROOT / "docs" / "SPEC.md").read_text("utf-8")
