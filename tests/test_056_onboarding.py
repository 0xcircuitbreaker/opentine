"""0.56 onboarding: ``tine init --auto`` and the ``tine doctor --bundle`` tarball."""

from __future__ import annotations

import io
import json
import os
import shutil
import tarfile
from pathlib import Path

import pytest

from opentine import cli
from opentine._hook_protocol import handle, normalize, session_ref

HOOKS = Path(__file__).parent / "fixtures" / "hooks"
#: Read before any test empties PATH, for the one test that needs git.
REAL_PATH = os.environ.get("PATH", "")
SECRET = "sk-proj-" + "Zq7Xw2Lr9Tb4Nc8Vm1Hs6Jd3Kf5Gp0Ya"
#: Agent -> (directory that makes it detectable, fixture sequence with event hints).
AGENTS = {
    "copilot": (".copilot", [("prompt.json", None), ("tool.json", None), ("stop.json", None),
                             ("session_end.json", None)]),
    "droid": (".factory", [("prompt.json", None), ("tool.json", None), ("stop.json", None),
                           ("session_end.json", None)]),
    "antigravity": (".gemini/antigravity-cli", [("PreInvocation.json", "PreInvocation"),
                                                ("PostToolUse.json", "PostToolUse"),
                                                ("Stop.json", "Stop")]),
}  # fmt: skip


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A clean HOME: no agent CLI on PATH, no config, a key passphrase from the env."""
    root = tmp_path / "home"
    root.mkdir()
    monkeypatch.setenv("HOME", str(root))
    monkeypatch.setenv("USERPROFILE", str(root))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(root / ".config"))
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    monkeypatch.setenv("OPENTINE_KEY_PASSPHRASE", "correct horse battery staple")
    for name in ("COPILOT_HOME", "PI_CODING_AGENT_DIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME",
                 "GEMINI_CLI_HOME"):  # fmt: skip
        monkeypatch.delenv(name, raising=False)
    return root


def _payload(agent: str, name: str, seed_secret: bool) -> bytes:
    document = json.loads((HOOKS / agent / name).read_text(encoding="utf-8"))
    if seed_secret:
        for key in ("prompt", "lastUserInput"):
            if key in document:
                document[key] = f"{document[key]} using OPENAI_API_KEY={SECRET}"
    return json.dumps(document).encode("utf-8")


@pytest.mark.parametrize("agent", sorted(AGENTS))
def test_init_auto_gives_a_signed_run_in_under_five_commands(home, tmp_path, capsys, agent):
    folder, sequence = AGENTS[agent]
    (home / folder).mkdir(parents=True)
    root = tmp_path / "work"
    commands = 0

    cli.main(["init", "--auto", str(root)])  # 1
    commands += 1
    from opentine import _enable_native as native
    from opentine._agent_keys import key_paths

    hook_file = native.config_path(agent).read_text(encoding="utf-8")
    assert f"hook capture --agent {agent}" in hook_file and str(root) in hook_file
    key = key_paths("local")[0]
    assert key.read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")

    # The agent's own session: what the installed hook command hands to the protocol.
    for name, hint in sequence:
        response = handle(_payload(agent, name, seed_secret=True), str(root), agent, hint)
        assert response["ok"], response
    first = json.loads((HOOKS / agent / sequence[0][0]).read_text(encoding="utf-8"))
    ref = session_ref(agent, normalize(first, sequence[0][1])["session"])

    capsys.readouterr()
    cli.main(["attest", ref, "--signer", "local", "--claim", '{"onboarded": true}',
              "--ed25519-key-file", str(key), "--repo", str(root), "--json"])  # 2  # fmt: skip
    commands += 1
    body = json.loads(capsys.readouterr().out)
    assert body["signed"] is True and body["signature"]
    assert commands < 5

    from opentine.repo import Repo

    repo = Repo.open(root)
    run = repo.get(repo.read_ref(ref)).payload()
    events = [repo.get(oid).payload() for oid in run["events"]]
    blobs = [repo.get(e[k]).body for e in events for k in ("input_blob", "output_blob")
             if e.get(k)]  # fmt: skip
    stored = json.dumps([run, *events]).encode() + b"".join(blobs)
    assert SECRET.encode() not in stored  # the seeded secret was scrubbed on the way in
    assert b"List the files" in stored  # and the prompt itself was kept


def test_init_auto_on_a_clean_home_finds_nothing_and_says_so(home, tmp_path):
    from opentine._init_auto import run

    result = run(str(tmp_path / "work"))
    steps = {row["step"]: row for row in result["steps"]}
    assert result["agents"] == [] and steps["hooks"]["status"] == "no agent CLI found"
    assert steps["repository"]["status"] == "created" and steps["key"]["status"] == "created"
    assert steps["push"]["status"] == "not a git work tree"
    assert {"otlp", "mcp-proxy"} <= set(steps)


def test_init_auto_dry_run_writes_nothing(home, tmp_path):
    from opentine._init_auto import run

    (home / ".factory").mkdir()
    result = run(str(tmp_path / "work"), dry_run=True)
    assert result["agents"] == ["droid"]
    assert not (tmp_path / "work").exists()
    assert not (home / ".factory" / "hooks.json").exists()
    assert not (home / ".config" / "opentine").exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_init_auto_push_beside_git_installs_the_pre_push_hook(home, tmp_path, monkeypatch):
    import subprocess

    from opentine._init_auto import run

    monkeypatch.setenv("PATH", REAL_PATH)

    work = tmp_path / "work"
    work.mkdir()
    subprocess.run(["git", "init", "-q", str(work)], check=True)
    offered = run(str(work))
    assert [r for r in offered["steps"] if r["step"] == "push"][0]["status"] == "offered"
    done = run(str(work), push_beside_git=True)
    row = [r for r in done["steps"] if r["step"] == "push"][0]
    assert row["status"] == "installed" and Path(row["path"]).name == "pre-push"


def test_doctor_tarball_holds_no_secret(home, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OPENTINE_TOKEN", SECRET)
    (home / ".factory").mkdir()
    hooks = home / ".factory" / "hooks.json"
    hooks.write_bytes(json.dumps({"Stop": [{"hooks": [
        {"type": "command", "command": f"notify --token {SECRET}"}]}]}).encode())  # fmt: skip
    out = tmp_path / "diag.tar.gz"
    cli.main(["doctor", "--repo", str(tmp_path), "--bundle", str(out), "--json"])
    capsys.readouterr()
    data = out.read_bytes()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = {m.name: archive.extractfile(m).read() for m in archive.getmembers()}
    assert {"doctor.json", "agents.json", "hooks/droid.json"} <= set(members)
    for name, raw in members.items():
        assert SECRET.encode() not in raw, name
    agents = {row["agent"]: row for row in json.loads(members["agents.json"])}
    assert agents["droid"]["present"] is True and agents["droid"]["shim_installed"] is False
    assert b"OPENTINE_TOKEN" in members["doctor.json"]


def test_doctor_tarball_is_reproducible(home, tmp_path):
    from opentine import _doctor, _doctor_tar

    body = _doctor.report(str(tmp_path))
    assert _doctor_tar.tarball(body) == _doctor_tar.tarball(body)


def test_doctor_tarball_refuses_a_surviving_secret(home, monkeypatch):
    from opentine import _doctor_tar

    monkeypatch.setattr("opentine.redaction.redact_value", lambda value: value)
    with pytest.raises(ValueError, match="not written"):
        _doctor_tar.tarball({"detail": f"OPENAI_API_KEY={SECRET}"})
