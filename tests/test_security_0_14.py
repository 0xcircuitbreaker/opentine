"""0.14.0 security fixes: display-safe errors, re-scrubbed MCP output, private files."""

from __future__ import annotations

import base64
import os
import stat
import sys
import sysconfig
from pathlib import Path
from types import SimpleNamespace

import pytest

from opentine import Run, StepKind, cli
from opentine.redaction import redact_text
from opentine.repository import Repo

POSIX = pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
TOKEN = "ghp_" + "C" * 36


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    return home


@pytest.fixture
def loose_umask():
    old = os.umask(0o002)
    yield
    os.umask(old)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# -- 1. MCP output is re-scrubbed like `tine export` -----------------------------------


def test_mcp_show_run_rescrubs_a_legacy_unredacted_run():
    from opentine.mcp_server import format_run_for_llm

    run = Run(run_id="legacy")  # as loaded from a pre-0.9.1 file: never redacted
    run.add_step(StepKind.tool, {"text": f"export GITHUB_TOKEN={TOKEN}"})
    text = format_run_for_llm(run)
    assert TOKEN not in text and "REDACTED" in text


# -- 2-4. `tine run --model` failures are display-safe ----------------------------------


class _FailingAgent:
    message = ""

    def __init__(self, model):
        pass

    def run_sync(self, prompt):
        raise RuntimeError(self.message)


@pytest.mark.parametrize(
    "message",
    [
        "Client error '401 Unauthorized' for url "
        "'http://user:pw-SECRET@127.0.0.1:9/?key=QSECRET/api/chat'",
        "Error code: 401 - {'error': 'bad key sk-ECHOEDSECRETFROMBODY'}",
    ],
    ids=["url", "body"],
)
def test_model_run_failure_hides_credentials(monkeypatch, capsys, message):
    import opentine.runtime

    monkeypatch.setattr(_FailingAgent, "message", message)
    monkeypatch.setattr(opentine.runtime, "Agent", _FailingAgent)
    with pytest.raises(SystemExit):
        cli.main(["run", "--model", "ollama:llama3", "--prompt", "hi"])
    shown = "".join(capsys.readouterr())
    assert "Model run failed" in shown and "SECRET" not in shown


def test_ollama_host_error_names_only_the_scheme(monkeypatch, capsys):
    from opentine.models._ollama_host import normalize_host

    with pytest.raises(ValueError) as caught:
        normalize_host("ftp://u:envpw-SECRET@h")
    assert "SECRET" not in str(caught.value) and "ftp" in str(caught.value)
    monkeypatch.setenv("OLLAMA_HOST", "ftp://u:envpw-SECRET@h")
    with pytest.raises(SystemExit):
        cli.main(["run", "--model", "ollama:llama3", "--prompt", "hi"])
    assert "SECRET" not in "".join(capsys.readouterr())


# -- 5. base64-wrapped credentials ------------------------------------------------------


def test_base64_wrapped_credentials_are_redacted():
    blob = base64.b64encode(b"Authorization: Bearer xyzSECRETBEARER1234567890").decode()
    assert blob not in redact_text(f"blob={blob}")
    assert blob not in redact_text(f'{{"blob": "{blob}"}}')
    wrapped = base64.b64encode(f"GITHUB_TOKEN={TOKEN}".encode()).decode()
    assert wrapped not in redact_text(wrapped)


def test_base64_without_credentials_is_kept():
    for text in (
        base64.b64encode(b"hello, this is an ordinary sentence").decode(),
        base64.b64encode(bytes(range(256))).decode(),  # binary payload
        "sha256 " + "0123456789abcdef" * 4,
        "/home/user/project/src/module/file_name",
    ):
        assert redact_text(text) == text


# -- 6-7. fan-out members ---------------------------------------------------------------


def test_parallel_members_keep_the_cwd_off_sys_path():
    from opentine._cli_fanout import _member_argv

    argv = _member_argv(["run", "s.py"])
    assert argv[:4] == [sys.executable, "-P", "-m", "opentine.cli"]


@POSIX
def test_member_logs_are_private_and_never_followed(tmp_path, loose_umask):
    from opentine.parallel._executor import _open_log

    log = tmp_path / "m.log"
    with _open_log(log) as handle:
        handle.write(b"token")
    assert _mode(log) == 0o600
    (tmp_path / "link.log").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OSError):
        _open_log(tmp_path / "link.log")
    assert not (tmp_path / "elsewhere").exists()


@POSIX
def test_fanout_log_dir_is_private(tmp_path, monkeypatch, loose_umask):
    from opentine import _cli_fanout

    monkeypatch.setattr(_cli_fanout, "drive", lambda *a, **k: 0)
    state = SimpleNamespace(id="f", data={"members": [{}]})
    args = SimpleNamespace(log_dir=str(tmp_path / "logs"), json=False, jobs=1, timeout=None, env=[])
    with pytest.raises(SystemExit):
        _cli_fanout._drive(state, ["x"], args)
    assert _mode(tmp_path / "logs") == 0o700


# -- 8. refs, reflogs, repository dirs, worktree marker ---------------------------------


@POSIX
def test_refs_reflogs_dirs_and_worktree_marker_are_private(tmp_path, monkeypatch, loose_umask):
    from opentine import _worktree

    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "project")
    run = Run(id="base0001", model_info="m")
    run.add_step(StepKind.model, {"text": "q"}, {"text": "a"})
    repo.put_run(run, ref="heads/main")
    tine = tmp_path / "project" / ".tine"
    for kind in ("refs", "logs"):
        assert _mode(tine / kind / "heads" / "main") == 0o600, kind
    for directory in [tine, *(p for p in tine.rglob("*") if p.is_dir())]:
        assert _mode(directory) == 0o700, directory
    _worktree.add(repo, tmp_path / "wt", "heads/main")
    assert _mode(tmp_path / "wt" / _worktree.MARKER) == 0o600


# -- 9. plugin export -------------------------------------------------------------------


@POSIX
def test_plugin_export_files_are_private(tmp_path, loose_umask):
    repo = Repo.init(tmp_path / "repo")
    target = tmp_path / "plugin"
    cli.main(["plugin", "export", str(target), "--repo", str(repo.path)])
    files = [p for p in target.rglob("*") if p.is_file()]
    assert files and all(_mode(p) == 0o600 for p in files)
    (target / ".mcp.json").chmod(0o644)
    cli.main(["plugin", "export", str(target), "--repo", str(repo.path), "--force"])
    assert _mode(target / ".mcp.json") == 0o600


# -- 10. adapter entry points found in the cwd ------------------------------------------


class _Dist:
    def __init__(self, root):
        self.root = root

    def locate_file(self, path):
        return Path(self.root, path)


class _Point:
    def __init__(self, name, root):
        self.name, self.dist, self.loaded = name, _Dist(root), False

    def load(self):
        self.loaded = True
        raise AssertionError("must not be loaded")


def test_allowlisted_adapter_from_the_cwd_is_not_loaded(tmp_path, monkeypatch, isolated_home):
    import json

    from opentine.harnesses import _adapter_spec

    monkeypatch.chdir(tmp_path)
    planted, unknown = _Point("good", "."), _Point("other", tmp_path)
    unknown.dist = None
    monkeypatch.setattr(_adapter_spec.metadata, "entry_points", lambda group: [planted, unknown])
    allow = isolated_home / ".config" / "opentine" / "adapters.json"
    allow.parent.mkdir(parents=True)
    allow.write_text(json.dumps({"allow": ["good", "other"]}))
    specs, skipped = _adapter_spec.external_specs()
    assert specs == {} and not planted.loaded and not unknown.loaded
    assert "working directory" in skipped["good"] and "working directory" in skipped["other"]
    site = _Point("good", sysconfig.get_paths()["purelib"])
    monkeypatch.setattr(_adapter_spec.metadata, "entry_points", lambda group: [site])
    _adapter_spec.external_specs()
    assert site.loaded  # an installed distribution still loads
