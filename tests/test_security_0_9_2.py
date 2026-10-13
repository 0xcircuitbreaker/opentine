"""Regression tests for the 0.9.2 hardening release (client side).

Each test fails on 0.9.1: ``tine --version`` did not exist, the python tool ran
with the host's ``PYTHON*`` environment, the Anthropic and Google adapters
followed a cross-origin redirect with the API key, the fs tool opened a path by
name after checking it, and ``put_run`` copied the prompts into the annotation.
"""

from __future__ import annotations

import asyncio
import json
import os
import struct
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from opentine import Run
from opentine._graph_serde import run_from_dict, run_to_dict
from opentine._version import __version__
from opentine.cli import main
from opentine.graph import StepKind
from opentine.policies import FilesystemPolicy, PythonPolicy
from opentine.repository import Repo
from opentine.tools import _fs_open, _fs_windows, fs
from opentine.tools.python import execute

# -- tine --version ------------------------------------------------------------


@pytest.mark.parametrize("flag", ["--version", "-V"])
def test_tine_version_flag_prints_the_package_version(flag, capsys):
    with pytest.raises(SystemExit) as exited:
        main([flag])
    assert exited.value.code == 0
    assert capsys.readouterr().out.strip() == f"opentine {__version__}"


# -- python tool isolated mode -------------------------------------------------


def test_python_tool_ignores_the_host_python_environment(tmp_path, monkeypatch):
    planted = tmp_path / "planted"
    planted.mkdir()
    (planted / "hostmod.py").write_text("VALUE = 'host'\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(planted))
    monkeypatch.setenv("PYTHONWARNINGS", "error")
    code = (
        "import sys\n"
        "try:\n"
        "    import hostmod\n"
        "    print('host module imported')\n"
        "except ImportError:\n"
        "    print('isolated')\n"
        "print(sys.flags.isolated, sys.warnoptions, '\\u00e9\\u2713')\n"
    )
    output = execute(code, policy=PythonPolicy(enabled=True, inherit_env=True))
    assert output.splitlines()[:2] == ["isolated", "1 [] é✓"]


# -- provider SDKs never follow a redirect with the key ------------------------

_ANTHROPIC_REPLY = {
    "id": "msg_1",
    "type": "message",
    "role": "assistant",
    "model": "claude-sonnet-5-5",
    "content": [{"type": "text", "text": "hi"}],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {"input_tokens": 3, "output_tokens": 1},
}
_GEMINI_REPLY = {
    "candidates": [
        {"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": "STOP"}
    ],
    "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1, "totalTokenCount": 4},
}


class _Servers:
    def __init__(self) -> None:
        self.seen: list[dict[str, str]] = []
        servers = self

        class Target(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("content-length") or 0))
                servers.seen.append({k.lower(): v for k, v in self.headers.items()})
                reply = _GEMINI_REPLY if "generateContent" in self.path else _ANTHROPIC_REPLY
                body = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args) -> None:
                pass

        class Redirector(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("content-length") or 0))
                self.send_response(307)
                self.send_header("location", f"{servers.target_url}{self.path}")
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, *args) -> None:
                pass

        self.target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
        self.redirector = ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
        # Another port is another origin: httpx keeps x-api-key across it.
        self.target_url = f"http://127.0.0.1:{self.target.server_port}"
        self.redirect_url = f"http://127.0.0.1:{self.redirector.server_port}"
        for server in (self.target, self.redirector):
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def close(self) -> None:
        for server in (self.target, self.redirector):
            server.shutdown()
            server.server_close()


@pytest.fixture
def servers() -> Iterator[_Servers]:
    running = _Servers()
    try:
        yield running
    finally:
        running.close()


def _adapter(provider: str, base_url: str, monkeypatch):
    if provider == "anthropic":
        pytest.importorskip("anthropic")
        from opentine.models.anthropic import Anthropic

        monkeypatch.setenv("ANTHROPIC_BASE_URL", base_url)
        return Anthropic(api_key="sk-ant-api03-secret"), "x-api-key"
    pytest.importorskip("google.genai")
    from opentine.models.google import Google

    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", base_url)
    return Google(api_key="AIza-secret"), "x-goog-api-key"


@pytest.mark.parametrize("provider", ["anthropic", "google"])
def test_adapter_does_not_follow_a_redirect_with_its_api_key(provider, servers, monkeypatch):
    model, header = _adapter(provider, servers.redirect_url, monkeypatch)
    with pytest.raises(Exception):  # noqa: B017 -- each SDK names its own status error
        asyncio.run(model.complete([{"role": "user", "content": "hi"}]))
    assert not [seen for seen in servers.seen if seen.get(header)]


@pytest.mark.parametrize("provider", ["anthropic", "google"])
def test_adapter_still_reaches_its_endpoint(provider, servers, monkeypatch):
    model, header = _adapter(provider, servers.target_url, monkeypatch)
    result = asyncio.run(model.complete([{"role": "user", "content": "hi"}]))
    assert result["text"] == "hi"
    assert [seen[header] for seen in servers.seen] == [model._api_key]


# -- fs tool: what is opened is what was checked --------------------------------


def _swap_after_check(monkeypatch, swap) -> None:
    checked = fs._locate

    def locate(*args, **kwargs):
        found = checked(*args, **kwargs)
        swap()
        return found

    monkeypatch.setattr(fs, "_locate", locate)


def _workspace(tmp_path: Path) -> tuple[Path, Path, FilesystemPolicy]:
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "notes.txt").write_text("mine", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "notes.txt").write_text("victim", encoding="utf-8")
    policy = FilesystemPolicy(roots=(str(root),), write_roots=(str(root),))
    return root, outside, policy


def _symlink_swap(root: Path, outside: Path):
    def swap() -> None:
        (root / "sub").rename(root / "sub-before")
        (root / "sub").symlink_to(outside, target_is_directory=True)

    return swap


@pytest.mark.skipif(os.name != "posix", reason="creating symlinks needs privileges on Windows")
@pytest.mark.parametrize("walk", [True, False], ids=["dir-fd-walk", "post-open-check"])
@pytest.mark.parametrize("verb", ["read", "write", "edit"])
def test_fs_refuses_a_directory_swapped_for_a_symlink_after_the_check(
    tmp_path, monkeypatch, walk, verb
):
    if walk and not _fs_open.WALKS:
        pytest.skip("no dir_fd walk on this platform")
    monkeypatch.setattr(_fs_open, "WALKS", walk)
    root, outside, policy = _workspace(tmp_path)
    _swap_after_check(monkeypatch, _symlink_swap(root, outside))
    with pytest.raises(PermissionError, match="changed while it was opened"):
        if verb == "read":
            fs.read("sub/notes.txt", policy=policy)
        elif verb == "write":
            fs.write("sub/notes.txt", "overwritten", policy=policy)
        else:
            fs.edit("sub/notes.txt", "victim", "overwritten", policy=policy)
    assert (outside / "notes.txt").read_text(encoding="utf-8") == "victim"


@pytest.mark.skipif(not _fs_open.WALKS, reason="no dir_fd walk on this platform")
def test_fs_ls_refuses_a_directory_swapped_for_a_symlink(tmp_path, monkeypatch):
    root, outside, policy = _workspace(tmp_path)
    _swap_after_check(monkeypatch, _symlink_swap(root, outside))
    with pytest.raises(PermissionError, match="changed while it was opened"):
        fs.ls("sub", policy=policy)


def _junction_swap(root: Path, outside: Path):
    import _winapi  # junctions need no privilege on Windows, unlike symlinks

    def swap() -> None:
        (root / "sub").rename(root / "sub-before")
        _winapi.CreateJunction(str(outside), str(root / "sub"))

    return swap


@pytest.mark.skipif(os.name != "nt", reason="junctions are Windows-only")
@pytest.mark.parametrize("verb", ["read", "write", "edit", "ls"])
def test_fs_refuses_a_directory_swapped_for_a_junction_after_the_check(tmp_path, monkeypatch, verb):
    root, outside, policy = _workspace(tmp_path)
    _swap_after_check(monkeypatch, _junction_swap(root, outside))
    with pytest.raises(PermissionError, match="changed while it was opened"):
        if verb == "read":
            fs.read("sub/notes.txt", policy=policy)
        elif verb == "write":
            fs.write("sub/notes.txt", "overwritten", policy=policy)
        elif verb == "edit":
            fs.edit("sub/notes.txt", "victim", "overwritten", policy=policy)
        else:
            fs.ls("sub", policy=policy)
    assert (outside / "notes.txt").read_text(encoding="utf-8") == "victim"


def _directory_record(name: str, attributes: int, last: bool, pad: int = 0) -> bytes:
    encoded = name.encode("utf-16-le")
    size = 68 + len(encoded) + pad
    head = struct.pack("<II", 0 if last else size, 0) + bytes(48)
    return head + struct.pack("<III", attributes, len(encoded), 0) + encoded + bytes(pad)


def test_windows_directory_records_parse_into_entries():
    raw = b"".join(
        [
            _directory_record(".", 0x10, False),
            _directory_record("..", 0x10, False, pad=4),
            _directory_record("sub", 0x10, False),
            _directory_record("notes \u00e9.txt", 0x20, True),
        ]
    ) + bytes(64)  # stale bytes after the last record are never read
    assert _fs_windows.parse_entries(raw) == [(True, "sub"), (False, "notes \u00e9.txt")]
    with pytest.raises(OSError, match="malformed"):
        _fs_windows.parse_entries(_directory_record("x", 0, True)[:-1])


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
@pytest.mark.parametrize("walk", [True, False], ids=["dir-fd-walk", "post-open-check"])
def test_fs_read_of_a_fifo_swapped_in_fails_instead_of_hanging(tmp_path, monkeypatch, walk):
    if walk and not _fs_open.WALKS:
        pytest.skip("no dir_fd walk on this platform")
    monkeypatch.setattr(_fs_open, "WALKS", walk)
    root, _, policy = _workspace(tmp_path)

    def swap() -> None:
        (root / "sub" / "notes.txt").unlink()
        os.mkfifo(root / "sub" / "notes.txt")

    _swap_after_check(monkeypatch, swap)
    with pytest.raises(ValueError, match="not a regular file"):
        fs.read("sub/notes.txt", policy=policy)


@pytest.mark.parametrize("walk", [True, False], ids=["dir-fd-walk", "post-open-check"])
def test_fs_verbs_still_work_on_ordinary_paths(tmp_path, monkeypatch, walk):
    if walk and not _fs_open.WALKS:
        pytest.skip("no dir_fd walk on this platform")
    monkeypatch.setattr(_fs_open, "WALKS", walk)
    root, _, policy = _workspace(tmp_path)
    assert fs.write("new/deeper/file.txt", "a\r\nb", policy=policy).startswith("Wrote")
    assert fs.read("new/deeper/file.txt", policy=policy) == "a\r\nb"
    assert fs.edit("new/deeper/file.txt", "b", "c", policy=policy).startswith("Edited")
    assert (root / "new" / "deeper" / "file.txt").read_bytes() == b"a\r\nc"
    assert fs.ls(".", policy=policy).splitlines() == ["d new", "d sub"]
    with pytest.raises(ValueError, match="max_file_bytes"):
        fs.read("sub/notes.txt", policy=FilesystemPolicy(roots=(str(root),), max_file_bytes=2))


# -- put_run no longer copies the prompts into the annotation -------------------


def test_put_run_keeps_prompts_out_of_the_annotation(tmp_path):
    run = Run(run_id="prompted", system_prompt="S" * 40_000, user_prompt="do it")
    run.metadata["note"] = "kept"
    run.add_step(StepKind.done, {"text": "ok"})
    stored = run_to_dict(run)
    loaded = run_from_dict(stored, Run)  # as from a .tine file: prompts in metadata
    repo = Repo.init(tmp_path / "repo")
    result = repo.put_run(loaded)
    annotation = repo.get(result.annotation_id).payload()["value"]
    assert annotation["metadata"] == {"note": "kept"}
    assert len(repo.raw(result.annotation_id)) < 1_000
    back = repo.load_run(result.run_id)
    assert (back.system_prompt, back.user_prompt) == ("S" * 40_000, "do it")
    assert run_to_dict(run_from_dict(run_to_dict(back), Run))["metadata"] == stored["metadata"]
