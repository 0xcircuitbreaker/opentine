"""0.41: OS-level shell sandbox backends (X5, OS level)."""

from __future__ import annotations

import os
import shutil
import sys

import pytest

from opentine.policies import ShellPolicy
from opentine.tools import _sandbox, shell

BACKENDS = {
    "bwrap": _sandbox.bwrap_available,
    "landlock": _sandbox.landlock_available,
    "sandbox-exec": _sandbox.sandbox_exec_available,
}
needs_posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX tools")


def _require(backend: str) -> None:
    if not BACKENDS[backend]():
        pytest.skip(f"{backend} is not available on this host")


@pytest.fixture
def ws(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.chdir(root)
    return root


def _run(ws, backend, command, *names, network=False):
    policy = ShellPolicy(
        enabled=True,
        executables=names,
        cwd_root=str(ws),
        sandbox=backend,
        sandbox_network=network,
    )
    return shell.run(command, policy=policy)


@needs_posix
@pytest.mark.parametrize("backend", sorted(BACKENDS))
def test_find_exec_is_blocked_by_the_os_even_without_the_argument_policy(ws, backend, monkeypatch):
    _require(backend)
    if not shutil.which("find") or not shutil.which("touch"):
        pytest.skip("find/touch not installed")
    monkeypatch.setattr(shell, "arg_refusal", lambda *a, **k: None)
    _run(ws, backend, "find . -exec touch pwned ;", "find")
    assert not (ws / "pwned").exists()


@needs_posix
@pytest.mark.parametrize("backend", sorted(BACKENDS))
def test_writes_inside_the_root_are_allowed_and_outside_denied(ws, backend, monkeypatch):
    _require(backend)
    if not shutil.which("touch"):
        pytest.skip("touch not installed")
    outside = ws.parent / "outside"
    monkeypatch.setattr(shell, "arg_refusal", lambda *a, **k: None)
    _run(ws, backend, f"touch inside {outside}", "touch")
    assert (ws / "inside").exists()
    assert not outside.exists()


@needs_posix
@pytest.mark.parametrize("backend", sorted(BACKENDS))
def test_network_is_denied_by_default(ws, backend):
    _require(backend)
    code = (
        "import socket\n"
        "try:\n"
        " socket.create_connection(('127.0.0.1', 9), 2); print('NET-OK')\n"
        "except PermissionError: print('NET-DENIED')\n"
        "except OSError as e: print('NET-ERR', e.errno)\n"
    )
    (ws / "probe.py").write_text(code)
    out = _run(ws, backend, f"{sys.executable} -I probe.py", sys.executable)
    assert "NET-DENIED" in out or ("NET-ERR" in out and backend == "bwrap"), out


def test_oci_backend_runs_in_a_container_without_network(ws):
    if _sandbox.oci_runtime() is None:
        pytest.skip("no working podman/docker runtime")
    image = "docker.io/library/busybox:1.36"
    policy = ShellPolicy(
        enabled=True, executables=("touch",), cwd_root=str(ws), sandbox="oci", sandbox_image=image
    )
    shell.run("touch inside", policy=policy)
    assert (ws / "inside").exists()


def test_oci_argv_mounts_root_and_drops_network(tmp_path):
    argv = _sandbox.wrap(
        "oci", ["/usr/bin/ls"], root=tmp_path, cwd=tmp_path,
        executables=[], network=False, env={"A": "1"}, image="img",
    )  # fmt: skip
    assert "--network" in argv and argv[argv.index("--network") + 1] == "none"
    assert f"{tmp_path.resolve()}:{tmp_path.resolve()}:rw" in argv
    assert argv[-2:] == ["img", "ls"]


def test_sbpl_profile_denies_by_default_and_scopes_writes():
    profile = _sandbox.sbpl_profile("/w", ["/usr/bin/find"], network=False)
    assert "(deny default)" in profile
    assert '(allow file-write* (subpath "/w")' in profile
    assert '(allow process-exec (literal "/usr/bin/find"))' in profile
    assert "network" not in profile
    assert "(allow network*)" in _sandbox.sbpl_profile("/w", [], network=True)


@pytest.mark.parametrize("backend", ["bwrap", "landlock", "sandbox-exec", "oci"])
def test_a_missing_backend_refuses_to_run(ws, backend, monkeypatch):
    for name in ("bwrap_available", "landlock_available", "sandbox_exec_available"):
        monkeypatch.setattr(_sandbox, name, lambda: False)
    monkeypatch.setattr(_sandbox, "oci_runtime", lambda: None)
    out = _run(ws, backend, "echo hi", "echo")
    assert out.startswith("Error: shell sandbox") and "not available" in out


def test_auto_without_any_backend_refuses(ws, monkeypatch):
    for name in ("bwrap_available", "landlock_available", "sandbox_exec_available"):
        monkeypatch.setattr(_sandbox, name, lambda: False)
    out = _run(ws, "auto", "echo hi", "echo")
    assert out.startswith("Error: shell sandbox 'auto' found no OS backend")


def test_unknown_backend_is_refused(ws):
    assert "unknown shell sandbox" in _run(ws, "chroot", "echo hi", "echo")


@needs_posix
def test_auto_picks_an_available_backend_and_runs(ws):
    if not any(check() for check in BACKENDS.values()):
        pytest.skip("no OS sandbox backend on this host")
    if not shutil.which("echo"):
        pytest.skip("echo not installed")
    assert "hi" in _run(ws, "auto", "echo hi", "echo")


@needs_posix
def test_without_a_sandbox_the_bypassed_argument_check_would_have_been_exploitable(ws, monkeypatch):
    if not shutil.which("find") or not shutil.which("touch"):
        pytest.skip("find/touch not installed")
    monkeypatch.setattr(shell, "arg_refusal", lambda *a, **k: None)
    _run(ws, "none", "find . -maxdepth 0 -exec touch pwned ;", "find")
    assert (ws / "pwned").exists()  # so the sandboxed tests above prove the OS layer


@needs_posix
def test_sbpl_profile_allows_a_symlinked_binary_by_its_real_path(tmp_path):
    real = tmp_path / "real-python"
    real.write_text("")
    link = tmp_path / "python"
    link.symlink_to(real)
    profile = _sandbox.sbpl_profile("/w", [str(link)], network=False)
    assert f'(literal "{link}")' in profile
    assert f'(literal "{os.path.realpath(real)}")' in profile


def test_oci_is_unavailable_on_a_windows_host(monkeypatch):
    monkeypatch.setattr(_sandbox.sys, "platform", "win32")
    _sandbox.oci_runtime.cache_clear()
    try:
        assert _sandbox.oci_runtime() is None
        with pytest.raises(_sandbox.SandboxUnavailable):
            _sandbox.choose("oci", image="img")
    finally:
        _sandbox.oci_runtime.cache_clear()
