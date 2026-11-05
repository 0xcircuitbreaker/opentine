"""0.35 X3: the offline guard cannot be bypassed below the socket wrappers."""

from __future__ import annotations

import _socket
import os
import socket
import subprocess
import sys

import pytest

from opentine import _hermetic
from opentine._offline_guard import NetworkRefused, no_network


def test_raw_socket_connect_is_refused() -> None:
    with no_network(), pytest.raises(NetworkRefused):
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        try:
            s.connect(("127.0.0.1", 9))
        finally:
            s.close()


def test_sendto_is_refused() -> None:
    with no_network(), pytest.raises(NetworkRefused):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"x", ("127.0.0.1", 9))


def test_raw_name_lookup_and_bind_are_refused() -> None:
    with no_network():
        with pytest.raises(NetworkRefused):
            _socket.getaddrinfo("example.com", 443)
        with pytest.raises(NetworkRefused), socket.socket() as s:
            s.bind(("0.0.0.0", 0))


@pytest.mark.parametrize(
    "launch",
    [
        lambda: subprocess.run([sys.executable, "-c", "pass"], check=False),
        lambda: os.system("true"),
        pytest.param(
            lambda: os.posix_spawn(sys.executable, [sys.executable, "-c", "pass"], os.environ),
            marks=pytest.mark.skipif(not hasattr(os, "posix_spawn"), reason="no posix_spawn"),
        ),
    ],
)
def test_process_launch_is_refused(launch) -> None:
    with no_network(), pytest.raises(NetworkRefused):
        launch()


def test_guard_is_inactive_afterwards() -> None:
    with no_network():
        pass
    assert subprocess.run([sys.executable, "-c", "pass"], check=False).returncode == 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))


def test_hermetic_unsupported_platform_exits_6(monkeypatch) -> None:
    monkeypatch.delenv(_hermetic.CHILD_ENV, raising=False)
    monkeypatch.setattr(_hermetic, "sandbox_prefix", lambda *_a: None)
    with pytest.raises(SystemExit) as exc:
        _hermetic.reexec_hermetic()
    assert exc.value.code == 6
    assert _hermetic.sandbox_prefix("win32") is None


def test_hermetic_child_does_not_reexec(monkeypatch) -> None:
    monkeypatch.setenv(_hermetic.CHILD_ENV, "1")
    _hermetic.reexec_hermetic()


def test_hermetic_is_refused_without_offline() -> None:
    from opentine._cli_verify_offline import OFFLINE_DESTS

    assert "hermetic" in OFFLINE_DESTS
