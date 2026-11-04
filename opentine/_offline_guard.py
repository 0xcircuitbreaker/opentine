"""A hard network guard for ``tine verify --offline``.

Offline verification refuses network paths rather than trying them, and this
is the backstop for that promise: while :func:`no_network` is active, every way
the standard library dials out -- ``socket.socket.connect``/``connect_ex``,
``socket.create_connection``, ``socket.getaddrinfo`` and the ``gethostbyname``
family -- raises :class:`NetworkRefused` instead. ``NetworkRefused`` is not an
``OSError``, so no "could not reach the server" handler can swallow it into an
ordinary failure; the checker reports it as ``offline.network-refused``.

Patching the Python wrappers is not enough: ``_socket`` itself, ``sendto`` and a
child process all go round them. So the guard also installs, once per process,
a PEP 578 audit hook that refuses every socket event and every process launch
(``subprocess.Popen``, ``os.system``, ``os.exec*``, ``os.posix_spawn``, ...)
while any :func:`no_network` block is active. Audit hooks cannot be removed;
outside the guard this one does nothing.
"""

from __future__ import annotations

import socket
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager

_MODULE_FUNCS = ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex")
_SOCKET_METHODS = ("connect", "connect_ex")
_PROCESS_EVENTS = frozenset(
    {
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.spawn",
        "os.fork",
        "os.forkpty",
        "os.startfile",
        "pty.spawn",
    }
)
_SAFE_SOCKET_EVENTS = frozenset({"socket.__new__", "socket.socketpair"})
_lock = threading.Lock()
_active = 0
_hooked = False


class NetworkRefused(RuntimeError):
    """Raised for any network attempt while offline verification runs."""


def _refuse(what: str):
    def refuse(*_args: object, **_kwargs: object):
        raise NetworkRefused(f"offline verification refused a network call ({what})")

    return refuse


def _audit(event: str, _args: tuple[object, ...]) -> None:
    if not _active:
        return
    if event in _PROCESS_EVENTS or (
        event.startswith("socket.") and event not in _SAFE_SOCKET_EVENTS
    ):
        raise NetworkRefused(f"offline verification refused {event}")


def _enter() -> None:
    global _active, _hooked
    with _lock:
        if not _hooked:
            sys.addaudithook(_audit)
            _hooked = True
        _active += 1


def _leave() -> None:
    global _active
    with _lock:
        _active -= 1


@contextmanager
def no_network() -> Iterator[None]:
    """Make every socket event and process launch raise for the duration."""
    saved_funcs = {name: getattr(socket, name) for name in _MODULE_FUNCS}
    saved_methods = {name: getattr(socket.socket, name) for name in _SOCKET_METHODS}
    _enter()
    try:
        for name in _MODULE_FUNCS:
            setattr(socket, name, _refuse(f"socket.{name}"))
        for name in _SOCKET_METHODS:
            setattr(socket.socket, name, _refuse(f"socket.socket.{name}"))
        yield
    finally:
        _leave()
        for name, value in saved_funcs.items():
            setattr(socket, name, value)
        for name, value in saved_methods.items():
            setattr(socket.socket, name, value)


__all__ = ["NetworkRefused", "no_network"]
