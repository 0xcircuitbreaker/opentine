"""A hard network guard for ``tine verify --offline``.

Offline verification refuses network paths rather than trying them, and this
is the backstop for that promise: while :func:`no_network` is active, every way
the standard library dials out -- ``socket.socket.connect``/``connect_ex``,
``socket.create_connection``, ``socket.getaddrinfo`` and the ``gethostbyname``
family -- raises :class:`NetworkRefused` instead. ``NetworkRefused`` is not an
``OSError``, so no "could not reach the server" handler can swallow it into an
ordinary failure; the checker reports it as ``offline.network-refused``.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from contextlib import contextmanager

_MODULE_FUNCS = ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex")
_SOCKET_METHODS = ("connect", "connect_ex")


class NetworkRefused(RuntimeError):
    """Raised for any network attempt while offline verification runs."""


def _refuse(what: str):
    def refuse(*_args: object, **_kwargs: object):
        raise NetworkRefused(f"offline verification refused a network call ({what})")

    return refuse


@contextmanager
def no_network() -> Iterator[None]:
    """Make every socket connect and name lookup raise for the duration."""
    saved_funcs = {name: getattr(socket, name) for name in _MODULE_FUNCS}
    saved_methods = {name: getattr(socket.socket, name) for name in _SOCKET_METHODS}
    try:
        for name in _MODULE_FUNCS:
            setattr(socket, name, _refuse(f"socket.{name}"))
        for name in _SOCKET_METHODS:
            setattr(socket.socket, name, _refuse(f"socket.socket.{name}"))
        yield
    finally:
        for name, value in saved_funcs.items():
            setattr(socket, name, value)
        for name, value in saved_methods.items():
            setattr(socket.socket, name, value)


__all__ = ["NetworkRefused", "no_network"]
