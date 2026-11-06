"""Which transfer pack, and which codec frames, a peer is sent (0.37).

Each end lists the pack formats it reads (``pack_formats``). ``TINEPACK5`` is
listed from 0.37 on, by an install that has zstd, so it is sent only to peers
advertising 0.37+; a 0.34--0.36 peer lists ``TINEPACK4`` and keeps getting it,
and a 0.11 peer lists neither and gets ``TINEPACK3`` (``_pack4``).

Codec v2 frames (``_codec.wrap(v2=True)``, past the 1000:1 ratio a 0.34 reader
accepts) go only to a peer that advertises 0.35 or newer (X13): a server in its
capabilities' ``version``, a client in the ``peer_version`` it sends a server
that lists ``TINEPACK5`` (older servers refuse unknown request keys).
"""

from __future__ import annotations

import re
from typing import Any

from opentine._version import __version__
from opentine.repository import _pack4, _pack5
from opentine.repository._pack5 import V5

V3, V4 = _pack4.V3, _pack4.V4
#: Request field naming the client's version, sent only to 0.37+ servers.
PEER_VERSION = "peer_version"
_VERSION = re.compile(r"^(\d+)\.(\d+)(?:\.\d+)?")


def local_formats() -> list[str]:
    """Pack formats this install reads, preferred first."""
    return ([V5] if _pack5.available() else []) + [V4, V3]


def at_least(version: Any, minimum: tuple[int, int]) -> bool:
    """Whether an advertised *version* string is *minimum* or newer."""
    match = _VERSION.match(version) if isinstance(version, str) else None
    return bool(match) and (int(match[1]), int(match[2])) >= minimum


def choose(formats: Any, codecs: Any) -> tuple[str, str | None]:
    """The format (and v4 codec) for a peer that offered these lists."""
    if isinstance(formats, list) and V5 in formats and _pack5.available():
        return V5, None
    return _pack4.choose(formats, codecs)


def convert(data: bytes, fmt: str, codec: str | None, *, peer_version: Any = None) -> bytes:
    """*data* (a v3 pack) in *fmt*; codec v2 frames only for a 0.35+ peer."""
    if fmt == V5:
        return _pack5.from_v3(data)
    if fmt == V4 and codec:
        return _pack4.from_v3(data, codec, v2=at_least(peer_version, (0, 35)))
    return data


def for_peer(data: bytes, capabilities: dict[str, Any]) -> bytes:
    """*data* (a v3 pack) in the best format a server with these capabilities reads."""
    fmt, codec = choose(capabilities.get("pack_formats"), capabilities.get("pack_codecs"))
    return convert(data, fmt, codec, peer_version=capabilities.get("version"))


def request_fields(capabilities: dict[str, Any]) -> dict[str, Any]:
    """Fetch-body fields offering newer packs, only to a server that advertises them."""
    offered = capabilities.get("pack_formats") or []
    if V5 in offered:  # only 0.37+ lists it, and accepts ``peer_version``
        return {
            "pack_codecs": _pack4.local_codecs(),
            "pack_formats": local_formats(),
            PEER_VERSION: __version__,
        }
    return _pack4.request_fields(capabilities)


__all__ = [
    "PEER_VERSION",
    "V3",
    "V4",
    "V5",
    "at_least",
    "choose",
    "convert",
    "for_peer",
    "local_formats",
    "request_fields",
]
