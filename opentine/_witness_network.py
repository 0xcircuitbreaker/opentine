"""The witness-network registry, ``opentine-witness-network/1`` (0.49).

A hosted log publishes the witness set it requires as one JSON document::

    {"schema": "opentine-witness-network/1",
     "log": {"origin": "log.example/main", "vkey": "<signed-note vkey>"},
     "policy": {"quorum": "2-of-3"},
     "witnesses": [{"name": "w1.example", "operator": "Org One",
                    "url": "https://w1.example", "vkeys": ["<cosignature/v1 vkey>", ...],
                    "contact": "mailto:ops@w1.example"}, ...]}

It is configuration, not a signed object: it names the keys a verifier pins,
so it is fetched once over an authenticated channel and checked in, exactly
like ``--witness-vkey`` arguments. :func:`load` refuses a registry that does
not meet the network policy: at least three witnesses, each run by a distinct
operator under a distinct name, a quorum that is a strict majority (``2N > M``,
so two disjoint quorums -- a split view -- cannot both exist), keys whose name
matches their witness, and ``https`` URLs (``http`` only on loopback, for
tests). A witness lists every vkey it currently cosigns with (rotation, SPEC
8.23): a cosignature by any of them counts once for that witness.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from opentine.repository._tlog import LogError
from opentine.repository._tlog_cosign import cosigners, parse_quorum, parse_witness_vkey
from opentine.repository._tlog_note import parse_vkey

SCHEMA = "opentine-witness-network/1"
MAX_BYTES = 1 << 20
MAX_WITNESSES = 64
MAX_KEYS = 4
MIN_WITNESSES = 3
LOOPBACK = ("127.0.0.1", "localhost", "::1")
_TOP = {"schema", "log", "policy", "witnesses", "description"}
_ENTRY = {"name", "operator", "url", "vkeys", "contact", "jurisdiction"}


def looks_like_quorum(text: str) -> bool:
    need, sep, total = text.lower().partition("-of-")
    return bool(sep) and need.isdigit() and total.isdigit()


def _str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LogError(f"witness network: {what} must be a non-empty string")
    return value


def _url(value: Any, name: str) -> str:
    parts = urlsplit(_str(value, f"{name} url"))
    loopback = parts.scheme == "http" and parts.hostname in LOOPBACK
    if not (parts.scheme == "https" or loopback) or not parts.hostname:
        raise LogError(f"witness network: {name} url must be https (http only on loopback)")
    return value


def _entry(item: Any, index: int) -> dict[str, Any]:
    if not isinstance(item, dict) or set(item) - _ENTRY:
        raise LogError(f"witness network: witness {index} is not a registry entry")
    name = _str(item.get("name"), f"witness {index} name")
    _str(item.get("operator"), f"{name} operator")
    _url(item.get("url"), name)
    vkeys = item.get("vkeys")
    if not isinstance(vkeys, list) or not 1 <= len(vkeys) <= MAX_KEYS:
        raise LogError(f"witness network: {name} must list 1 to {MAX_KEYS} vkeys")
    for vkey in vkeys:
        if parse_witness_vkey(_str(vkey, f"{name} vkey"))[0] != name:
            raise LogError(f"witness network: a vkey of {name} names another witness")
    for optional in ("contact", "jurisdiction"):
        if optional in item:
            _str(item[optional], f"{name} {optional}")
    return item


def validate(doc: Any) -> dict[str, Any]:
    """``doc`` if it is a registry that meets the network policy; LogError otherwise."""
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or set(doc) - _TOP:
        raise LogError(f"not an {SCHEMA} document")
    log, policy, witnesses = doc.get("log"), doc.get("policy"), doc.get("witnesses")
    if not isinstance(log, dict) or set(log) != {"origin", "vkey"}:
        raise LogError("witness network: log must be {origin, vkey}")
    if parse_vkey(_str(log["vkey"], "log vkey"))[0] != _str(log["origin"], "log origin"):
        raise LogError("witness network: the log vkey names another origin")
    if not isinstance(policy, dict) or set(policy) != {"quorum"}:
        raise LogError("witness network: policy must be {quorum}")
    need, total = parse_quorum(_str(policy["quorum"], "policy quorum"))
    if not isinstance(witnesses, list) or not 0 < len(witnesses) <= MAX_WITNESSES:
        raise LogError(f"witness network: witnesses must list 1 to {MAX_WITNESSES} entries")
    entries = [_entry(item, i) for i, item in enumerate(witnesses)]
    if total != len(entries):
        raise LogError(f"witness network: quorum {need}-of-{total} but {len(entries)} witnesses")
    if total < MIN_WITNESSES or 2 * need <= total:
        raise LogError(f"witness network: {need}-of-{total} is not a majority of 3 or more")
    for field in ("name", "operator", "url"):
        values = [str(e[field]).strip().lower().rstrip("/") for e in entries]
        if len(set(values)) != len(values):
            raise LogError(f"witness network: two witnesses share a {field}")
    keys = [parse_witness_vkey(v)[1] for e in entries for v in e["vkeys"]]
    if len(set(keys)) != len(keys):
        raise LogError("witness network: two entries share a key")
    return doc


def load(path: Path) -> dict[str, Any]:
    with open(path, "rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise LogError(f"witness network: {path.name} exceeds {MAX_BYTES} bytes")
    try:
        doc = json.loads(data)
    except ValueError as exc:
        raise LogError(f"witness network: {path.name} is not JSON") from exc
    return validate(doc)


def quorum(doc: dict[str, Any]) -> tuple[int, int]:
    return parse_quorum(doc["policy"]["quorum"])


def vkeys(doc: dict[str, Any]) -> list[str]:
    return [vkey for entry in doc["witnesses"] for vkey in entry["vkeys"]]


def check(note: bytes, doc: dict[str, Any]) -> dict[str, int]:
    """``{witness: timestamp}`` cosigners; LogError unless the policy quorum cosigned."""
    need, total = quorum(doc)
    found = cosigners(note, vkeys(doc))
    if len(found) < need:
        raise LogError(f"witness quorum not met: {len(found)} of {need}-of-{total} cosigned")
    return found


__all__ = ["SCHEMA", "check", "load", "looks_like_quorum", "quorum", "validate", "vkeys"]
