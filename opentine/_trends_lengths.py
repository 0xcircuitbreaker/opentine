"""Signed task lengths for the trends time horizon (0.72): ``opentine.trends.task-lengths/1``.

The 50%-success horizon needs, per eval item, how long the task takes a
human (minutes). Those lengths are a signed file convention, not an object
kind (docs/TRENDS.md)::

    {"kind": "opentine.trends.task-lengths/1", "suite": "NAME", "dataset": "sha256:<hex>",
     "lengths": {"<item id>": "<minutes, decimal>"}, "signer": "sha256:<fpr>",
     "signed_at": "YYYY-MM-DDTHH:MM:SSZ", "signature": {tine-sig/3, Ed25519}}

The signature covers the domain ``opentine.trends.task-lengths.v1:`` and the
record (:mod:`opentine._signed_record`). :func:`load` uses the lengths only when
the signature holds, ``signer`` is the key the signature rests on, and that key
holds the ``dataset`` role in the owner-pinned trust bundle and is not an
``optimizer`` key: a loop cannot set the yardstick it is measured with. In any
other case the horizon is withheld and ``status`` says why (fail closed).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from opentine import _signed_record as sr

KIND = "opentine.trends.task-lengths/1"
DOMAIN = b"opentine.trends.task-lengths.v1:"
FIELDS = ("kind", "suite", "dataset", "lengths", "signer", "signed_at")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
DEFAULT = Path(".tine") / "trends" / "task-lengths.json"
MINUTES = re.compile(r"(0|[1-9][0-9]{0,8})(\.[0-9]{0,5}[1-9])?")
MAX_ITEMS = 1_000_000


def _check_lengths(lengths: Any) -> dict[str, str]:
    if not isinstance(lengths, dict) or not lengths or len(lengths) > MAX_ITEMS:
        raise ValueError("lengths must map 1..1000000 item ids to minutes")
    for item, minutes in lengths.items():
        if not (isinstance(item, str) and sr.NAME.fullmatch(item)):
            raise ValueError(f"invalid item id {item!r}")
        if not (isinstance(minutes, str) and MINUTES.fullmatch(minutes) and minutes != "0"):
            raise ValueError(f"item {item}: minutes must be a positive decimal string")
    return lengths


def sign(lengths: dict[str, str], key: Any, *, suite: str, dataset: str,
         at: str) -> dict[str, Any]:  # fmt: skip
    """The signed record for *lengths* (item id -> minutes)."""
    from opentine._signing_pins import key_fingerprint

    if not sr.NAME.fullmatch(suite):
        raise ValueError("--suite is 1..256 of A-Z a-z 0-9 _ . : / @ + -")
    if not (isinstance(dataset, str) and DIGEST.fullmatch(dataset)):
        raise ValueError("--dataset is the eval dataset digest, sha256:HEX")
    if not sr.WHEN.fullmatch(at):
        raise ValueError("--at is YYYY-MM-DDTHH:MM:SSZ")
    body = {
        "kind": KIND,
        "suite": suite,
        "dataset": dataset,
        "lengths": dict(sorted(_check_lengths(lengths).items())),
        "signer": key_fingerprint(key.public_key().public_bytes_raw()),
        "signed_at": at,
    }
    return sr.sign(body, DOMAIN, "task lengths", key, algorithm="ed25519", signed_at=at)


def verify(record: Any) -> dict[str, Any]:
    """The body of a record whose signature holds under its own signer; RecordError else."""
    from opentine._signing_pins import used_key_fingerprint

    body = sr.fields(record, KIND, FIELDS, "trends-lengths", "the task lengths")
    _check_lengths(body["lengths"])
    if not (isinstance(body["suite"], str) and sr.NAME.fullmatch(body["suite"])):
        raise sr.RecordError("trends-lengths.malformed", "the suite name is invalid")
    if not (isinstance(body["dataset"], str) and DIGEST.fullmatch(body["dataset"])):
        raise sr.RecordError("trends-lengths.malformed", "the dataset digest is invalid")
    sr.check_signature(record, body, domain=DOMAIN, code="trends-lengths", subject="task lengths")
    if used_key_fingerprint(record.get("signature")) != body["signer"]:
        raise sr.RecordError("trends-lengths.signer-mismatch",
                             "signer is not the key the signature rests on")  # fmt: skip
    return body


def load(path: Path, store: Path | None) -> dict[str, Any]:
    """``{"status", "suite", "signer", "dataset", "lengths"}``; ``dataset`` is ``None`` and
    ``lengths`` empty unless trusted.

    ``status``: ``trusted``, ``missing``, ``invalid``, ``roles-unpinned`` or
    ``signer-untrusted``.
    """
    from opentine._key_roles_pin import pinned

    out: dict[str, Any] = {"status": "missing", "suite": None, "signer": None, "dataset": None,
                           "lengths": {}}  # fmt: skip
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return out
    try:
        body = verify(json.loads(raw.decode("utf-8")))
    except (sr.RecordError, ValueError, UnicodeDecodeError):
        return {**out, "status": "invalid"}
    out.update(suite=body["suite"], signer=body["signer"])
    roles = pinned(store)
    if roles is None:
        return {**out, "status": "roles-unpinned"}
    signer = body["signer"]
    if signer not in roles.get("dataset", []) or signer in roles.get("optimizer", []):
        return {**out, "status": "signer-untrusted"}
    return {**out, "status": "trusted", "dataset": body["dataset"], "lengths": body["lengths"]}


__all__ = ["DEFAULT", "DOMAIN", "KIND", "load", "sign", "verify"]
