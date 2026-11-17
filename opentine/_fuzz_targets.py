"""The fuzz targets (0.53): each reads one untrusted input the way the product does.

Every target names its documented refusals; :func:`opentine._fuzz.check` calls
anything else a crash. A target's input is a tuple of byte strings:

* ``otlp-spans`` / ``otlp-logs`` -- one OTLP protobuf export request body
  (``opentine._otlp_fuzz.run_one``: bounded decoder, then the GenAI importer).
* ``tine`` -- one ``.tine`` v4 or v5 artifact, plain or TINEZ1-wrapped
  (``read_v4``), then ``verify_integrity`` on the parsed document, which must
  answer a result and never raise.
* ``pack`` -- one wire pack, TINEPACK3, 4 or 5 (``inspect_pack``).
* ``localpack`` -- a storage-v3 local pack: ``(.tidx, .tpk, dicts JSON)``,
  where the JSON maps a ``dicts/`` name to base64 dictionary bytes (codec 3);
  every listed object is read back.
* ``dsse`` -- one DSSE envelope as JSON, through the in-toto run attestation
  verifier (pinned key and trust-on-first-use) and the ``replay/v1`` verifier.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

#: The Ed25519 key the DSSE seeds are signed with (a fixed test key, never a secret).
DSSE_SEED_KEY = bytes(range(32))
_REFUSALS: tuple[type[BaseException], ...] = (ValueError, RecursionError)


@dataclass(frozen=True)
class Target:
    run: Callable[[tuple[bytes, ...]], None]
    refusals: tuple[type[BaseException], ...] = _REFUSALS
    parts: int = 1


def _otlp(route: str) -> Callable[[tuple[bytes, ...]], None]:
    def run(parts: tuple[bytes, ...]) -> None:
        from opentine import _otlp_fuzz

        _otlp_fuzz.run_one(route, parts[0])

    return run


def _tine(parts: tuple[bytes, ...]) -> None:
    from opentine import _codec
    from opentine._artifact_io import MAX_TINE_ARTIFACT_BYTES, parse_artifact_json
    from opentine._artifact_v4_read import read_v4
    from opentine._graph_serde import verify_integrity

    try:
        data = parse_artifact_json(_codec.unwrap(parts[0], limit=MAX_TINE_ARTIFACT_BYTES))
    except _REFUSALS:
        data = None
    if isinstance(data, dict):
        result = verify_integrity(data)  # answers ok or a reason; raising is a crash
        if not isinstance(result.ok, bool):
            raise AssertionError("verify_integrity answered no verdict")
    read_v4(parts[0])


def _pack(parts: tuple[bytes, ...]) -> None:
    from opentine.repository.pack import inspect_pack

    inspect_pack(parts[0])


def _dicts(raw: bytes) -> dict[str, bytes]:
    """The harness's own framing of ``dicts/``; garbage here means no dictionaries."""
    try:
        listed = json.loads(raw)
        return {
            str(name): base64.b64decode(value, validate=True)
            for name, value in listed.items()
            if isinstance(name, str) and name.isalnum() and isinstance(value, str)
        }
    except (ValueError, AttributeError, TypeError, binascii.Error, RecursionError):
        return {}


def _localpack(parts: tuple[bytes, ...]) -> None:
    from opentine.repository._pack_write import load_pack, pack_version

    index, body, dicts = parts[0], parts[1], _dicts(parts[2])
    digest = hashlib.sha256(body).hexdigest()
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        (root / "packs").mkdir()
        (root / "packs" / f"{digest}.tpk").write_bytes(body)
        (root / "packs" / f"{digest}.tidx").write_bytes(index)
        if dicts:
            (root / "dicts").mkdir()
            for name, content in dicts.items():
                (root / "dicts" / f"{name}.zdict").write_bytes(content)
        pack_version(root, digest)
        single = load_pack(root, digest)
        for oid in single.in_block_order():
            single.read(oid)


def _dsse(parts: tuple[bytes, ...]) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine import _intoto_replay, intoto

    envelope = json.loads(parts[0])
    public = Ed25519PrivateKey.from_private_bytes(DSSE_SEED_KEY).public_key()
    for result in (
        intoto.verify_envelope(envelope, public_key=public),
        intoto.verify_envelope(envelope, trust_embedded=True),
    ):
        if not isinstance(result, intoto.EnvelopeResult):
            raise AssertionError("verify_envelope answered no result")
    _intoto_replay.verify_envelope(envelope, public)


TARGETS: dict[str, Target] = {
    "otlp-spans": Target(_otlp("add_spans")),
    "otlp-logs": Target(_otlp("add_logs")),
    "tine": Target(_tine),
    "pack": Target(_pack),
    "localpack": Target(_localpack, parts=3),
    "dsse": Target(_dsse),
}

__all__ = ["DSSE_SEED_KEY", "TARGETS", "Target"]
