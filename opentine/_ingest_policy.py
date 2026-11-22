"""Sampling policies for batched streaming ingest (0.77): ``opentine.ingest-policy/1``.

A sampling policy says what an ingest stream keeps and what it drops. It is a
claim convention: the ``value`` of an existing ``annotation`` object on the
stream's anchor blob (``{"convention": "opentine.ingest-stream/1", "stream":
S}``); no new kind::

    {"convention": "opentine.ingest-policy/1", "stream": "rl-train",
     "capture": ["*"] | ["episode", "step", ...], "drop": ["debug", ...],
     "rate": 0.25, "seed_source": "operator" | "random", "seed": "<64 hex>",
     "redact": true, "issued_at": "YYYY-MM-DDTHH:MM:SSZ"}

``redact`` (default true) runs the stored-blob credential scrubber over each
batch's captured events before they are signed; a stream of plain numeric
steps may turn it off, and the signed policy then says so.

An event of kind ``k`` at stream index ``i`` is captured when ``k`` is captured
(``"*"`` or listed), is not listed in ``drop``, and
``u(seed, stream, i) < rate``, where ``u`` is the first 8 bytes of
``SHA-256(seed || stream || 0x00 || decimal(i))`` read as a fraction of 2^64.
The decision is a pure function of the signed policy and the index, so an
auditor recomputes it for every captured event; the seed is fixed before any
event is seen. The policy digest is SHA-256 over the claim's canonical JSON.

The policy is signed (Ed25519) by the key named in ``signer``; the signer is
the key that signed (``used_key_fingerprint``). It takes effect for
``tine ingest verify`` only when that key holds the ``policy`` role in the
owner-pinned trust bundle (:mod:`opentine._key_roles_pin`) and holds no
``optimizer`` role. Every policy is held (``ingest-policy:STREAM``), released
never.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any

from opentine.kernel import canonical_json

CONVENTION = "opentine.ingest-policy/1"
STREAM_CONVENTION = "opentine.ingest-stream/1"
SEED_SOURCES = ("operator", "random")
STREAM = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
KIND = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$")
SEED = re.compile(r"^[0-9a-f]{64}$")
MAX_KINDS = 256
_KEYS = {"convention", "stream", "capture", "drop", "rate", "seed_source", "seed", "redact",
         "issued_at"}  # fmt: skip


class IngestError(ValueError):
    """An ingest policy, batch or stream that cannot be used."""


def stream_name(value: Any) -> str:
    if not isinstance(value, str) or not STREAM.fullmatch(value):
        raise IngestError(f"{value!r} is not a stream name: lowercase [a-z0-9._-], at most 64")
    return value


def _kinds(name: str, value: Any, *, star: bool) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_KINDS:
        raise IngestError(f"{name} is a list of at most {MAX_KINDS} event kinds")
    for kind in value:
        if not (isinstance(kind, str) and (KIND.fullmatch(kind) or (star and kind == "*"))):
            raise IngestError(f"{name} holds {kind!r}, which is not an event kind")
    if "*" in value and value != ["*"]:
        raise IngestError(f'{name} is ["*"] or a list of kinds, not both')
    return sorted(set(value))


def claim(doc: Any) -> dict[str, Any]:
    """The validated policy claim of *doc*."""
    if not isinstance(doc, dict) or doc.get("convention") != CONVENTION or set(doc) - _KEYS:
        raise IngestError(f"not an {CONVENTION} claim")
    rate = doc.get("rate")
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate):
        raise IngestError("rate is a number in (0, 1]")
    if not 0 < rate <= 1:
        raise IngestError("rate is a number in (0, 1]")
    if doc.get("seed_source") not in SEED_SOURCES:
        raise IngestError(f"seed_source is one of {', '.join(SEED_SOURCES)}")
    if not isinstance(doc.get("seed"), str) or not SEED.fullmatch(doc["seed"]):
        raise IngestError("seed is 64 lowercase hex digits")
    if not isinstance(doc.get("redact"), bool):
        raise IngestError("redact is true or false")
    if not isinstance(doc.get("issued_at"), str):
        raise IngestError("issued_at is an RFC 3339 time")
    return {"convention": CONVENTION, "stream": stream_name(doc.get("stream")),
            "capture": _kinds("capture", doc.get("capture"), star=True),
            "drop": _kinds("drop", doc.get("drop", []), star=False), "rate": float(rate),
            "seed_source": doc["seed_source"], "seed": doc["seed"], "redact": doc["redact"],
            "issued_at": doc["issued_at"]}  # fmt: skip


def build(stream: str, *, capture: list[str], drop: list[str], rate: float, seed: str | None,
          issued_at: str, redact: bool = True) -> dict[str, Any]:  # fmt: skip
    """A policy claim; ``seed=None`` draws a random seed and records that it did."""
    import os

    source = "operator" if seed is not None else "random"
    value = seed.strip().lower() if seed is not None else os.urandom(32).hex()
    return claim({"convention": CONVENTION, "stream": stream, "capture": capture or ["*"],
                  "drop": drop, "rate": rate, "seed_source": source, "seed": value,
                  "redact": redact, "issued_at": issued_at})  # fmt: skip


def digest(policy: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(claim(policy))).hexdigest()


def fraction(seed: str, stream: str, index: int) -> float:
    material = bytes.fromhex(seed) + stream.encode("ascii") + b"\x00" + str(index).encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big") / 2**64


def decide(policy: dict[str, Any], index: int, kind: str) -> str | None:
    """``None`` when the event is captured; else why it is dropped (``kind`` or ``rate``)."""
    capture = policy["capture"]
    if (capture != ["*"] and kind not in capture) or kind in policy["drop"]:
        return "kind"
    if policy["rate"] < 1 and fraction(policy["seed"], policy["stream"], index) >= policy["rate"]:
        return "rate"
    return None


def _anchor_bytes(stream: str) -> bytes:
    return canonical_json({"convention": STREAM_CONVENTION, "stream": stream_name(stream)})


def anchor(repo: Any, stream: str) -> str:
    """Store the stream's anchor blob, the target every record of the stream names."""
    return repo.put("blob", _anchor_bytes(stream), redact=False)


def anchor_id(stream: str) -> str:
    from opentine.kernel import ObjectEnvelope

    return ObjectEnvelope.create("blob", _anchor_bytes(stream)).oid


def record(repo: Any, policy: dict[str, Any], key: Any) -> str:
    """Sign *policy* with *key*, store it as an annotation and hold it; its id."""
    from opentine._ingest_holds import hold_policy, write

    clean = claim(policy)
    oid = write(repo, anchor(repo, clean["stream"]), clean, key, previous=None,
                signed_at=clean["issued_at"])  # fmt: skip
    hold_policy(repo, clean["stream"], oid)
    return oid


def judge(signer: str | None, roles: dict[str, Any]) -> str | None:
    """``None`` when a policy signed by *signer* may take effect; else the finding code.

    Fails closed: no pinned roles, an unsigned policy, an optimizer key or a key
    without the pinned ``policy`` role each refuse it.
    """
    if signer is None:
        return "ingest.policy-unsigned"
    if roles.get("status") != "pinned":
        return "ingest.policy-unpinned"
    held = roles.get("roles") or {}
    if signer in held.get("optimizer", []):
        return "ingest.policy-optimizer-key"
    if signer not in held.get("policy", []):
        return "ingest.policy-role"
    return None


__all__ = ["CONVENTION", "IngestError", "SEED_SOURCES", "anchor", "build", "claim", "decide",
           "anchor_id", "digest", "fraction", "judge", "record", "stream_name"]  # fmt: skip
