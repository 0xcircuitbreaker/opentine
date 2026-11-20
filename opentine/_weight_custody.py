"""Checkpoint and weight custody (0.71): signed, held, per-artifact hash-chained events.

Weights never enter the repository: an artifact is named, and each custody event
carries the **digest** (``sha256:``) and size of the bytes it concerns, computed by
:func:`file_digest` as a streaming read with a size cap. Nothing is uploaded.

Every event is an attestation (an existing object kind) whose claim names the
convention ``opentine.weight-custody/1`` and is kept by a ``custody:weights:`` hold
that ``tine hold release`` refuses, so a loop cannot delete the record of a copy
or a load. Events of one artifact form a hash chain: ``seq`` counts from 0 and
``prev`` is the attestation id of the event before. An event links the checkpoint
to its training ``run``, its ``data`` commitments (0.60 holdout and dataset
commitments) and its ``lineage`` node (0.58).

Signed means the Ed25519 signature verifies and the payload signer is the key that
signed (``used_key_fingerprint``, :mod:`opentine._containment_records`). Event
signers count only when the owner-pinned trust bundle gives them the ``runner``
role; an ``approved`` event (the approval to load a ``model-organism`` artifact)
counts only when it gives them the ``policy`` role. Gaps and approvals are judged
by :mod:`opentine._weight_custody_check`.
"""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Any

from opentine import _containment_records as records

CONVENTION = "opentine.weight-custody/1"
HOLD = "custody:weights:"
EVENTS = ("created", "copied", "loaded", "exported", "destroyed", "approved")
NEEDS_DIGEST = ("created", "copied", "loaded", "exported", "approved")
MODEL_ORGANISM = "model-organism"
TAGS = (MODEL_ORGANISM,)
MAX_BYTES = 1 << 40  # 1 TiB: the default cap of a streaming weight digest
CHUNK = 1 << 20
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@+-]{0,199}")
MAX_DATA = 256


def file_digest(path: Path, max_bytes: int = MAX_BYTES) -> tuple[str, int]:
    """``(sha256:<hex>, size)`` of *path*, read in chunks; ``ValueError`` past *max_bytes*."""
    digest, size = hashlib.sha256(), 0
    with Path(path).open("rb") as handle:
        while chunk := handle.read(CHUNK):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"{path} is larger than the {max_bytes}-byte digest cap")
            digest.update(chunk)
    return "sha256:" + digest.hexdigest(), size


def _check_fields(artifact: str, event: str, location: str, digest: str | None,
                  data: list[str], tags: list[str]) -> None:  # fmt: skip
    if not _NAME.fullmatch(artifact):
        raise ValueError(f"artifact name {artifact!r} is not [A-Za-z0-9._/@+-], 1..200 chars")
    if event not in EVENTS:
        raise ValueError(f"unknown custody event {event!r}; one of {', '.join(EVENTS)}")
    if not location or len(location) > 4096 or "\n" in location:
        raise ValueError("the location is one line of at most 4096 characters")
    if digest is None and event in NEEDS_DIGEST:
        raise ValueError(f"a {event} event needs --file or --digest")
    if digest is not None and not _DIGEST.fullmatch(digest):
        raise ValueError("a weight digest is sha256:<64 lowercase hex>")
    if len(data) > MAX_DATA or any(not _DIGEST.fullmatch(d) for d in data):
        raise ValueError(f"data commitments are at most {MAX_DATA} sha256:<64 hex> digests")
    if any(t not in TAGS for t in tags):
        raise ValueError(f"unknown tag; one of {', '.join(TAGS)}")
    if tags and event != "created":
        raise ValueError("tags are set by the created event only")


def record(repo: Any, artifact: str, event: str, key: Any, *, location: str,
           digest: str | None = None, size: int | None = None, run: str | None = None,
           data: list[str] | None = None, lineage: str | None = None,
           tags: list[str] | None = None, now: float | None = None) -> dict[str, Any]:  # fmt: skip
    """Sign, chain and hold one custody event; ``{"record", "seq", "prev", "claim"}``."""
    data, tags = sorted(set(data or [])), sorted(set(tags or []))
    _check_fields(artifact, event, location, digest, data, tags)
    rows = events(repo, artifact)
    prev = rows[-1]["oid"] if rows else None
    seq = len(rows)
    if rows and rows[0]["target"]:
        target = rows[0]["target"]
    else:
        target = run or records.anchor(repo, "custody", f"weight custody of {artifact}")
    claim = {"convention": CONVENTION, "artifact": artifact, "event": event, "seq": seq,
             "prev": prev, "location": location, "digest": digest, "size": size, "run": run,
             "data": data, "lineage": lineage, "tags": tags,
             "recorded_at": records.rfc3339(time.time() if now is None else now)}  # fmt: skip
    oid = records.record(repo, target, claim, key, f"{HOLD}{artifact}:{seq:08d}")
    return {"record": oid, "seq": seq, "prev": prev, "claim": claim}


def events(repo: Any, artifact: str) -> list[dict[str, Any]]:
    """The held events of *artifact*, by hold order (``seq``), each a records.read row."""
    prefix = f"{HOLD}{artifact}:"
    out = []
    for target, row in records.held(repo, prefix):
        tail = target[len(prefix) :]
        if tail.isdigit() and len(tail) == 8:  # not "a:b" when asked for "a"
            out.append({**row, "hold": target, "hold_seq": int(tail)})
    return out


def artifacts(repo: Any) -> list[str]:
    """Every artifact name with at least one held event, sorted."""
    from opentine.repository._holds import holds_path, read_holds

    names = {r["target"][len(HOLD):].rsplit(":", 1)[0]
             for r in read_holds(holds_path(repo)) if r["target"].startswith(HOLD)}  # fmt: skip
    return sorted(names)


__all__ = ["CONVENTION", "EVENTS", "HOLD", "MAX_BYTES", "MODEL_ORGANISM", "TAGS", "artifacts",
           "events", "file_digest", "record"]  # fmt: skip
