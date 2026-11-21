"""A contributor's public bundle of one run, its leak scan and its check (0.75).

:func:`build` derives the run's redacted public copy (:mod:`opentine._redacted_derive`)
with the contributor's deny-list applied after the publication ruleset, adds a
signed licence annotation on the public run (:mod:`opentine._dataset_licence`)
to the pack, and signs the ``opentine.redacted-copy`` record over that pack
with the same Ed25519 key (the bundle's contributor key). The record's ruleset
reads ``opentine-redaction/2+publish/1+contributor/1``; nothing of the
deny-list (terms, count, digest) is written.

:func:`leak_scan` unbundles the result into a fresh repository and counts
deny-list matches in every object and in the manifest; ``tine dataset
contrib-redact`` keeps the bundle only when that count is zero.

:func:`check` is ``tine dataset check``: the bundle must verify, carry an
Ed25519-signed redacted-copy record, a verified licence annotation by that
record's key with an allowed SPDX id, a clean file-level licence scan, and its
public run must not be tombstoned.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from typing import Any

from opentine._redact_publish import PUBLISH_RULESET

RULESET = f"{PUBLISH_RULESET}+contributor/1"


def build(
    repo: Any,
    ref: str,
    run: str,
    key: Any,
    deny: Any,
    *,
    spdx: str,
    grant: bool,
    at: str,
    allow: tuple[str, ...],
    pack_format: str = "TINEPACK3",
) -> tuple[bytes, dict[str, Any]]:
    """``(bundle bytes, summary)`` for *run*'s contributed public copy under *ref*."""
    from opentine import _bundle, _dataset_licence, _redacted_copy
    from opentine._redacted_derive import _View, derive
    from opentine.repository import _pack5, _tombstones
    from opentine.repository._pack5 import V5
    from opentine.repository.pack import create_pack

    counts: dict[str, dict[str, int]] = {}
    public, objects, boundary, changed = derive(repo, run, counts, deny=deny)
    note = _dataset_licence.envelope(public, spdx, grant, key, at, allow)
    objects[note.oid] = note.encode()
    pack = create_pack(_View(objects, boundary), sorted(objects))
    if pack_format == V5:
        pack = _pack5.from_v3(pack, slim=True)
    record = {
        "kind": _redacted_copy.KIND,
        "copy_version": 1,
        "source_run": run,
        "public_run": public,
        "ruleset": RULESET,
        "objects": len(objects),
        "redacted": changed,
        "pack": "sha256:" + hashlib.sha256(pack).hexdigest(),
    }
    extra: dict[str, Any] = {"tombstones": _tombstones.carried(repo, boundary)}
    extra["redacted_public"] = _redacted_copy.sign(record, key, algorithm="ed25519")
    totals: dict[str, int] = {}
    for per in counts.values():
        for kind, number in per.items():
            totals[kind] = totals.get(kind, 0) + number
    summary = {
        "source_run": run,
        "public_run": public,
        "objects": len(objects),
        "redacted": changed,
        "ruleset": RULESET,
        "totals": totals,
        "licence_record": note.oid,
    }
    return _bundle.assemble(pack, {ref: public}, extra), summary


def objects_of(data: bytes) -> tuple[Any, dict[str, Any]]:
    """``(verified bundle, {oid: envelope})``; raises ``BundleError`` for a bad bundle."""
    from opentine import _bundle
    from opentine.kernel import ObjectEnvelope
    from opentine.repository.pack import inspect_pack

    checked = _bundle.verify(data)
    _, rows, _ = inspect_pack(checked.pack)
    return checked, {oid: ObjectEnvelope.decode(raw, oid) for oid, raw in rows}


def leak_scan(data: bytes, deny: Any) -> dict[str, int]:
    """Deny-list matches left in the unbundled copy of *data*: ``{objects, hits}``."""
    from opentine import _bundle
    from opentine.repository import Repo

    checked, found = objects_of(data)
    body = data[len(_bundle.MAGIC) + 32 :]
    hits = deny.count(_bundle._manifest(body[4 : 4 + int.from_bytes(body[:4], "big")]))
    with tempfile.TemporaryDirectory(prefix="tine-contrib-", ignore_cleanup_errors=True) as tmp:
        target = Repo.init(Path(tmp) / "scan")
        _bundle.unbundle(target, data, "contrib")
        for oid in found:
            env = target.get(oid)
            hits += deny.count(env.body if env.encoding == "raw" else env.payload())
        hits += sum(deny.count(ref) for ref in checked.refs)
        close = getattr(target, "close", None)
        if callable(close):
            close()
    return {"objects": len(found), "hits": hits}


def check(
    data: bytes,
    *,
    allow: tuple[str, ...],
    pubkey: bytes | None = None,
    tombstones: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """The ``tine dataset check`` row; ``ok`` false lists each ``problem``."""
    from opentine import _dataset_licence, _redacted_copy
    from opentine._dataset_withdraw import tombstoned
    from opentine._signed_record import RecordError
    from opentine._signing_pins import used_key_fingerprint

    checked, found = objects_of(data)
    problems: list[str] = []
    record = checked.redacted_public
    row: dict[str, Any] = {
        "contributor": None,
        "public_run": None,
        "record_state": None,
        "licence": [],
        "scan": [],
        "allow": list(allow),
    }
    if record is None:
        return {**row, "ok": False, "problems": ["not a --redacted-public bundle"]}
    row["public_run"] = record.get("public_run")
    if not isinstance(record.get("signature"), dict) or record["signature"].get("alg") != "ed25519":
        problems.append("the redacted-copy record is not signed with an Ed25519 contributor key")
    else:
        try:
            state = _redacted_copy.check(record, public_key=pubkey, pack=record["pack"])["state"]
            row["record_state"] = state
            row["contributor"] = used_key_fingerprint(record["signature"])
        except RecordError as exc:
            row["record_state"] = f"failed: {exc.code}"
            problems.append(f"the redacted-copy record does not verify ({exc.code})")
    notes = _dataset_licence.annotations(found, row["public_run"], row["contributor"], allow)
    row["licence"] = notes
    if not any(n["state"] == "verified" for n in notes):
        why = notes[0]["state"] if notes else "no licence annotation"
        problems.append(f"no valid licence annotation by the contributor key ({why})")
    row["scan"] = _dataset_licence.scan(found, allow)
    if row["scan"]:
        problems.append(f"the file-level licence scan is dirty ({len(row['scan'])} findings)")
    runs = (row["public_run"] or "", str(record.get("source_run") or ""))
    if tombstones and any(tombstoned(r, tombstones) for r in runs):
        problems.append("the public run is tombstoned (withdrawn)")
    return {**row, "ok": not problems, "problems": problems}


__all__ = ["RULESET", "build", "check", "leak_scan", "objects_of"]
