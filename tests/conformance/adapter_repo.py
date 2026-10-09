"""The repository half of the conformance adapter (SPEC Parts 1.5 and 2).

Split from ``adapter`` so neither module hides an op behind a scroll. Ops that
the reference implements only against a filesystem -- the ref file reader, the
config validator, pack installation -- are answered by materializing the input
in a temporary directory and calling the real function, rather than by
re-deriving the rule here. Re-deriving it would make the vector agree with a
second implementation written by the same author, which proves nothing.
"""

from __future__ import annotations

import base64
import tempfile
from pathlib import Path
from typing import Any

from opentine.kernel import ObjectEnvelope, canonical_json, parse_oid
from opentine.repository._annotations import validate_annotation_chain
from opentine.repository._config import validate_config
from opentine.repository._ref_store import read_ref_oid
from opentine.repository._refs import normalize_ref, validate_ref_oid, validate_ref_target
from opentine.repository._run_graph import validate_run_graph
from opentine.repository._shallow import _decode as decode_shallow
from opentine.repository._shallow import encode_shallow
from opentine.repository.pack import inspect_pack, install_pack


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _stored(args: dict[str, Any]) -> dict[str, bytes]:
    """``args.objects`` -- base64 stored envelopes -- as an oid -> bytes map."""
    out: dict[str, bytes] = {}
    for encoded in args.get("objects") or []:
        raw = base64.b64decode(encoded, validate=True)
        out[ObjectEnvelope.decode(raw).oid] = raw
    return out


def existence(args: dict[str, Any]):
    """The ``exists`` callable SPEC 1.5.6 needs, or ``None`` for no check."""
    if not any(key in args for key in ("present", "objects", "shallow")):
        return None
    known = set(args.get("present") or []) | set(_stored(args)) | set(args.get("shallow") or [])
    return lambda oid: oid in known


class MemRepo:
    """The smallest object store the cross-object validators accept."""

    def __init__(self, args: dict[str, Any]) -> None:
        self._objects = _stored(args)
        self._present = set(args.get("present") or []) | set(self._objects)
        self._shallow = frozenset(args.get("shallow") or [])

    def has(self, oid: str) -> bool:
        return oid in self._present

    def raw(self, oid: str) -> bytes:
        return self._objects[oid]

    def get(self, oid: str) -> ObjectEnvelope:
        return ObjectEnvelope.decode(self._objects[oid], oid)

    def shallow_oids(self) -> frozenset[str]:
        return self._shallow


def op_annotation_chain(inp, args: dict[str, Any]) -> dict[str, Any]:
    validate_annotation_chain(MemRepo(args), ObjectEnvelope.decode(inp.bytes_()))
    return {}


def op_run_graph(inp, args: dict[str, Any]) -> dict[str, Any]:
    validate_run_graph(MemRepo(args), ObjectEnvelope.decode(inp.bytes_()))
    return {}


def op_object_load(inp, args: dict[str, Any]) -> dict[str, Any]:
    """A full local read: SPEC Part 6 items 3-5 in one op."""
    from opentine.kernel import validate_links
    from opentine.repository._run_graph import validate_event_metrics

    repo = MemRepo(args)
    envelope = ObjectEnvelope.decode(inp.bytes_(), args.get("expected_oid"))
    links = validate_links(envelope, existence(args))
    validate_event_metrics(envelope)
    validate_run_graph(repo, envelope)
    validate_annotation_chain(repo, envelope)
    return {"oid": envelope.oid, "links": sorted(links)}


def op_object_path(inp, args: dict[str, Any]) -> dict[str, Any]:
    object_type, digest = parse_oid(inp.value)
    return {"path": f"objects/{object_type}/{digest[:2]}/{digest[2:]}"}


def op_config_validate(inp, args: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / "config.json"
        path.write_bytes(inp.bytes_())
        validate_config(path)
    return {}


def op_ref_name(inp, args: dict[str, Any]) -> dict[str, Any]:
    return {"name": normalize_ref(inp.value)}


def op_ref_file(inp, args: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as scratch:
        base = Path(scratch)
        target = base / "refs" / "heads"
        target.mkdir(parents=True)
        (target / "main").write_bytes(inp.bytes_())
        return {"oid": read_ref_oid(base, "heads/main")}


def op_ref_target(inp, args: dict[str, Any]) -> dict[str, Any]:
    name = args["name"]
    validate_ref_oid(name, inp.value)
    stored = _stored(args)
    if inp.value in stored:
        envelope = ObjectEnvelope.decode(stored[inp.value], inp.value)
        payload = envelope.payload() if envelope.encoding == "json" else None
        validate_ref_target(name, envelope.object_type, payload)
    return {}


def op_reflog_row(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 2.6, writer-only.

    ``_reflog.reflog_entry`` calls ``time.time_ns()`` and is not injectable, so
    its *bytes* can never be a vector. It is still called here for its
    disposition -- it is what enforces the 4096-character actor bound and the
    string type -- and the row is then composed from the caller's fixed
    ``time_ns`` so the expected bytes are deterministic.
    """
    from opentine.repository._reflog import reflog_entry

    row = inp.value
    fields = {
        "actor": row["actor"],
        "new": row["new"],
        "old": row["old"],
        "ref": row["ref"],
        "time_ns": row["time_ns"],
    }
    normalized = normalize_ref(fields["ref"])
    parse_oid(fields["new"])
    if fields["old"] is not None:
        parse_oid(fields["old"])
    reflog_entry(normalized, fields["old"], fields["new"], fields["actor"])
    if not isinstance(fields["time_ns"], str) or not fields["time_ns"].isdigit():
        raise ValueError("reflog time_ns must be decimal digits in a JSON string")
    return {"bytes_b64": _b64(canonical_json(fields) + b"\n")}


def op_shallow_parse(inp, args: dict[str, Any]) -> dict[str, Any]:
    return {"oids": sorted(decode_shallow(inp.bytes_()))}


def op_shallow_encode(inp, args: dict[str, Any]) -> dict[str, Any]:
    return {"bytes_b64": _b64(encode_shallow(inp.value))}


def op_pack_inspect(inp, args: dict[str, Any]) -> dict[str, Any]:
    pack_id, objects, shallow = inspect_pack(inp.bytes_())
    return {
        "pack_id": pack_id,
        "objects": sorted(oid for oid, _ in objects),
        "shallow": sorted(shallow),
    }


def op_pack_manifest(inp, args: dict[str, Any]) -> dict[str, Any]:
    """The writer half: manifest bytes and pack id, with compression left free."""
    import hashlib

    from opentine.kernel import validate_links

    raws = [base64.b64decode(item, validate=True) for item in inp.value]
    entries = []
    packed = {ObjectEnvelope.decode(raw).oid for raw in raws}
    shallow: set[str] = set()
    for raw in raws:
        envelope = ObjectEnvelope.decode(raw)
        entries.append({"data": _b64(raw), "id": envelope.oid})
        shallow.update(link for link in validate_links(envelope) if link not in packed)
    entries.sort(key=lambda entry: entry["id"])
    body = canonical_json({"objects": entries, "shallow": sorted(shallow), "version": 1})
    return {
        "manifest_body_b64": _b64(body),
        "pack_id": f"sha256:{hashlib.sha256(body).hexdigest()}",
    }


def op_pack_install(inp, args: dict[str, Any]) -> dict[str, Any]:
    from opentine.repository.store import Repo

    with tempfile.TemporaryDirectory() as scratch:
        repo = Repo.init(Path(scratch) / "work")
        for raw in _stored(args).values():
            envelope = ObjectEnvelope.decode(raw)
            path = repo._object_path(envelope.oid)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        result = install_pack(repo, inp.bytes_())
        return {"pack_id": result.pack_id, "objects": sorted(result.objects)}


OPS = {
    "annotation.chain": op_annotation_chain,
    "run.graph": op_run_graph,
    "object.load": op_object_load,
    "object.path": op_object_path,
    "config.validate": op_config_validate,
    "ref.name": op_ref_name,
    "ref.file": op_ref_file,
    "ref.target": op_ref_target,
    "reflog.row": op_reflog_row,
    "shallow.parse": op_shallow_parse,
    "shallow.encode": op_shallow_encode,
    "pack.inspect": op_pack_inspect,
    "pack.manifest": op_pack_manifest,
    "pack.install": op_pack_install,
}
