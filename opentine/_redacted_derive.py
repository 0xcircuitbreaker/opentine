"""Deriving a run's redacted public copy and its pack (0.46, SPEC 4.15).

:func:`derive` walks the run's object graph only (never its annotations or
attestations, which stay private) and rebuilds it bottom-up in memory:

* a plain blob is re-redacted with the current ruleset until it is stable;
* a tree blob (schema 2) keeps its entries, its links rewritten;
* every JSON payload (event, run) is redacted again, then each oid it names is
  rewritten to the oid of the object derived from it.

A blob the repository does not hold (purged, or cut by a shallow fetch) keeps
its oid and stays a boundary of the pack, with its tombstone carried beside it.
Nothing is written to the repository. :func:`public_bundle` packs the derived
objects, signs the ``opentine.redacted-copy`` record over the pack digest with
the caller's key, and writes an ordinary bundle whose one ref names the copy.
"""

from __future__ import annotations

import hashlib
from typing import Any

from opentine._redact_obfuscated import REDACTION_RULESET
from opentine._redacted_copy import KIND, sign
from opentine._v3_guards import guarded_redaction
from opentine.kernel import TREE_SCHEMA, ObjectEnvelope, validate_links
from opentine.redaction import redact_blob
from opentine.repository._run_graph import validate_run_graph
from opentine.repository.pack import create_pack

_MAX_PASSES = 4


def _stable(body: bytes) -> bytes:
    for _ in range(_MAX_PASSES):
        cleaned = redact_blob(body)
        if cleaned == body:
            return body
        body = cleaned
    raise ValueError("redaction of a blob did not settle; it cannot be published")


def _rewrite(value: Any, mapping: dict[str, str]) -> Any:
    if isinstance(value, str):
        return mapping.get(value, value)
    if isinstance(value, list):
        items = []
        for item in value:  # a loop, not a comprehension: one frame per level
            items.append(_rewrite(item, mapping))
        return items
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            out[key] = _rewrite(item, mapping)
        return out
    return value


class _View:
    """The derived objects, read like a repository by ``create_pack``."""

    def __init__(self, objects: dict[str, bytes], boundary: set[str]) -> None:
        self.objects, self.boundary = objects, boundary

    def has(self, oid: str) -> bool:
        return oid in self.objects

    def _link_exists(self, oid: str) -> bool:
        return oid in self.objects or oid in self.boundary

    def raw(self, oid: str) -> bytes:
        try:
            return self.objects[oid]
        except KeyError:
            raise KeyError(oid) from None

    def get(self, oid: str) -> ObjectEnvelope:
        return ObjectEnvelope.decode(self.raw(oid), oid)


def _derived(envelope: ObjectEnvelope, mapping: dict[str, str]) -> ObjectEnvelope:
    if envelope.encoding == "raw" and envelope.schema != TREE_SCHEMA:
        return ObjectEnvelope.create("blob", _stable(envelope.body), envelope.schema)
    if envelope.encoding == "raw":  # a tree: its entries are links
        import json

        from opentine.kernel import _parse_int, canonical_json

        tree = _rewrite(json.loads(envelope.body, parse_int=_parse_int), mapping)
        return ObjectEnvelope.create("blob", canonical_json(tree), envelope.schema)
    where = f"redacted copy {envelope.object_type!r}"
    payload = _rewrite(guarded_redaction(envelope.payload(), where=where), mapping)
    return ObjectEnvelope.create(envelope.object_type, payload, envelope.schema)


def derive(repo: Any, run: str) -> tuple[str, dict[str, bytes], set[str], int]:
    """``(public run, derived objects, boundary oids, objects changed)`` for *run*."""
    if not run.startswith("run:") or not repo.has(run):
        raise KeyError(f"no such run in this repository: {run}")
    mapping: dict[str, str] = {}
    objects: dict[str, bytes] = {}
    boundary: set[str] = set()
    stack: list[tuple[str, bool]] = [(run, False)]
    links: dict[str, tuple[str, ...]] = {}
    while stack:
        oid, ready = stack.pop()
        if oid in mapping:
            continue
        if not repo.has(oid):
            mapping[oid] = oid
            boundary.add(oid)
            continue
        if not ready:
            envelope = repo.get(oid)
            links[oid] = validate_links(envelope)
            stack.append((oid, True))
            stack.extend((link, False) for link in links[oid] if link not in mapping)
            continue
        new = _derived(repo.get(oid), mapping)
        mapping[oid] = new.oid
        objects[new.oid] = new.encode()
    view = _View(objects, boundary)
    for oid in objects:
        validate_run_graph(view, view.get(oid))
    changed = sum(1 for old, new in mapping.items() if old != new)
    return mapping[run], objects, boundary, changed


def public_bundle(repo: Any, ref: str, run: str, key: Any, *, algorithm: str,
                  key_id: str | None = None, pack_format: str = "TINEPACK3") -> bytes:  # fmt: skip
    """A bundle holding only *run*'s redacted copy under *ref*, and its signed record."""
    from opentine import _bundle
    from opentine.repository import _pack5, _tombstones
    from opentine.repository._pack5 import V5

    public, objects, boundary, changed = derive(repo, run)
    pack = create_pack(_View(objects, boundary), sorted(objects))
    record = {
        "kind": KIND,
        "copy_version": 1,
        "source_run": run,
        "public_run": public,
        "ruleset": REDACTION_RULESET,
        "objects": len(objects),
        "redacted": changed,
        "pack": "",
    }
    extra: dict[str, Any] = {"tombstones": _tombstones.carried(repo, boundary)}
    if pack_format == V5:
        pack = _pack5.from_v3(pack, slim=True)
    record["pack"] = "sha256:" + hashlib.sha256(pack).hexdigest()
    extra["redacted_public"] = sign(record, key, algorithm=algorithm, key_id=key_id)
    return _bundle.assemble(pack, {ref: public}, extra)


__all__ = ["derive", "public_bundle"]
