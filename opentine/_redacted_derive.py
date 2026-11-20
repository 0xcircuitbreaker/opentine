"""Deriving a run's redacted public copy and its pack (0.46, SPEC 4.15).

:func:`derive` walks the run's object graph only (never its annotations or
attestations, which stay private) and rebuilds it bottom-up in memory:

* a plain blob is re-redacted with the current ruleset until it is stable;
* a tree blob (schema 2) keeps its entries, its links rewritten;
* every JSON payload (event, run) is redacted again, then each oid it names is
  rewritten to the oid of the object derived from it;
* after the credential ruleset, the publication ruleset (:mod:`opentine._redact_publish`:
  home paths, email addresses, the local login in actor fields) runs on blobs
  and payloads alike, and the record names ``opentine-redaction/2+publish/1``.

A blob the repository does not hold (purged, or cut by a shallow fetch) keeps
its oid and stays a boundary of the pack, with its tombstone carried beside it.
Nothing is written to the repository. :func:`public_bundle` packs the derived
objects, signs the ``opentine.redacted-copy`` record over the pack digest with
the caller's key, and writes an ordinary bundle whose one ref names the copy.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any

from opentine import _redact_publish
from opentine._redact_publish import PUBLISH_RULESET
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


def _derived(
    envelope: ObjectEnvelope, mapping: dict[str, str], login: str | None, counts: Counter[str]
) -> ObjectEnvelope:
    if envelope.encoding == "raw" and envelope.schema != TREE_SCHEMA:
        body, found = _redact_publish.scrub_bytes(_stable(envelope.body), login=login)
        counts.update(found)
        return ObjectEnvelope.create("blob", body, envelope.schema)
    if envelope.encoding == "raw":  # a tree: its entries are links
        import json

        from opentine._tree import encode_tree
        from opentine.kernel import _parse_int

        tree = _rewrite(json.loads(envelope.body, parse_int=_parse_int), mapping)
        for row in tree.get("entries", []) + tree.get("omitted", []):  # names can hold emails
            row["name"], found = _redact_publish.scrub_text(row["name"], login=login)
            counts.update(found)
        body = encode_tree(tree["entries"], tree.get("omitted", []))  # re-sorted; refuses clashes
        return ObjectEnvelope.create("blob", body, envelope.schema)
    where = f"redacted copy {envelope.object_type!r}"
    payload, found = _redact_publish.scrub_value(
        guarded_redaction(envelope.payload(), where=where), login=login
    )
    counts.update(found)
    payload = _rewrite(payload, mapping)
    return ObjectEnvelope.create(envelope.object_type, payload, envelope.schema)


def _count(counts: dict[str, dict[str, int]], oid: str, found: Counter[str]) -> None:
    """Record *found* for *oid* once: equal sources derive one object, counted once."""
    if found and oid not in counts:
        counts[oid] = dict(found)


def derive(
    repo: Any, run: str, counts: dict[str, dict[str, int]] | None = None
) -> tuple[str, dict[str, bytes], set[str], int]:
    """``(public run, derived objects, boundary oids, objects changed)`` for *run*.

    *counts*, when given, is filled with ``{derived oid: {kind: n}}`` for each
    object the publication ruleset changed (kinds ``path``, ``email``, ``user``).
    """
    login = _redact_publish.login()
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
        found: Counter[str] = Counter()
        new = _derived(repo.get(oid), mapping, login, found)
        mapping[oid] = new.oid
        if counts is not None:
            _count(counts, new.oid, found)
        objects[new.oid] = new.encode()
    view = _View(objects, boundary)
    for oid in objects:
        validate_run_graph(view, view.get(oid))
    changed = sum(1 for old, new in mapping.items() if old != new)
    return mapping[run], objects, boundary, changed


def public_bundle(repo: Any, ref: str, run: str, key: Any, *, algorithm: str,
                  key_id: str | None = None, pack_format: str = "TINEPACK3",
                  counts: dict[str, dict[str, int]] | None = None) -> bytes:  # fmt: skip
    """A bundle holding only *run*'s redacted copy under *ref*, and its signed record."""
    from opentine import _bundle
    from opentine.repository import _pack5, _tombstones
    from opentine.repository._pack5 import V5

    public, objects, boundary, changed = derive(repo, run, counts)
    pack = create_pack(_View(objects, boundary), sorted(objects))
    record = {
        "kind": KIND,
        "copy_version": 1,
        "source_run": run,
        "public_run": public,
        "ruleset": PUBLISH_RULESET,
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
