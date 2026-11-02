"""Format v4 ``.tine`` artifacts: one JCS object bundling a run's v3 envelopes.

``write_v4`` converts a run with the v3 writer itself (``repository.runs``) into
an in-memory store, so every envelope, oid and redaction is byte-for-byte what
``Repo.put_run`` would store: the artifact's ``root`` *is* the run's v3 oid.
``read_v4`` re-derives every oid, requires every object to be reachable from the
root, and loads the run through the v3 reader with all of its validators.
Nothing here rewrites an original: a v2 run becomes v4 only when it is written.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
from typing import Any

from opentine._artifact_io import (
    MAX_TINE_ARTIFACT_BYTES,
    _structural_token_budget,
)
from opentine._format_v4 import (
    ARTIFACT_V4_KIND,
    ARTIFACT_V4_VERSION,
    MAX_V4_OBJECTS,
    V4Unrepresentable,
)
from opentine._v3_guards import guarded_redaction
from opentine._v4_values import prepare_run
from opentine.kernel import (
    KernelError,
    ObjectEnvelope,
    _parse_int,
    canonical_json,
    validate_json_shape,
    validate_links,
)
from opentine.policies import run_redaction
from opentine.redaction import redact_blob
from opentine.repository._annotations import annotation_ref, validate_annotation_chain
from opentine.repository._migration_preflight import _MemoryRepo
from opentine.repository._refs import normalize_ref
from opentine.repository._run_graph import validate_event_metrics, validate_run_graph

#: The compatibility-Run attributes that tie a run to one v3 store.
_PROVENANCE = ("_v3_run_id", "_v3_payload", "_v3_fork_base", "_v3_source_run_id")
_PROVENANCE += ("_v3_source_payload", "_v3_repo")
_HEADER = ("encoding", "schema", "type")


class _BundleRepo(_MemoryRepo):
    """A memory store whose writes redact exactly as ``Repo.put`` does."""

    def put(self, object_type: str, payload: Any, schema: int = 1, *, redact: bool = True) -> str:
        if redact and object_type == "blob":
            stored = redact_blob(payload)
        else:
            stored = guarded_redaction(payload, where=f"v3 {object_type!r}", redact=redact)
        envelope = ObjectEnvelope.create(object_type, stored, schema)
        validate_links(envelope, self.has)
        validate_annotation_chain(self, envelope)
        validate_event_metrics(envelope)
        validate_run_graph(self, envelope)
        if envelope.oid not in self.objects and len(self.objects) >= MAX_V4_OBJECTS:
            raise V4Unrepresentable(
                f"run has more than {MAX_V4_OBJECTS:,} objects, over the format v4 limit"
            )
        self.objects[envelope.oid] = envelope
        return envelope.oid


def _entry(envelope: ObjectEnvelope) -> dict[str, Any]:
    head: dict[str, Any] = {"encoding": envelope.encoding, "schema": envelope.schema}
    head["type"] = envelope.object_type
    if envelope.encoding == "raw":
        return {**head, "data": base64.b64encode(envelope.body).decode("ascii")}
    return {**head, "body": envelope.payload()}


def _envelope(entry: Any, oid: Any, where: str) -> ObjectEnvelope:
    """Rebuild one stored envelope from its v4 spelling and check its oid."""
    if not isinstance(entry, dict) or not isinstance(oid, str):
        raise ValueError(f"{where}: malformed v4 envelope")
    raw = entry.get("encoding") == "raw"
    if set(entry) != {*_HEADER, "data" if raw else "body"}:
        raise ValueError(f"{where}: a v4 envelope is encoding, schema, type and data|body")
    try:
        if raw:
            data = entry["data"]
            body = base64.b64decode(data.encode("ascii"), validate=True)
            if base64.b64encode(body).decode("ascii") != data:
                raise ValueError("blob data is not canonical base64")
        else:
            # The bounded reader parsed wide literals as ints; a v4 writer never
            # emits one, so each is a float's spelling (kernel._parse_int).
            text = json.dumps(entry["body"], allow_nan=False)
            body = canonical_json(json.loads(text, parse_int=_parse_int))
        header = canonical_json({name: entry[name] for name in _HEADER})
        return ObjectEnvelope.decode(header + b"\n" + body, oid)
    except (AttributeError, binascii.Error, RecursionError, UnicodeError, ValueError) as exc:
        raise ValueError(f"{where}: {exc}") from exc


def _closure(objects: dict[str, ObjectEnvelope], root: str) -> dict[str, ObjectEnvelope]:
    """Every object the root reaches, walked with an explicit stack."""
    seen = {root: objects[root]}
    stack = [root]
    while stack:
        for link in validate_links(seen[stack.pop()]):
            if link in seen:
                continue
            if link not in objects:
                raise ValueError(f"v4 artifact is missing linked object {link}")
            seen[link] = objects[link]
            stack.append(link)
    return seen


def _annotation_chain(repo: _BundleRepo, root: str) -> list[ObjectEnvelope]:
    chain: list[ObjectEnvelope] = []
    head = repo.refs.get(normalize_ref(annotation_ref(root)))
    while head:
        envelope = repo.objects[head]
        chain.append(envelope)
        head = envelope.payload().get("previous_id")
    return chain[::-1]


_FORK = ("_v3_fork_base", "_v3_source_run_id", "_v3_source_payload")


def _fork_source(run: Any, view: Any, repo: _BundleRepo) -> tuple[str, ...]:
    """A fork of a repository run or a v4 file: load its source's envelopes, so
    the fork reuses every unchanged event (and its root equals ``put_run``'s)."""
    from opentine._artifact_v4_repo import repo_origin

    source = view.__dict__.pop("_v4_source", None)
    if isinstance(source, dict) and getattr(run, "_v3_fork_base", None) is None:
        from opentine._graph_analysis import fork_base

        view._v3_fork_base = fork_base(source["payload"])
        view._v3_source_run_id, view._v3_source_payload = source["root"], source["payload"]
        repo.objects.update(source["objects"])
        return _FORK
    if getattr(run, "_v3_fork_base", None) is None or getattr(run, "_v3_repo", None) is None:
        return ()
    source_id, payload = run._v3_source_run_id, getattr(run, "_v3_source_payload", None)
    found = repo_origin(run._v3_repo, source_id, payload) if isinstance(payload, dict) else None
    if found is None:
        return ()
    repo.objects.update(found["objects"])
    return _FORK


def _writable_view(run: Any, repo: _BundleRepo) -> Any:
    """A shallow copy the v3 writer can convert into an empty memory store."""
    view = copy.copy(run)
    if isinstance(run.metadata, dict):
        view.metadata = {k: v for k, v in run.metadata.items() if k != "integrity"}
    origin = getattr(run, "_v4_origin", None)
    stored = getattr(run, "_v3_payload", None)  # a repository run keeps its upgraded_from
    if isinstance(stored, dict) and "upgraded_from" in stored:
        view.__dict__.setdefault("_v4_upgraded_from", stored["upgraded_from"])
    source = getattr(run, "_v3_repo", None)
    if origin is None and source is not None and isinstance(stored, dict):
        from opentine._artifact_v4_repo import repo_origin  # loaded from a repository:

        origin = repo_origin(source, getattr(run, "_v3_run_id", None), stored)  # same root
    kept = _fork_source(run, view, repo) if origin is None else ()
    for name in _PROVENANCE:
        if name not in kept:
            view.__dict__.pop(name, None)
    if isinstance(origin, dict):  # read from v4: reuse its envelopes, re-address nothing
        repo.objects.update(origin["objects"])
        for envelope in origin["annotations"]:
            repo.objects[envelope.oid] = envelope
        if origin["annotations"]:
            name = normalize_ref(annotation_ref(origin["root"]))
            repo.refs[name] = origin["annotations"][-1].oid
        view._v3_run_id, view._v3_payload = origin["root"], dict(origin["payload"])
    return view


def write_v4(run: Any) -> bytes:
    """The v4 artifact bytes for *run*: canonical JSON (RFC 8785) throughout."""
    from opentine.repository.runs import _put_run

    prepare_run(run, "run")  # a recorder's run is softened; any other is refused
    repo = _BundleRepo()
    view = _writable_view(run, repo)
    try:
        with run_redaction(run.policies):  # RedactionPolicy.extra_secret_keys, every object
            root = _put_run(repo, view).run_id
    except ValueError as exc:  # the v2 writer's wording for the same refusal
        if "nesting" not in str(exc):
            raise
        raise ValueError(f"run nesting or structure exceeds what v4 can hold: {exc}") from exc
    objects = _closure(repo.objects, root)
    document: dict[str, Any] = {
        "annotations": [{"id": e.oid, **_entry(e)} for e in _annotation_chain(repo, root)],
        "format_version": ARTIFACT_V4_VERSION,
        "kind": ARTIFACT_V4_KIND,
        "objects": {oid: _entry(objects[oid]) for oid in sorted(objects)},
        "root": root,
        "signatures": [],
    }
    encoded = canonical_json(document)
    if len(encoded) > MAX_TINE_ARTIFACT_BYTES:
        raise ValueError(
            f"format v4 artifact would exceed the {MAX_TINE_ARTIFACT_BYTES}-byte limit "
            "every reader enforces; save the run into a v3 repository instead"
        )
    try:  # never persist what the reader below would refuse
        validate_json_shape(encoded, max_tokens=_structural_token_budget(len(encoded)))
    except KernelError as exc:
        raise ValueError("run nesting or structure exceeds what a v4 artifact can hold") from exc
    return encoded


def save_v4(run: Any, target: Any, *, fsync: bool = False, sign_key: Any = None, **sign: Any):
    """``Run.save`` (the 0.26 default writer): TINEZ1-wrapped exactly like v2.

    With *sign_key*, one ``tine-sig/3`` block is appended (``sign`` carries
    ``algorithm``, ``key_id``, ``signer`` and ``signed_at``).
    """
    from opentine._codec_io import write_artifact

    encoded = write_v4(run)
    if sign_key is not None:
        from opentine._signing_v4 import append_signature

        encoded = append_signature(json.loads(encoded), sign_key, **sign)
    write_artifact(target, encoded.decode("utf-8"), fsync=fsync)
    return target


def __getattr__(name: str) -> Any:
    """Re-export the reader lazily: ``_artifact_v4_read`` imports this module."""
    if name in ("read_v4", "read_v4_data"):
        from opentine import _artifact_v4_read

        return getattr(_artifact_v4_read, name)
    raise AttributeError(name)


__all__ = ["save_v4", "write_v4"]  # read_v4, read_v4_data: lazily, above
