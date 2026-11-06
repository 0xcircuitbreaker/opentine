"""Reading format v4 ``.tine`` artifacts (SPEC Part 9).

Every envelope's oid is re-derived from its bytes, the root must be a run the
artifact carries, every object must be reachable from it, and the run is then
loaded through the v3 reader with all of its validators. Any mismatch refuses.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from opentine import _codec
from opentine._artifact_io import MAX_TINE_ARTIFACT_BYTES, parse_artifact_json
from opentine._artifact_v4 import _PROVENANCE, _BundleRepo, _closure, _envelope
from opentine._format_v4 import (
    ARTIFACT_V4_KIND,
    MAX_V4_ANNOTATIONS,
    MAX_V4_OBJECTS,
    V4_KEYS,
    is_v4_artifact,
)
from opentine._provenance_v4 import require_upgraded_from
from opentine._signing_v4 import MAX_V4_SIGNATURES, SCHEME_V3
from opentine._tine_v5 import as_v4
from opentine.kernel import ObjectEnvelope, parse_oid
from opentine.repository._annotations import annotation_ref
from opentine.repository._refs import normalize_ref

_BUNDLED = frozenset({"blob", "event", "run"})


def _check_document(data: Any) -> None:
    if not is_v4_artifact(data):
        raise ValueError(f"not a format v4 artifact (kind {ARTIFACT_V4_KIND!r})")
    if set(data) != V4_KEYS:
        raise ValueError(f"v4 artifact keys must be exactly {sorted(V4_KEYS)}")
    if not isinstance(data["objects"], dict) or len(data["objects"]) > MAX_V4_OBJECTS:
        raise ValueError(f"v4 objects must be a map of at most {MAX_V4_OBJECTS} envelopes")
    annotations = data["annotations"]
    if not isinstance(annotations, list) or len(annotations) > MAX_V4_ANNOTATIONS:
        raise ValueError(f"v4 annotations must be a list of at most {MAX_V4_ANNOTATIONS}")
    signatures = data["signatures"]
    if not isinstance(signatures, list) or len(signatures) > MAX_V4_SIGNATURES:
        raise ValueError(f"v4 signatures must be a list of at most {MAX_V4_SIGNATURES}")
    if any(not isinstance(b, dict) or b.get("scheme") != SCHEME_V3 for b in signatures):
        raise ValueError(f"every v4 signature must be a {SCHEME_V3} block")


def read_v4_data(data: Any) -> Any:
    """Load a parsed v4 artifact, refusing any envelope or root that fails to verify."""
    from opentine.repository.runs import load_run

    data = as_v4(data)  # SPEC Part 10: v5 text blobs re-spelled as v4 base64
    _check_document(data)
    root = data["root"]
    objects: dict[str, ObjectEnvelope] = {}
    for oid, entry in data["objects"].items():
        if parse_oid(oid)[0] not in _BUNDLED:
            raise ValueError(f"v4 objects hold only blob, event and run envelopes: {oid}")
        objects[oid] = _envelope(entry, oid, f"objects[{oid}]")
    if not isinstance(root, str) or parse_oid(root)[0] != "run" or root not in objects:
        raise ValueError("v4 root must name a run envelope the artifact carries")
    if len(_closure(objects, root)) != len(objects):
        raise ValueError("v4 artifact carries objects its root does not reach")
    if "upgraded_from" in objects[root].payload():
        require_upgraded_from(objects[root].payload()["upgraded_from"])
    repo = _BundleRepo()
    repo.objects.update(objects)
    chain: list[ObjectEnvelope] = []
    for index, entry in enumerate(data["annotations"]):
        where = f"annotations[{index}]"
        body = {k: v for k, v in entry.items() if k != "id"} if isinstance(entry, dict) else None
        envelope = _envelope(body, entry.get("id") if body is not None else None, where)
        payload = envelope.payload()
        previous = chain[-1].oid if chain else None
        if envelope.object_type != "annotation" or payload.get("target_id") != root:
            raise ValueError(f"{where}: must be an annotation of the root run")
        if payload.get("previous_id") != previous:
            raise ValueError(f"{where}: annotations must form one chain, oldest first")
        repo.objects[envelope.oid] = envelope
        chain.append(envelope)
    if chain:
        repo.refs[normalize_ref(annotation_ref(root))] = chain[-1].oid
    run = load_run(repo, root)
    _restore_step_ids(run, objects)
    for name in _PROVENANCE:
        run.__dict__.pop(name, None)
    run._v4_origin = {
        "annotations": chain,
        "objects": objects,
        "payload": objects[root].payload(),
        "root": root,
    }
    return run


def _restore_step_ids(run: Any, objects: dict[str, ObjectEnvelope]) -> None:
    """Give each step back the id it had before it was written (``legacy_step_id``).

    The writer records every step's own id in its event, so a run saved as v4 and
    read back keeps the ids its refs, transcript and pricing manifest name, and
    re-writing it re-derives byte-identical events. Events without one (a run
    recorded straight into a repository) keep their event oids, as ``load_run``.
    """
    names: dict[str, str] = {}
    for oid in run.graph.order:
        legacy = objects[oid].payload().get("legacy_step_id")
        if not isinstance(legacy, str) or not legacy or legacy.startswith("event:"):
            return
        names[oid] = legacy
    if len(set(names.values())) != len(names):
        return
    from opentine._graph_types import Graph

    graph = Graph()
    for oid in list(run.graph.order):
        step = run.graph.steps[oid]
        parents = [names.get(item, item) for item in step.parent_ids]
        causal_ids = [names.get(item, item) for item in step.causal_ids]
        graph.add(replace(step, id=names[oid], parent_ids=parents, causal_ids=causal_ids))
    run.graph = graph
    run.refs = {key: names.get(value, value) for key, value in run.refs.items()}
    # 0.33: the transcript names steps too; left as event oids, a fork's causal
    # slice found none of them and dropped every scoped turn.
    run.transcript = [_renamed_turn(item, names) for item in run.transcript]
    causal = getattr(run, "_v3_causal_ids", {})
    run._v3_causal_ids = {names.get(k, k): [names.get(c, c) for c in v] for k, v in causal.items()}


def _renamed_turn(item: Any, names: dict[str, str]) -> Any:
    if isinstance(item, dict) and item.get("step_id") in names:
        return {**item, "step_id": names[item["step_id"]]}
    return item


def read_v4(raw: bytes) -> Any:
    """Load a v4 artifact from its bytes, TINEZ1-compressed or plain."""
    return read_v4_data(parse_artifact_json(_codec.unwrap(raw, limit=MAX_TINE_ARTIFACT_BYTES)))


def verify_v4(data: dict[str, Any]) -> Any:
    """v4 integrity: every envelope oid re-derives and the root reaches them all."""
    from opentine._graph_types import IntegrityResult

    root = data.get("root") if isinstance(data.get("root"), str) else None
    try:
        data = as_v4(data)
        read_v4_data(data)
    except (KeyError, RecursionError, TypeError, ValueError) as exc:
        return IntegrityResult(False, "sha256", root, None, f"invalid v4 artifact: {exc}")
    return IntegrityResult(True, "sha256", root, root, "ok")
