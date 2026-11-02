"""Format v4 files and v3 repositories: the same envelopes, the same oids (SPEC 9.10).

``export_v4`` builds a v4 file from a repository run's *stored* envelopes, so
its root is the repository oid byte for byte (``tine migrate --to v4 --repo``).
``install_v4`` is the converse (``tine import FILE.tine --repo``): it verifies
the file with the full v4 reader, then installs every envelope unchanged, adopts
the annotation chain, and keeps the ``tine-sig/3`` blocks in a sidecar
(``_sig_sidecar``), because they sign the root and annotation head rather than
being objects themselves. A file exported again carries the sidecar's blocks
whose annotation head still matches, so import then export is byte-identical.
"""

from __future__ import annotations

from typing import Any

from opentine._artifact_io import MAX_TINE_ARTIFACT_BYTES, parse_artifact_json
from opentine._artifact_v4 import _entry
from opentine._format_v4 import (
    ARTIFACT_V4_KIND,
    ARTIFACT_V4_VERSION,
    MAX_V4_ANNOTATIONS,
    MAX_V4_OBJECTS,
    V4Unrepresentable,
)
from opentine.kernel import ObjectEnvelope, canonical_json, parse_oid, validate_links
from opentine.repository._annotations import (
    _resolved_head,
    annotation_ref,
    validate_annotation_chain,
)
from opentine.repository._run_graph import validate_event_metrics, validate_run_graph
from opentine.repository._sig_sidecar import add_signatures, signatures_for


def _stored_closure(repo: Any, root: str) -> dict[str, ObjectEnvelope]:
    seen = {root: repo.get(root)}
    stack = [root]
    while stack:
        for link in validate_links(seen[stack.pop()]):
            if link not in seen:
                if len(seen) >= MAX_V4_OBJECTS:
                    raise V4Unrepresentable(
                        f"run has more than {MAX_V4_OBJECTS:,} objects, over the format v4 limit"
                    )
                seen[link] = repo.get(link)
                stack.append(link)
    return seen


def _stored_chain(repo: Any, root: str) -> list[ObjectEnvelope]:
    chain: list[ObjectEnvelope] = []
    # The ref, or (in a repository that received the run by bundle or fetch, where
    # no annotation ref moved) the newest associated annotation, as load_run reads.
    head = repo.read_ref(annotation_ref(root)) or _resolved_head(repo, root)[0]
    while head:
        if len(chain) >= MAX_V4_ANNOTATIONS:
            raise ValueError(f"run has more than {MAX_V4_ANNOTATIONS} annotations for format v4")
        envelope = repo.get(head)
        chain.append(envelope)
        head = envelope.payload().get("previous_id")
    return chain[::-1]


def repo_origin(repo: Any, root: Any, payload: dict[str, Any]) -> dict[str, Any] | None:
    """A repository run's stored envelopes, for ``write_v4`` to reuse (one root)."""
    try:
        if not isinstance(root, str) or repo.get(root).payload() != payload:
            return None
        objects, chain = _stored_closure(repo, root), _stored_chain(repo, root)
    except (KeyError, OSError, ValueError):
        return None
    return {"annotations": chain, "objects": objects, "payload": payload, "root": root}


def export_v4(repo: Any, root: str) -> bytes:
    """The v4 artifact of repository run *root*, whose root is *root* itself."""
    from opentine._artifact_v4_read import read_v4_data

    if parse_oid(root)[0] != "run":
        raise ValueError(f"not a run oid: {root}")
    objects = _stored_closure(repo, root)
    chain = _stored_chain(repo, root)
    head = chain[-1].oid if chain else None
    document = {
        "annotations": [{"id": e.oid, **_entry(e)} for e in chain],
        "format_version": ARTIFACT_V4_VERSION,
        "kind": ARTIFACT_V4_KIND,
        "objects": {oid: _entry(objects[oid]) for oid in sorted(objects)},
        "root": root,
        "signatures": signatures_for(repo, root, head),
    }
    encoded = canonical_json(document)
    if len(encoded) > MAX_TINE_ARTIFACT_BYTES:
        raise ValueError(f"format v4 artifact would exceed {MAX_TINE_ARTIFACT_BYTES} bytes")
    read_v4_data(parse_artifact_json(encoded))  # never hand out what the reader refuses
    return encoded


def _post_order(objects: dict[str, ObjectEnvelope], root: str) -> list[ObjectEnvelope]:
    """Links before linkers, walked with an explicit stack (content addressing: no cycles)."""
    order: list[ObjectEnvelope] = []
    done: set[str] = set()
    stack = [(root, False)]
    while stack:
        oid, expanded = stack.pop()
        if oid in done:
            continue
        if expanded:
            done.add(oid)
            order.append(objects[oid])
            continue
        stack.append((oid, True))
        stack.extend((link, False) for link in validate_links(objects[oid]) if link not in done)
    return order


def _install(repo: Any, envelope: ObjectEnvelope) -> bool:
    if repo.has(envelope.oid):
        return False
    validate_links(envelope, repo._link_exists)
    validate_annotation_chain(repo, envelope)
    validate_event_metrics(envelope)
    validate_run_graph(repo, envelope)
    repo._store_envelope(envelope)  # the file's own bytes: the oid cannot move
    return True


def _adopt_chain(repo: Any, root: str, chain: list[ObjectEnvelope]) -> str:
    """Install the file's annotation chain when it equals or extends the repository's."""
    if not chain:
        return "none"
    name = annotation_ref(root)
    current = repo.read_ref(name)
    oids = [envelope.oid for envelope in chain]
    if current == oids[-1]:
        return "unchanged"
    if current is not None and current not in oids:
        return "kept-repository"  # diverged: the repository's tags and metadata win
    for envelope in chain:
        _install(repo, envelope)
    repo.update_ref(name, oids[-1], expected_old=current)
    return "installed"


def install_v4(repo: Any, data: dict[str, Any], *, ref: str | None = None) -> dict[str, Any]:
    """Install a parsed v4 artifact into *repo* unchanged; returns a summary."""
    from opentine._artifact_v4_read import read_v4_data

    origin = read_v4_data(data)._v4_origin  # every oid re-derived, every rule checked
    root = origin["root"]
    written = sum(_install(repo, e) for e in _post_order(origin["objects"], root))
    annotations = _adopt_chain(repo, root, origin["annotations"])
    head = origin["annotations"][-1].oid if origin["annotations"] else None
    signatures = add_signatures(repo, root, head, data["signatures"])
    if ref:
        repo.update_ref(ref, root, expected_old=repo.read_ref(ref))
    return {
        "annotations": annotations,
        "objects": len(origin["objects"]),
        "objects_written": written,
        "ref": ref,
        "root": root,
        "signatures": signatures,
    }


__all__ = ["export_v4", "install_v4"]
