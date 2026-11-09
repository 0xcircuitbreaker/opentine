"""Validate a Provenance Run Crate against the profile rules it claims (0.48).

A structural checker for the requirements of RO-Crate 1.1 and the Workflow Run
RO-Crate profiles 0.5 that a crate's metadata can show on its own: the JSON-LD
contexts, the descriptor and root ``conformsTo``, a ``ComputationalWorkflow``
main entity, a ``CreateAction`` per execution whose ``instrument`` is the
workflow, and, for the Provenance profile, an engine ``OrganizeAction`` whose
``ControlAction`` objects tie each ``HowToStep`` of the workflow to the
``CreateAction`` that ran it. Every ``{"@id": ...}`` reference must resolve
(except absolute URLs), and ``@id``s are unique. It returns the list of
problems; an empty list means valid. The upstream ``rocrate-validator`` is not
a dependency and is not run here.
"""

from __future__ import annotations

from typing import Any

from opentine._citation_export import RO_CRATE_CONTEXT, RO_CRATE_SPEC
from opentine._run_crate import PROFILES, WFRUN_CONTEXT


def _types(entity: dict[str, Any]) -> set[str]:
    kind = entity.get("@type", [])
    return {kind} if isinstance(kind, str) else set(kind)


def _ids(value: Any) -> list[str]:
    items = value if isinstance(value, list) else [value]
    return [i["@id"] for i in items if isinstance(i, dict) and isinstance(i.get("@id"), str)]


def _refs(node: Any) -> list[str]:
    """Every ``{"@id": ...}`` reference, walked iteratively (no recursion depth limit)."""
    found: list[str] = []
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if set(item) == {"@id"}:
                found.append(item["@id"])
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return found


def validate(crate: Any) -> list[str]:  # noqa: C901 - one rule per branch, read top to bottom
    if not isinstance(crate, dict) or not isinstance(crate.get("@graph"), list):
        return ["not an RO-Crate: no @graph"]
    problems: list[str] = []
    context = crate.get("@context")
    contexts = context if isinstance(context, list) else [context]
    for needed in (RO_CRATE_CONTEXT, WFRUN_CONTEXT):
        if needed not in contexts:
            problems.append(f"@context lacks {needed}")
    graph = [e for e in crate["@graph"] if isinstance(e, dict)]
    by_id: dict[str, dict[str, Any]] = {}
    for entity in graph:
        oid = entity.get("@id")
        if not isinstance(oid, str) or oid in by_id:
            problems.append(f"missing or duplicate @id: {oid!r}")
            continue
        by_id[oid] = entity
    for ref in _refs(crate["@graph"]):
        if ref not in by_id and not ref.startswith(("http://", "https://")):
            problems.append(f"dangling reference {ref}")
    descriptor = by_id.get("ro-crate-metadata.json", {})
    if RO_CRATE_SPEC not in _ids(descriptor.get("conformsTo")):
        problems.append("metadata descriptor does not conform to RO-Crate 1.1")
    root = by_id.get(next(iter(_ids(descriptor.get("about"))), ""), {})
    if "Dataset" not in _types(root):
        problems.append("root data entity is not a Dataset")
    for profile in PROFILES:
        if profile not in _ids(root.get("conformsTo")):
            problems.append(f"root does not declare conformsTo {profile}")
    main = next(iter(_ids(root.get("mainEntity"))), "")
    workflow = by_id.get(main, {})
    if not {"ComputationalWorkflow", "File", "SoftwareSourceCode"} <= _types(workflow):
        problems.append("mainEntity is not a File/SoftwareSourceCode/ComputationalWorkflow")
    if main not in _ids(root.get("hasPart")):
        problems.append("mainEntity is not in the root's hasPart")
    runs = [e for e in graph if "CreateAction" in _types(e) and main in _ids(e.get("instrument"))]
    if not runs:
        problems.append("no CreateAction has the workflow as instrument")
    for action in runs:
        if action["@id"] not in _ids(root.get("mentions")):
            problems.append(f"root does not mention the workflow run {action['@id']}")
    steps = set(_ids(workflow.get("step")))
    for sid in steps:
        if "HowToStep" not in _types(by_id.get(sid, {})) or "position" not in by_id.get(sid, {}):
            problems.append(f"{sid} is not a HowToStep with a position")
    organize = [e for e in graph if "OrganizeAction" in _types(e)]
    if not organize:
        problems.append("provenance: no OrganizeAction for the engine")
    for org in organize:
        engine = by_id.get(next(iter(_ids(org.get("instrument"))), ""), {})
        if "SoftwareApplication" not in _types(engine):
            problems.append("provenance: OrganizeAction instrument is not a SoftwareApplication")
        if not set(_ids(org.get("result"))) & {r["@id"] for r in runs}:
            problems.append("provenance: OrganizeAction result is not the workflow run")
        covered = set()
        for cid in _ids(org.get("object")):
            control = by_id.get(cid, {})
            step = next(iter(_ids(control.get("instrument"))), "")
            action = by_id.get(next(iter(_ids(control.get("object"))), ""), {})
            if "ControlAction" not in _types(control) or step not in steps:
                problems.append(f"provenance: {cid} does not control a workflow step")
            elif "CreateAction" not in _types(action):
                problems.append(f"provenance: {cid} object is not a CreateAction")
            covered.add(step)
        if steps - covered:
            problems.append(f"provenance: steps without a ControlAction: {sorted(steps - covered)}")
    return problems


__all__ = ["validate"]
