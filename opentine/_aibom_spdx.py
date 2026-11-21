"""The SPDX 3.0.1 AI and Dataset profile rendering of a lineage node (0.78).

One JSON-LD ``@graph`` (:mod:`opentine._aibom`): every variant of the ancestry
is an ``ai_AIPackage`` (eval pass rates in ``ai_metric``), every dataset
version a ``dataset_DatasetPackage`` whose ``dataset_dataPreprocessing``
records the taint filter. Relationships: a parent is ``ancestorOf`` its child;
a variant was ``trainedOn`` its training datasets and ``testedOn`` the datasets
its evals scored; ``hasDeclaredLicense`` links a licence expression. Signers
and eval details are ``Annotation`` statements. Every ``spdxId`` is a
``urn:opentine:`` IRI derived from digests, so the bytes depend on the inputs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from opentine._aibom import used_by
from opentine._version import __version__

CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
CI = "_:creationinfo"
TOOL = "urn:opentine:agent:opentine"


def _compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _id(kind: str, *parts: str) -> str:
    tail = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
    return f"urn:opentine:{kind}:{tail}"


def _el(kind: str, spdx_id: str, **fields: Any) -> dict[str, Any]:
    return {"type": kind, "spdxId": spdx_id, "creationInfo": CI, **fields}


def _hash(digest: str) -> dict[str, str]:
    return {"type": "Hash", "algorithm": "sha256", "hashValue": digest[7:]}


def _ds_id(d: dict[str, Any]) -> str:
    return f"urn:opentine:dataset:{d['role']}:{d['dataset'][7:]}"


def _var_id(variant: str) -> str:
    return f"urn:opentine:variant:{variant[7:]}"


def _rel(kind: str, src: str, to: list[str]) -> dict[str, Any]:
    return _el("Relationship", _id("relationship", kind, src, *to), **{
        "from": src, "to": to, "relationshipType": kind})  # fmt: skip


def _note(subject: str, statement: dict[str, Any]) -> dict[str, Any]:
    text = _compact(statement)
    return _el("Annotation", _id("annotation", subject, text), annotationType="other",
               subject=subject, statement=text)  # fmt: skip


def _package(node: dict[str, Any], name: str) -> dict[str, Any]:
    metrics = [{"type": "DictionaryEntry", "key": f"{ev['scorer']}:{ev['dataset']}",
                "value": f"{ev['passed']}/{ev['items']}"} for ev in node["evals"]]  # fmt: skip
    out = _el("ai_AIPackage", _var_id(node["variant"]), name=name,
              software_packageVersion=node["variant"],
              verifiedUsing=[_hash(d) for d in sorted(set(node["artifacts"].values()))],
              software_primaryPurpose="model")  # fmt: skip
    if node["signed_at"]:
        out["releaseTime"] = node["signed_at"]
    if metrics:
        out["ai_metric"] = metrics
    return out


def _dataset(d: dict[str, Any]) -> dict[str, Any]:
    if d["taint_filter"] is None:
        steps = ["opentine:taint-filter none recorded"]
    else:
        steps = [f"opentine:taint-filter sha256:{d['taint_filter_sha256']} "
                 + _compact(d["taint_filter"])]  # fmt: skip
    out = _el("dataset_DatasetPackage", _ds_id(d), name=d["name"],
              software_packageVersion=d["dataset"], verifiedUsing=[_hash(d["dataset"])],
              software_primaryPurpose="data", dataset_datasetType=["other"],
              dataset_dataPreprocessing=steps)  # fmt: skip
    if d["signed_at"]:
        out["releaseTime"] = d["signed_at"]
    return out


def _licence(subject: str, expr: str | None) -> list[dict[str, Any]]:
    if not expr:
        return []
    lid = _id("licence", expr)
    return [_el("simplelicensing_LicenseExpression", lid, simplelicensing_licenseExpression=expr),
            _rel("hasDeclaredLicense", subject, [lid])]  # fmt: skip


def document(model: dict[str, Any]) -> dict[str, Any]:
    nodes, datasets = model["nodes"], model["datasets"]
    head = nodes[0]
    created = head["signed_at"] or "1970-01-01T00:00:00Z"
    graph: list[dict[str, Any]] = [
        {"type": "CreationInfo", "@id": CI, "specVersion": "3.0.1", "created": created,
         "createdBy": [TOOL], "comment": f"opentine {__version__} tine bom export"},
        {"type": "SoftwareAgent", "spdxId": TOOL, "creationInfo": CI, "name": "opentine"},
    ]  # fmt: skip
    for i, node in enumerate(nodes):
        vid = _var_id(node["variant"])
        graph.append(_package(node, model["name"] if i == 0 else
                              f"variant-{node['variant'][7:19]}"))  # fmt: skip
        if node["parents"]:
            graph += [_rel("ancestorOf", _var_id(p), [vid]) for p in node["parents"]]
        used = used_by(node, datasets, head=i == 0)
        trained = [_ds_id(d) for d in used if d["role"] == "training"]
        tested = [_ds_id(d) for d in used if d["role"] == "eval"]
        if trained:
            graph.append(_rel("trainedOn", vid, trained))
        if tested:
            graph.append(_rel("testedOn", vid, tested))
        graph.append(
            _note(
                vid,
                {
                    "opentine": "lineage-record",
                    "signer": node["signer"],
                    "mutation_run": node["mutation_run"],
                    "artifacts": node["artifacts"],
                    "selector": node["selector"],
                    "loop": node["loop"],
                    "policy": node["policy"],
                    "decision": node["decision"],
                    "evals": node["evals"],
                },
            )
        )
    graph += _licence(_var_id(head["variant"]), model["licence"])
    for d in datasets:
        graph.append(_dataset(d))
        graph.append(_note(_ds_id(d), {"opentine": "dataset-version", "role": d["role"],
                                       "convention": d["convention"], "signer": d["signer"],
                                       "record_sha256": d["record_sha256"]}))  # fmt: skip
        graph += _licence(_ds_id(d), d["licence"])
    unique: dict[str, dict[str, Any]] = {}  # one licence element however many declare it
    for element in graph:
        unique.setdefault(element.get("spdxId") or element["@id"], element)
    graph = list(unique.values())
    root = _var_id(head["variant"])
    graph.append(_el("SpdxDocument", _id("document", root, _compact(graph)),
                     name=f"AI-BOM {model['name']}", rootElement=[root],
                     element=sorted({e["spdxId"] for e in graph if "spdxId" in e}),
                     profileConformance=["core", "software", "ai", "dataset",
                                         "simpleLicensing"]))  # fmt: skip
    return {"@context": CONTEXT, "@graph": graph}


__all__ = ["CONTEXT", "document"]
