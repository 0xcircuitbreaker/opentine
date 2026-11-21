"""The CycloneDX 1.6 ML-BOM rendering of a lineage node (0.78, :mod:`opentine._aibom`).

The exported variant is ``metadata.component`` (type ``machine-learning-model``);
its ancestors are further model components and every dataset version is a
``data`` component. ``dependencies`` carry the lineage (a variant depends on
its parents) and the datasets it was trained or evaluated on. Eval results go
in ``modelCard.quantitativeAnalysis``; signers, runs, taint filters and other
OpenTine facts are ``opentine:``-prefixed properties. ``serialNumber`` is a
UUID over the rest of the document, so the bytes depend on the inputs only.
"""

from __future__ import annotations

import json
from typing import Any

from opentine._aibom import digest_uuid, render, used_by
from opentine._version import __version__

SPEC = "1.6"


def _props(pairs: list[tuple[str, Any]]) -> list[dict[str, str]]:
    out = []
    for name, value in pairs:
        if value is None or value == "":
            continue
        text = value if isinstance(value, str) else json.dumps(value, sort_keys=True,
                                                               separators=(",", ":"))  # fmt: skip
        out.append({"name": f"opentine:{name}", "value": text})
    return out


def _hashes(digests: list[str]) -> list[dict[str, str]]:
    return [{"alg": "SHA-256", "content": d[7:]} for d in sorted(set(digests))]


def _dataset_ref(d: dict[str, Any]) -> str:
    return f"dataset:{d['role']}:{d['dataset']}"


def _model(node: dict[str, Any], name: str, licence: str | None,
           used: list[dict[str, Any]]) -> dict[str, Any]:  # fmt: skip
    refs = [{"ref": _dataset_ref(d)} for d in used]
    metrics = [{"type": f"pass-rate:{ev['scorer']}", "value": f"{ev['passed']}/{ev['items']}",
                "slice": ev["dataset"]} for ev in node["evals"]]  # fmt: skip
    pairs: list[tuple[str, Any]] = [
        (f"artifact:{k}", v) for k, v in node["artifacts"].items()
    ] + [("mutation-run", node["mutation_run"]), ("record-signer", node["signer"]),
         ("record-signed-at", node["signed_at"]), ("selector", node["selector"]),
         ("loop", node["loop"]), ("promotion-policy", node["policy"]),
         ("promotion-decision", node["decision"])]  # fmt: skip
    for ev in node["evals"]:
        pairs.append(("eval", {k: ev[k] for k in ("eval", "dataset", "scorer", "scorer_version",
                                                   "threshold", "items", "passed", "signers",
                                                   "verdicts_sha256")}))  # fmt: skip
    out: dict[str, Any] = {
        "type": "machine-learning-model", "bom-ref": node["variant"], "name": name,
        "version": node["variant"], "hashes": _hashes(list(node["artifacts"].values())),
        "properties": _props(pairs),
    }  # fmt: skip
    card: dict[str, Any] = {}
    if refs:
        card["modelParameters"] = {"datasets": refs}
    if metrics:
        card["quantitativeAnalysis"] = {"performanceMetrics": metrics}
    if card:
        out["modelCard"] = card
    if licence:
        out["licenses"] = [{"expression": licence}]
    return out


def _data(d: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "type": "data", "bom-ref": _dataset_ref(d), "name": d["name"], "version": d["dataset"],
        "hashes": _hashes([d["dataset"]]),
        "data": [{"type": "dataset", "name": d["name"]}],
        "properties": _props([
            ("dataset-role", d["role"]), ("dataset-convention", d["convention"]),
            ("dataset-record-sha256", d["record_sha256"]), ("dataset-signer", d["signer"]),
            ("dataset-signed-at", d["signed_at"]), ("taint-filter", d["taint_filter"]),
            ("taint-filter-sha256", d["taint_filter_sha256"]),
            ("taint-filter-recorded", "true" if d["taint_filter"] is not None else "false")]),
    }  # fmt: skip
    if d["licence"]:
        out["licenses"] = [{"expression": d["licence"]}]
    return out


def document(model: dict[str, Any]) -> dict[str, Any]:
    datasets = model["datasets"]
    nodes = model["nodes"]
    head, *ancestors = nodes
    components = [_model(n, f"variant-{n['variant'][7:19]}", None,
                         used_by(n, datasets, head=False)) for n in ancestors]  # fmt: skip
    components += [_data(d) for d in datasets]
    deps = []
    for node in nodes:
        used = used_by(node, datasets, head=node is head)
        on = list(node["parents"]) + [_dataset_ref(d) for d in used]
        deps.append({"ref": node["variant"], "dependsOn": on})
    deps += [{"ref": _dataset_ref(d), "dependsOn": []} for d in datasets]
    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX", "specVersion": SPEC, "version": 1,
        "metadata": {
            "timestamp": head["signed_at"],
            "tools": {"components": [{"type": "application", "name": "opentine",
                                      "version": __version__}]},  # fmt: skip
            "component": _model(head, model["name"], model["licence"],
                                used_by(head, datasets, head=True)),
            "properties": _props([("lineage-check", "ok"),
                                  ("eval-signers", model["signers"])]),  # fmt: skip
        },
        "components": components,
        "dependencies": deps,
    }  # fmt: skip
    if not doc["metadata"]["timestamp"]:
        del doc["metadata"]["timestamp"]
    doc["serialNumber"] = "urn:uuid:" + digest_uuid(render(doc))
    return doc


__all__ = ["SPEC", "document"]
