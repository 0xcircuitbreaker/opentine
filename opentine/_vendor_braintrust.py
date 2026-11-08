"""Braintrust files for :mod:`opentine._vendor_io`.

**Export** is the body of ``POST /v1/project_logs/{project_id}/insert`` (and
of an experiment's ``/insert``): ``{"events": [row, ...]}``, one row per span
with ``id``/``span_id``, ``root_span_id`` (the trace), ``span_parents``,
``input``/``output``, ``error``, ``scores`` (``{name: number}``),
``metadata``, ``metrics`` (``start``/``end`` in Unix seconds,
``prompt_tokens``/``completion_tokens``) and ``span_attributes``
(``{name, type}``, type ``llm``/``tool``/``task``). Braintrust scores are
numbers in [0, 1]: an evaluation outside that range, or a label without a
score, is kept under ``metadata["opentine.evaluations"]`` instead, so nothing
is dropped and Braintrust never sees an invalid score.

**Import** reads that body, the ``{"events": [...]}`` page that ``GET
/v1/project_logs/{id}/fetch`` returns, a bare list, or JSON Lines of rows.
"""

from __future__ import annotations

from typing import Any

from opentine._vendor_io import evaluation, nanos, records

_TYPE = {"model": "llm", "tool": "tool", "step": "task"}
_EXTRA = "opentine.evaluations"


def _in_range(item: dict[str, Any]) -> bool:
    return item["score"] is not None and 0 <= item["score"] <= 1 and not item["explanation"]


def export(spans: list[dict[str, Any]]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for span in spans:
        metrics = {"start": span["start"] / 1e9, "end": span["end"] / 1e9}
        for key, value in (("prompt_tokens", span["tokens_in"]),
                           ("completion_tokens", span["tokens_out"])):  # fmt: skip
            if value is not None:
                metrics[key] = value
        metadata: dict[str, Any] = {}
        if span["model"]:
            metadata["model"] = span["model"]
        extra = [item for item in span["evals"] if not _in_range(item)]
        if extra:
            metadata[_EXTRA] = extra
        row = {"id": span["span"], "span_id": span["span"], "root_span_id": span["trace"],
               "span_parents": [span["parent"]] if span["parent"] else [],
               "input": span["input"], "output": span["output"],
               "scores": {i["name"]: i["score"] for i in span["evals"] if _in_range(i)},
               "metadata": metadata, "metrics": metrics,
               "span_attributes": {"name": span["name"], "type": _TYPE[span["kind"]]}}  # fmt: skip
        if span["error"]:
            row["error"] = span["error"]
        rows.append(row)
    return {"events": rows}


def parse(document: Any) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    for row in records(document, "events"):
        attrs = row.get("span_attributes") if isinstance(row.get("span_attributes"), dict) else {}
        metrics = row.get("metrics") if isinstance(row.get("metrics"), dict) else {}
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        parents = row.get("span_parents") if isinstance(row.get("span_parents"), list) else []
        scores = row.get("scores") if isinstance(row.get("scores"), dict) else {}
        evals = [evaluation(name, value) for name, value in scores.items() if value is not None]
        for item in metadata.get(_EXTRA) or []:
            if isinstance(item, dict):
                evals.append(evaluation(item.get("name"), item.get("score"), item.get("label"),
                                        item.get("explanation")))  # fmt: skip
        span_id = str(row.get("span_id") or row.get("id") or "")
        start = nanos(metrics.get("start"))
        error = row.get("error")
        spans.append({"trace": str(row.get("root_span_id") or span_id), "span": span_id,
                      "parent": parents[0] if parents else None,
                      "name": str(attrs.get("name") or ""),
                      "kind": {"llm": "model", "tool": "tool"}.get(attrs.get("type"), "step"),
                      "start": start, "end": nanos(metrics.get("end")) or start,
                      "input": row.get("input"), "output": row.get("output"),
                      "model": metadata.get("model"),
                      "tokens_in": metrics.get("prompt_tokens"),
                      "tokens_out": metrics.get("completion_tokens"),
                      "error": None if error in (None, "") else str(error),
                      "evals": evals})  # fmt: skip
    return spans


__all__ = ["export", "parse"]
