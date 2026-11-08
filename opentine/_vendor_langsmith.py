"""LangSmith files for :mod:`opentine._vendor_io`.

**Export** is ``{"post": [run, ...], "feedback": [...]}``: ``post`` is the
body of ``POST /runs/batch`` (``id``, ``trace_id``, ``parent_run_id``,
``dotted_order``, ``name``, ``run_type`` ``llm``/``tool``/``chain``,
``inputs``/``outputs`` (objects: a scalar becomes ``{"value": ...}``),
``start_time``/``end_time``, ``error``, ``extra.metadata`` with
``ls_model_name``, and ``usage_metadata`` (``input_tokens``/``output_tokens``)
in an ``llm`` run's outputs); ``feedback`` holds one ``POST /feedback`` body
per evaluation (``run_id``, ``key``, ``score``, ``value``, ``comment``).
LangSmith ids are UUIDs, so every id is derived as a name-based UUID from the
OpenTine span id; ``dotted_order`` is ``<start %Y%m%dT%H%M%S%fZ><id>`` per
ancestor, root first, joined by ``.``.

**Import** reads that file, a ``{"runs": [...]}`` or bare list of runs (what
``Client.list_runs`` yields, serialized), or JSON Lines of runs; ``feedback``
records beside them become evaluations.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from opentine._vendor_io import evaluation, iso, nanos, records

_NS = uuid.UUID("6f70656e-7469-6e65-8000-6c616e677331")
_TYPE = {"model": "llm", "tool": "tool", "step": "chain"}
_USAGE = "usage_metadata"


def run_id(value: Any) -> str:
    text = str(value or "")
    try:
        return str(uuid.UUID(text))
    except ValueError:
        return str(uuid.uuid5(_NS, text))


def _stamp(nanos_: int) -> str:
    return datetime.fromtimestamp(nanos_ / 1e9, UTC).strftime("%Y%m%dT%H%M%S%fZ")


def export(spans: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {span["span"]: span for span in spans}

    def dotted(span: dict[str, Any], seen: frozenset = frozenset()) -> str:
        own = _stamp(span["start"]) + run_id(span["span"])
        parent = by_id.get(span["parent"])
        if parent is None or span["span"] in seen:
            return own
        return dotted(parent, seen | {span["span"]}) + "." + own

    runs: list[dict[str, Any]] = []
    feedback: list[dict[str, Any]] = []
    for span in spans:
        outputs = span["output"] if isinstance(span["output"], dict) else (
            {} if span["output"] is None else {"value": span["output"]})  # fmt: skip
        usage = {"input_tokens": span["tokens_in"], "output_tokens": span["tokens_out"]}
        if span["kind"] == "model" and any(v is not None for v in usage.values()):
            outputs = {**outputs, _USAGE: {k: v for k, v in usage.items() if v is not None}}
        metadata = {"ls_model_name": span["model"]} if span["model"] else {}
        root = next((s for s in spans if s["trace"] == span["trace"] and not s["parent"]), span)
        run = {"id": run_id(span["span"]), "trace_id": run_id(root["span"]),
               "dotted_order": dotted(span), "name": span["name"],
               "run_type": _TYPE[span["kind"]],
               "inputs": span["input"] if isinstance(span["input"], dict) else (
                   {} if span["input"] is None else {"value": span["input"]}),
               "outputs": outputs, "start_time": iso(span["start"]),
               "end_time": iso(span["end"]), "extra": {"metadata": metadata}}  # fmt: skip
        if span["parent"]:
            run["parent_run_id"] = run_id(span["parent"])
        if span["error"]:
            run["error"] = span["error"]
        runs.append(run)
        for item in span["evals"]:
            row = {"id": str(uuid.uuid5(_NS, f"{span['span']}\x00{item['name']}")),
                   "run_id": run["id"], "key": item["name"], "score": item["score"],
                   "value": item["label"], "comment": item["explanation"]}  # fmt: skip
            feedback.append({k: v for k, v in row.items() if v is not None})
    return {"post": runs, "feedback": feedback}


def parse(document: Any) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    for run in records(document, "post", "runs"):
        if "run_id" in run and "key" in run:
            continue  # a feedback line in a JSON Lines file
        outputs = (
            dict(run["outputs"]) if isinstance(run.get("outputs"), dict) else run.get("outputs")
        )
        usage = outputs.pop(_USAGE, {}) if isinstance(outputs, dict) else {}
        extra = run.get("extra") if isinstance(run.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        start = nanos(run.get("start_time"))
        parent = run_id(run["parent_run_id"]) if run.get("parent_run_id") else None
        spans.append({"trace": run_id(run.get("trace_id") or run.get("id")),
                      "span": run_id(run.get("id")), "parent": parent,
                      "name": str(run.get("name") or ""),
                      "kind": {"llm": "model", "tool": "tool"}.get(run.get("run_type"), "step"),
                      "start": start, "end": nanos(run.get("end_time")) or start,
                      "input": run.get("inputs"), "output": outputs,
                      "model": metadata.get("ls_model_name"),
                      "tokens_in": usage.get("input_tokens"),
                      "tokens_out": usage.get("output_tokens"),
                      "error": run.get("error") or None, "evals": []})  # fmt: skip
    by_id = {span["span"]: span for span in spans}
    lines = records(document, "feedback") if isinstance(document, dict) else records(document)
    for row in lines:
        target = by_id.get(run_id(row.get("run_id"))) if "key" in row else None
        if target is not None:
            target["evals"].append(evaluation(row["key"], row.get("score"), row.get("value"),
                                              row.get("comment")))  # fmt: skip
    return spans


__all__ = ["export", "parse", "run_id"]
