"""Arize Phoenix files for :mod:`opentine._vendor_io`.

**Export** is ``{"data": [span, ...], "span_annotations": [...]}``: ``data``
in the shape of Phoenix's REST spans (``GET``/``POST
/v1/projects/{project}/spans``: ``name``, ``context.trace_id``/``span_id``,
``parent_id``, ``span_kind``, ``start_time``/``end_time``, ``status_code``,
flat OpenInference ``attributes`` and ``events``), and ``span_annotations``
the body of ``POST /v1/span_annotations`` (``span_id``, ``name``,
``annotator_kind: "CODE"``, ``result: {score, label, explanation}``), one per
evaluation. Each evaluation is also a ``gen_ai.evaluation.result`` span event.
OpenInference keys: ``openinference.span.kind`` (``LLM``/``TOOL``/``CHAIN``),
``input.value``/``output.value`` with ``*.mime_type``, ``llm.model_name``,
``llm.token_count.prompt``/``completion``, ``tool.name``.

**Import** reads that file, a bare list of spans, or JSON Lines of spans;
nested attribute objects (``{"input": {"value": ...}}``) are flattened first.
"""

from __future__ import annotations

import json
from typing import Any

from opentine._vendor_io import EVAL_EVENT, evaluation, iso, maybe_json, nanos, records

_KIND = {"model": "LLM", "tool": "TOOL", "step": "CHAIN"}
_JSON = "application/json"


def _value(attrs: dict[str, Any], side: str, payload: Any) -> None:
    if payload is None:
        return
    if isinstance(payload, str):
        attrs[f"{side}.value"] = payload
        attrs[f"{side}.mime_type"] = "text/plain"
    else:
        attrs[f"{side}.value"] = json.dumps(payload, sort_keys=True, default=str)
        attrs[f"{side}.mime_type"] = _JSON


def export(spans: list[dict[str, Any]]) -> dict[str, Any]:
    data: list[dict[str, Any]] = []
    notes: list[dict[str, Any]] = []
    for span in spans:
        attrs: dict[str, Any] = {"openinference.span.kind": _KIND[span["kind"]]}
        _value(attrs, "input", span["input"])
        _value(attrs, "output", span["output"])
        if span["kind"] == "model" and span["model"]:
            attrs["llm.model_name"] = span["model"]
        for key, value in (("prompt", span["tokens_in"]), ("completion", span["tokens_out"])):
            if value is not None:
                attrs[f"llm.token_count.{key}"] = value
        if span["kind"] == "tool":
            attrs["tool.name"] = span["name"]
        events = []
        for item in span["evals"]:
            fields = {"gen_ai.evaluation.name": item["name"],
                      "gen_ai.evaluation.score.value": item["score"],
                      "gen_ai.evaluation.score.label": item["label"],
                      "gen_ai.evaluation.explanation": item["explanation"]}  # fmt: skip
            events.append(
                {
                    "name": EVAL_EVENT,
                    "timestamp": iso(span["end"]),
                    "attributes": {k: v for k, v in fields.items() if v is not None},
                }
            )
            result = {k: item[k] for k in ("score", "label", "explanation") if item[k] is not None}
            notes.append({"span_id": span["span"], "name": item["name"],
                          "annotator_kind": "CODE", "result": result})  # fmt: skip
        data.append({"name": span["name"], "context": {"trace_id": span["trace"],
                     "span_id": span["span"]}, "parent_id": span["parent"],
                     "span_kind": _KIND[span["kind"]], "start_time": iso(span["start"]),
                     "end_time": iso(span["end"]),
                     "status_code": "ERROR" if span["error"] else "OK",
                     "status_message": span["error"] or "", "attributes": attrs,
                     "events": events})  # fmt: skip
    return {"data": data, "span_annotations": notes}


def _flat(value: Any, prefix: str = "") -> dict[str, Any]:
    if not isinstance(value, dict) or (prefix and not value):
        return {prefix: value} if prefix else {}
    out: dict[str, Any] = {}
    for key, item in value.items():
        out.update(_flat(item, f"{prefix}.{key}" if prefix else str(key)))
    return out


def _payload(attrs: dict[str, Any], side: str) -> Any:
    value = attrs.get(f"{side}.value")
    if attrs.get(f"{side}.mime_type") == _JSON or attrs.get(f"{side}.mime_type") is None:
        return maybe_json(value)
    return value


def parse(document: Any) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    for raw in records(document, "data", "spans"):
        context = raw.get("context") if isinstance(raw.get("context"), dict) else {}
        attrs = _flat(raw.get("attributes") or {})
        kind = str(raw.get("span_kind") or attrs.get("openinference.span.kind") or "").upper()
        start = nanos(raw.get("start_time"))
        evals = []
        for event in raw.get("events") or []:
            fields = event.get("attributes") if isinstance(event, dict) else None
            if isinstance(fields, dict) and event.get("name") == EVAL_EVENT:
                evals.append(evaluation(fields.get("gen_ai.evaluation.name"),
                                        fields.get("gen_ai.evaluation.score.value"),
                                        fields.get("gen_ai.evaluation.score.label"),
                                        fields.get("gen_ai.evaluation.explanation")))  # fmt: skip
        spans.append({"trace": str(context.get("trace_id", raw.get("trace_id", ""))),
                      "span": str(context.get("span_id", raw.get("span_id", ""))),
                      "parent": raw.get("parent_id"), "name": str(raw.get("name") or ""),
                      "kind": {"LLM": "model", "TOOL": "tool"}.get(kind, "step"),
                      "start": start, "end": nanos(raw.get("end_time")) or start,
                      "input": _payload(attrs, "input"), "output": _payload(attrs, "output"),
                      "model": attrs.get("llm.model_name"),
                      "tokens_in": attrs.get("llm.token_count.prompt"),
                      "tokens_out": attrs.get("llm.token_count.completion"),
                      "error": (raw.get("status_message") or "error")
                      if raw.get("status_code") == "ERROR" else None, "evals": evals})  # fmt: skip
    if isinstance(document, dict):  # annotations exported beside the spans
        by_id = {span["span"]: span for span in spans}
        for note in records(document, "span_annotations"):
            result = note.get("result") if isinstance(note.get("result"), dict) else {}
            target = by_id.get(str(note.get("span_id", "")))
            item = evaluation(note.get("name"), result.get("score"), result.get("label"),
                              result.get("explanation"))  # fmt: skip
            if target is not None and item not in target["evals"]:
                target["evals"].append(item)
    return spans


__all__ = ["export", "parse"]
