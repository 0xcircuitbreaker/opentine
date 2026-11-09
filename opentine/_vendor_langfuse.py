"""Langfuse files for :mod:`opentine._vendor_io`.

**Export** is the body of ``POST /api/public/ingestion``: ``{"batch": [...]}``
of ``trace-create`` (one per trace), ``generation-create`` (model steps) or
``span-create`` (everything else) with ``traceId``/``parentObservationId``,
``startTime``/``endTime``, ``input``/``output``, ``model`` and
``usageDetails`` (``input``/``output``), ``level: "ERROR"`` plus
``statusMessage`` on failures, and one ``score-create`` per evaluation
(``value`` numeric, or a ``CATEGORICAL`` string label; ``comment`` the
explanation) on its ``observationId``. Event ids are derived, so re-exporting
is idempotent in Langfuse (it de-duplicates by event id).

**Import** reads that batch, or Langfuse's own export: a trace object from
``GET /api/public/traces/{id}`` (``observations`` and ``scores``), a list of
them, or a ``{"data": [...]}`` page.
"""

from __future__ import annotations

import hashlib
from typing import Any

from opentine._vendor_io import evaluation, iso, nanos, records


def _id(*parts: Any) -> str:
    return hashlib.sha256("\x00".join(map(str, parts)).encode()).hexdigest()[:32]


def export(spans: list[dict[str, Any]]) -> dict[str, Any]:
    batch: list[dict[str, Any]] = []
    traces: set[str] = set()
    for span in spans:
        stamp = iso(span["start"])
        if span["trace"] not in traces:
            traces.add(span["trace"])
            root = next((s for s in spans if s["trace"] == span["trace"] and not s["parent"]), span)
            batch.append({"id": _id("trace", span["trace"]), "type": "trace-create",
                          "timestamp": stamp, "body": {"id": span["trace"], "name": root["name"],
                          "timestamp": stamp, "input": root["input"], "output": root["output"],
                          "metadata": {"source": "opentine"}}})  # fmt: skip
        body: dict[str, Any] = {"id": span["span"], "traceId": span["trace"], "name": span["name"],
                                "startTime": stamp, "endTime": iso(span["end"]),
                                "input": span["input"], "output": span["output"],
                                "metadata": {"opentine.kind": span["kind"]}}  # fmt: skip
        if span["parent"]:
            body["parentObservationId"] = span["parent"]
        if span["error"]:
            body.update(level="ERROR", statusMessage=span["error"])
        kind = "span-create"
        if span["kind"] == "model":
            kind = "generation-create"
            body["model"] = span["model"]
            usage = {"input": span["tokens_in"], "output": span["tokens_out"]}
            body["usageDetails"] = {k: v for k, v in usage.items() if v is not None}
        batch.append({"id": _id(kind, span["span"]), "type": kind, "timestamp": stamp,
                      "body": body})  # fmt: skip
        for item in span["evals"]:
            score: dict[str, Any] = {"id": _id("score", span["span"], item["name"]),
                                     "traceId": span["trace"], "observationId": span["span"],
                                     "name": item["name"]}  # fmt: skip
            if item["score"] is not None:
                score.update(value=item["score"], dataType="NUMERIC")
            else:
                score.update(value=item["label"] or "", dataType="CATEGORICAL")
            if item["explanation"]:
                score["comment"] = item["explanation"]
            batch.append({"id": score["id"], "type": "score-create", "timestamp": stamp,
                          "body": score})  # fmt: skip
    return {"batch": batch}


def _kind(obs: dict[str, Any]) -> str:
    metadata = obs.get("metadata") if isinstance(obs.get("metadata"), dict) else {}
    return (
        "tool" if metadata.get("opentine.kind") == "tool" or obs.get("type") == "TOOL" else "step"
    )


def _span(obs: dict[str, Any], trace: str) -> dict[str, Any]:
    usage = obs.get("usageDetails") or obs.get("usage") or {}
    is_model = obs.get("type") in ("GENERATION", "generation-create") or bool(obs.get("model"))
    start = nanos(obs.get("startTime") or obs.get("timestamp"))
    return {"trace": str(obs.get("traceId") or trace), "span": str(obs.get("id", "")),
            "parent": obs.get("parentObservationId"), "name": str(obs.get("name") or ""),
            "kind": "model" if is_model else _kind(obs), "start": start,
            "end": nanos(obs.get("endTime")) or start,
            "input": obs.get("input"), "output": obs.get("output"), "model": obs.get("model"),
            "tokens_in": usage.get("input", usage.get("promptTokens")),
            "tokens_out": usage.get("output", usage.get("completionTokens")),
            "error": (obs.get("statusMessage") or "error") if obs.get("level") == "ERROR" else None,
            "evals": []}  # fmt: skip


def _score(score: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    value = score.get("value")
    label = score.get("stringValue", value if isinstance(value, str) else None)
    item = evaluation(score.get("name"), value, label, score.get("comment"))
    return str(score.get("observationId") or score.get("traceId") or ""), item


def parse(document: Any) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    scores: list[tuple[str, dict[str, Any]]] = []
    if isinstance(document, dict) and isinstance(document.get("batch"), list):
        for event in records(document, "batch"):
            body = event.get("body") if isinstance(event.get("body"), dict) else {}
            kind = str(event.get("type", ""))
            if kind in ("span-create", "generation-create", "event-create"):
                spans.append(_span({**body, "type": kind}, ""))
            elif kind == "score-create":
                scores.append(_score(body))
    else:
        for trace in records(document, "data"):
            for obs in trace.get("observations") or []:
                if isinstance(obs, dict):
                    spans.append(_span(obs, str(trace.get("id", ""))))
            scores += [_score(s) for s in trace.get("scores") or [] if isinstance(s, dict)]
    by_id = {span["span"]: span for span in spans}
    for target, item in scores:
        if target in by_id:
            by_id[target]["evals"].append(item)
    return spans


__all__ = ["export", "parse"]
