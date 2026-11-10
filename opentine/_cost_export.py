"""Cost aggregates out: OTLP metrics and a signed cost statement (0.44).

``tine cost RUN --otlp PATH`` writes an OTLP/JSON ``ExportMetricsServiceRequest``
from the run's cost breakdown: ``gen_ai.client.token.usage`` (a cumulative
monotonic sum in ``{token}``, by ``gen_ai.token.type``) and
``opentine.cost.usd`` (a sum in ``USD``, by ``gen_ai.request.model`` and by
``opentine.step.kind``), all on one resource naming the run. Any OTLP/HTTP
collector that accepts JSON takes the file as a ``/v1/metrics`` body.

``tine cost RUN --statement PATH --sign-key KEY`` writes a
``tine-cost-statement/1`` document: the aggregate (totals, by model, by kind)
plus an Ed25519 ``tine-sig/3`` block (``_signed_doc``) under the domain
``opentine.cost-statement.v1:``. ``--verify-statement PATH`` recomputes the
aggregate from the run and checks both the numbers and the signature, offline.
It states what the run *recorded*; ``tine price`` re-prices from the catalog.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine import _signed_doc
from opentine.kernel import canonical_json

SCHEMA = "tine-cost-statement/1"
DOMAIN = b"opentine.cost-statement.v1:"
SCOPE = {"name": "opentine.cost", "version": "1"}
MAX_STATEMENT_BYTES = 4 * 1024 * 1024


def aggregate(run: Any) -> dict[str, Any]:
    breakdown = run.cost_breakdown()
    return {
        "run_id": str(run.id),
        "total_cost": float(breakdown.total_cost),
        "total_tokens": int(breakdown.total_tokens),
        "input_tokens": int(breakdown.input_tokens),
        "output_tokens": int(breakdown.output_tokens),
        "by_model": {str(k): float(v) for k, v in sorted(breakdown.by_model.items())},
        "by_kind": {str(k): float(v) for k, v in sorted(breakdown.by_kind.items())},
        "currency": "USD",
    }


def _attr(key: str, value: str) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": value}}


def _sum(name: str, unit: str, points: list[dict[str, Any]], doc: str) -> dict[str, Any]:
    return {
        "name": name,
        "unit": unit,
        "description": doc,
        "sum": {"aggregationTemporality": 2, "isMonotonic": True, "dataPoints": points},
    }


def otlp_metrics(run: Any, *, now_ns: int | None = None) -> dict[str, Any]:
    totals = aggregate(run)
    stamp = str(now_ns if now_ns is not None else time.time_ns())
    start = str(int(float(getattr(run, "created_at", 0) or 0) * 1e9))

    def point(value: float | int, *attrs: dict[str, Any]) -> dict[str, Any]:
        key = "asInt" if isinstance(value, int) else "asDouble"
        number: Any = str(value) if key == "asInt" else value
        return {"attributes": list(attrs), "startTimeUnixNano": start,
                "timeUnixNano": stamp, key: number}  # fmt: skip

    tokens = [
        point(totals["input_tokens"], _attr("gen_ai.token.type", "input")),
        point(totals["output_tokens"], _attr("gen_ai.token.type", "output")),
    ]
    cost = [point(totals["total_cost"])]
    cost += [point(v, _attr("gen_ai.request.model", k)) for k, v in totals["by_model"].items()]
    cost += [point(v, _attr("opentine.step.kind", k)) for k, v in totals["by_kind"].items()]
    metrics = [
        _sum("gen_ai.client.token.usage", "{token}", tokens, "Tokens the run recorded"),
        _sum("opentine.cost.usd", "USD", cost, "Cost the run recorded at capture"),
    ]
    resource = [_attr("service.name", "opentine"), _attr("opentine.run.id", totals["run_id"])]
    return {
        "resourceMetrics": [
            {
                "resource": {"attributes": resource},
                "scopeMetrics": [{"scope": SCOPE, "metrics": metrics}],
            }
        ]
    }


def statement(run: Any) -> dict[str, Any]:
    return {"schema": SCHEMA, "aggregate": aggregate(run)}


def sign_statement(doc: dict[str, Any], private_key: Any, signer: str | None = None):
    body = {key: value for key, value in doc.items() if key != "signature"}
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    block = _signed_doc.sign(DOMAIN, body, private_key, signer=signer, signed_at=now)
    return {**body, "signature": block}


def dumps(doc: dict[str, Any]) -> bytes:
    return canonical_json(doc) + b"\n"


def load(path: str | Path) -> dict[str, Any]:
    raw = Path(path).read_bytes()
    if len(raw) > MAX_STATEMENT_BYTES:
        raise ValueError(f"{Path(path).name} exceeds {MAX_STATEMENT_BYTES} bytes")
    try:
        doc = json.loads(raw)
    except (RecursionError, ValueError):
        raise ValueError(f"{Path(path).name} is not JSON") from None
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise ValueError(f"{Path(path).name} is not a {SCHEMA} document")
    return doc


def verify_statement(doc: dict[str, Any], run: Any, public_key: Any = None) -> dict[str, Any]:
    """``{"ok", "matches_run", "signature", "basis"}`` for *doc* against *run*."""
    return verify_against(doc, statement(run), public_key)


def verify_against(doc: dict[str, Any], expected: Any, public_key: Any = None) -> dict[str, Any]:
    """:func:`verify_statement` against the statement a run yields (*expected*)."""
    body = {key: value for key, value in doc.items() if key != "signature"}
    matches = body == expected
    block = doc.get("signature")
    if not isinstance(block, dict):
        return {"ok": False, "matches_run": matches, "signature": "unsigned", "basis": None}
    result = _signed_doc.verify(DOMAIN, body, block, public_key=public_key)
    state = "verified" if result.ok else result.state
    return {
        "ok": bool(matches and result.ok),
        "matches_run": matches,
        "signature": state,
        "basis": _signed_doc.basis(block, public_key) if result.ok else None,
    }
