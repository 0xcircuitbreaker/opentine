"""``tine explain RUN``: a deterministic, offline summary of one run.

The summary is built from the recorded run alone: no clock, no network, no
model. The same run always gives the same summary and the same bytes, in both
the text and the JSON rendering, so it can be stored as an annotation, diffed
and cited. Facts the run does not carry (tokens, cost) are *absent*, never 0.

An optional narrative (``--narrative``) is the one exception: it is written by
a *local* model named in ``OPENTINE_EXPLAIN_MODEL`` (``provider[:model]`` with
an unmetered local provider such as ``ollama``), is stored apart from the
summary and is labelled ``model-generated`` wherever it appears.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

from opentine._actions import extract_actions
from opentine._local_providers import LOCAL_UNMETERED_PROVIDERS

SCHEMA = "opentine-explain/1"
NARRATIVE_SCHEMA = "opentine-explain-narrative/1"
ANNOTATION_KEY = "opentine.explain"
NARRATIVE_KEY = "opentine.explain.narrative"
NARRATIVE_ENV = "OPENTINE_EXPLAIN_MODEL"
NARRATIVE_LABEL = "model-generated narrative; not deterministic, not evidence"
MAX_TEXT = 500
MAX_LIST = 50
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def _clip(value: Any, limit: int = MAX_TEXT) -> str:
    text = " ".join(_CONTROL.sub(" ", str(value or "")).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _text_of(mapping: Any) -> str:
    if isinstance(mapping, str):
        return mapping
    if isinstance(mapping, dict):
        for key in ("text", "content", "prompt", "message", "result", "output"):
            if isinstance(mapping.get(key), str):
                return mapping[key]
    return ""


def _asked(run: Any) -> str:
    if run.user_prompt:
        return _clip(run.user_prompt)
    for step in run.steps:
        if step.kind.value in ("model", "think") and _text_of(step.inputs):
            return _clip(_text_of(step.inputs))
    return ""


def _outcome(run: Any) -> dict[str, Any]:
    final = ""
    for step in reversed(run.steps):
        if step.kind.value in ("done", "model") and _text_of(step.outputs):
            final = _clip(_text_of(step.outputs))
            break
    return {"status": str(getattr(run.status, "value", run.status)), "final_text": final}


def _errors(run: Any) -> list[dict[str, Any]]:
    found = []
    for seq, step in enumerate(run.steps):
        if step.kind.value == "error" or step.error:
            message = _text_of(step.error) or step.error.get("type", "") if step.error else ""
            found.append({"seq": seq, "kind": step.kind.value, "message": _clip(message, 200)})
    return found[:MAX_LIST]


def summarize(run: Any) -> dict[str, Any]:
    """The deterministic summary of *run* (a JSON-ready dict, sorted where it is a set)."""
    actions, clipped = extract_actions(run)
    tools: dict[str, int] = {}
    written: set[str] = set()
    read: set[str] = set()
    hosts: set[str] = set()
    failed_tools = 0
    for action in actions:
        tools[action.tool] = tools.get(action.tool, 0) + 1
        written.update(action.written)
        read.update(path for path in action.paths if path not in action.written)
        hosts.update(action.hosts)
        failed_tools += bool(action.error)
    kinds: dict[str, int] = {}
    for step in run.steps:
        kinds[step.kind.value] = kinds.get(step.kind.value, 0) + 1
    models = sorted({step.model_info for step in run.steps if step.model_info})
    summary: dict[str, Any] = {
        "schema": SCHEMA,
        "run": run.id,
        "asked": _asked(run),
        "models": models or ([run.model_info] if run.model_info else []),
        "steps": {"total": len(run.steps), "by_kind": dict(sorted(kinds.items()))},
        "tools": dict(sorted(tools.items())),
        "files_written": sorted(written)[:MAX_LIST],
        "files_read": sorted(read - written)[:MAX_LIST],
        "hosts": sorted(hosts)[:MAX_LIST],
        "outcome": _outcome(run),
        "errors": _errors(run),
        "failed_tool_calls": failed_tools,
        "actions_clipped": bool(clipped),
    }
    breakdown = run.cost_breakdown()
    if breakdown.input_tokens or breakdown.output_tokens:
        summary["token_usage"] = {
            "input": breakdown.input_tokens,
            "output": breakdown.output_tokens,
        }
    if run.total_cost:
        summary["cost_usd"] = round(float(run.total_cost), 6)
    return summary


def canonical(summary: dict[str, Any]) -> bytes:
    return json.dumps(summary, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest(summary: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical(summary)).hexdigest()


def _names(values: list[str] | dict[str, int], empty: str = "none") -> str:
    if isinstance(values, dict):
        return ", ".join(f"{name} x{count}" for name, count in values.items()) or empty
    shown = ", ".join(values[:10]) + (f" (+{len(values) - 10} more)" if len(values) > 10 else "")
    return shown or empty


def render_text(summary: dict[str, Any]) -> str:
    """The human rendering: a fixed layout over the summary, so also deterministic."""
    outcome = summary["outcome"]
    lines = [
        f"Run {summary['run']}",
        f"Asked: {summary['asked'] or '(no prompt recorded)'}",
        f"Models: {_names(summary['models'], 'unknown')}",
        f"Steps: {summary['steps']['total']} ({_names(summary['steps']['by_kind'])})",
        f"Tools: {_names(summary['tools'])}",
        f"Files written: {_names(summary['files_written'])}",
        f"Files read: {_names(summary['files_read'])}",
        f"Outcome: {outcome['status']}"
        + (f": {outcome['final_text']}" if outcome["final_text"] else ""),
        f"Errors: {len(summary['errors'])} step(s), "
        f"{summary['failed_tool_calls']} failed tool call(s)",
    ]
    for error in summary["errors"][:5]:
        lines.append(f"  step {error['seq']} ({error['kind']}): {error['message'] or '-'}")
    if "token_usage" in summary:
        usage = summary["token_usage"]
        lines.append(f"Tokens: {usage['input']} in, {usage['output']} out")
    if "cost_usd" in summary:
        lines.append(f"Cost: ${summary['cost_usd']:.6f}")
    return "\n".join(lines) + "\n"


class NarrativeUnavailable(RuntimeError):
    """No local model is configured, or the one configured is not local."""


def narrative_model_spec() -> str:
    spec = os.environ.get(NARRATIVE_ENV, "").strip()
    if not spec:
        raise NarrativeUnavailable(
            f"--narrative needs a local model: set {NARRATIVE_ENV}=provider[:model] "
            "(for example ollama:llama3.1); nothing was sent anywhere"
        )
    provider = spec.partition(":")[0].strip().casefold()
    if provider not in LOCAL_UNMETERED_PROVIDERS:
        raise NarrativeUnavailable(
            f"{NARRATIVE_ENV} names {provider!r}, which is not a local provider; "
            "--narrative only uses a model on this machine"
        )
    return spec


def _model(spec: str) -> Any:
    from opentine.models import resolve_model

    return resolve_model(spec)


def narrative(summary: dict[str, Any], spec: str) -> dict[str, Any]:
    """Ask the local model *spec* for a short narrative of *summary*; label it."""
    import asyncio

    prompt = (
        "Summarise this recorded agent run in three to five plain sentences. "
        "Use only the facts given.\n\n" + canonical(summary).decode()
    )
    response = asyncio.run(_model(spec).complete([{"role": "user", "content": prompt}]))
    text = _clip(_text_of(response), 4000)
    return {
        "schema": NARRATIVE_SCHEMA,
        "generated_by": "model",
        "label": NARRATIVE_LABEL,
        "model": spec,
        "summary_digest": digest(summary),
        "text": text,
    }


__all__ = [
    "ANNOTATION_KEY",
    "NARRATIVE_ENV",
    "NARRATIVE_KEY",
    "NARRATIVE_LABEL",
    "NarrativeUnavailable",
    "SCHEMA",
    "canonical",
    "digest",
    "narrative",
    "narrative_model_spec",
    "render_text",
    "summarize",
]
