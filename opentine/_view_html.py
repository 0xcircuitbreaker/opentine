"""Render one run as a single self-contained, static HTML page.

The page makes no external request (inline CSS, no script, no link to any
resource) and is a pure function of the run: the same run gives the same bytes.
Every recorded string passes through :func:`html.escape`, so a step that holds
markup renders as text. Each pretty-printed field is capped at ``FIELD_CAP``
characters and a marker says how much was cut.
"""

from __future__ import annotations

import datetime
import json
from html import escape
from typing import Any

FIELD_CAP = 64 * 1024

_CSS = """
:root{--bg:#fbfaf8;--fg:#1d1b19;--dim:#6b645c;--line:#e4dfd8;--card:#fff;--acc:#a8733f}
@media (prefers-color-scheme:dark){:root{--bg:#161412;--fg:#ece7e1;--dim:#a39a90;
--line:#33302c;--card:#1f1c19;--acc:#d4a574}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,sans-serif}main{max-width:960px;margin:0 auto;padding:24px 16px}
h1{font-size:20px;margin:0 0 8px}h1 code{color:var(--acc)}h2{font-size:16px;margin:28px 0 8px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}
dt{color:var(--dim)}dd{margin:0;overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--bg);border:1px solid var(--line);
padding:8px;border-radius:6px;font:12px/1.45 ui-monospace,monospace;margin:6px 0 0}
ol{list-style:none;padding:0;margin:0}li{background:var(--card);border:1px solid var(--line);
border-radius:8px;padding:10px 12px;margin:0 0 8px}.meta{color:var(--dim);font-size:13px}
.kind{font-weight:600;color:var(--acc)}details{margin-top:6px}summary{cursor:pointer;color:var(--dim)}
.err{color:#c0392b}.cut{color:var(--acc);font-style:italic}
"""


def _e(value: Any) -> str:
    return escape(str(value), quote=True)


def _pretty(value: Any) -> str:
    """Escaped, pretty-printed JSON for *value*, capped with a visible marker."""
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)
    if len(text) <= FIELD_CAP:
        return _e(text)
    marker = f"\n… [truncated {len(text) - FIELD_CAP} characters of {len(text)}]"
    return _e(text[:FIELD_CAP]) + f'<span class="cut">{_e(marker)}</span>'


def _usage(steps: list) -> dict[str, float]:
    total: dict[str, float] = {}
    for step in steps:
        for key, value in (step.usage or {}).items():
            total[key] = total.get(key, 0) + value
    return dict(sorted(total.items()))


def _num(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:g}"


def _seconds(value: float) -> str:
    return f"{value:.3f}s"


def _tool_name(step: Any) -> str:
    for source in (step.tool_info, step.inputs):
        name = source.get("name") if isinstance(source, dict) else None
        if isinstance(name, str) and name:
            return name
    return ""


def _block(label: str, value: Any) -> str:
    if value in ({}, [], "", None):
        return ""
    return f"<details><summary>{_e(label)}</summary><pre>{_pretty(value)}</pre></details>"


def _step(index: int, step: Any) -> str:
    tokens = sum(value for value in (step.usage or {}).values())
    parts = [f'<span class="kind">{_e(step.kind.value)}</span>']
    for label, value in (
        ("model", step.model_info),
        ("provider", step.provider),
        ("tool", _tool_name(step)),
        ("duration", _seconds(step.duration) if step.duration else ""),
        ("tokens", _num(tokens) if tokens else ""),
    ):
        if value:
            parts.append(f"{label} <b>{_e(value)}</b>")
    body = "".join(
        (
            _block("Inputs", step.inputs),
            _block("Outputs", step.outputs),
            _block("Usage", step.usage),
            _block("Error", step.error),
        )
    )
    error = ' <span class="err">error</span>' if step.error else ""
    return (
        f'<li id="step-{index}"><div class="meta">#{index} <code>{_e(step.id[:12])}</code>'
        f"{error}</div><div>{' · '.join(parts)}</div>{body}</li>"
    )


def _when(created_at: float) -> str:
    try:
        moment = datetime.datetime.fromtimestamp(float(created_at), tz=datetime.UTC)
    except (OverflowError, OSError, ValueError, TypeError):
        return ""
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def render_run(run: Any, *, cost: str) -> str:
    """The whole page for *run*; *cost* is the already-formatted total cost."""
    metadata = run.metadata if isinstance(run.metadata, dict) else {}
    integrity = metadata.get("integrity") if isinstance(metadata.get("integrity"), dict) else {}
    digest = integrity.get("digest") or ""
    models = sorted({m for m in [run.model_info, *(s.model_info for s in run.steps)] if m})
    usage_text = ", ".join(f"{key} {_num(value)}" for key, value in _usage(run.steps).items())
    rows = [
        ("Status", run.status.value),
        ("Model", ", ".join(models) or "-"),
        ("Created", _when(run.created_at)),
        ("Steps", str(len(run.steps))),
        ("Duration", _seconds(run.total_duration)),
        ("Tokens", f"{run.total_tokens}" + (f" ({usage_text})" if usage_text else "")),
        ("Cost", cost),
        ("Forked from", metadata.get("forked_from") or ""),
        ("Integrity", f"{integrity.get('algorithm') or 'sha256'}:{digest}" if digest else ""),
    ]
    header = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in rows if v)
    prompts = "".join(
        f"<h2>{_e(label)}</h2><pre>{_pretty(text)}</pre>"
        for label, text in (("System prompt", run.system_prompt), ("Prompt", run.user_prompt))
        if text
    )
    steps = "".join(_step(index, step) for index, step in enumerate(run.steps))
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="color-scheme" content="light dark">'
        f"<title>tine run {_e(run.id[:12])}</title><style>{_CSS}</style></head>"
        f"<body><main><h1>Run <code>{_e(run.id)}</code></h1><dl>{header}</dl>{prompts}"
        f"<h2>Steps</h2><ol>{steps or '<li>No steps.</li>'}</ol>"
        '<p class="meta">Written by tine view.</p></main></body></html>\n'
    )


__all__ = ["FIELD_CAP", "render_run"]
