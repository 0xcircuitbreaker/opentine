"""``tine evidence report RUN --format html``: one self-contained, deterministic page.

The HTML is the canonical report and is byte-identical for the same run and
opentine version:

* every value comes from the run or from its offline verification report; the
  only time shown is the run's own (``created_at``, step timestamps), never "now";
* the source path is reduced to its file name, so the machine does not leak in;
* every string is re-redacted (field-name redaction, then ``redact_text``) before
  it is written, the embedded JSON included;
* the evidence is embedded as canonical JSON (sorted keys, no whitespace) in a
  ``<script type="application/json" id="tine-evidence">`` data block;
* CSS is inline and the Content-Security-Policy is the one ``tine view`` uses
  (no scripts run, nothing is fetched).

The PDF derivative lives in :mod:`opentine._evidence_pdf`.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from html import escape
from pathlib import Path
from typing import Any

from opentine._canon_redact import _redact
from opentine._evidence_export import timeline_rows
from opentine._view_html import _scrub

SCHEMA = "tine-evidence-report/1"
_CSS = """
:root{--fg:#1d1d1f;--bg:#fff;--dim:#6e6e73;--line:#d2d2d7;--acc:#0b6e4f}
@media (prefers-color-scheme:dark){:root{--fg:#f5f5f7;--bg:#111;--dim:#a1a1a6;--line:#333}}
body{font:14px/1.5 system-ui,sans-serif;color:var(--fg);background:var(--bg);margin:0}
main{max-width:960px;margin:0 auto;padding:24px 16px}h1{font-size:20px}h2{font-size:16px}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);
padding:4px 8px;text-align:left;vertical-align:top}code{word-break:break-all}
.pass{color:var(--acc);font-weight:600}.fail{color:#c0392b;font-weight:600}
.meta{color:var(--dim);font-size:12px}
"""
_CSS_HASH = base64.b64encode(hashlib.sha256(_CSS.encode("utf-8")).digest()).decode("ascii")
CSP = (
    f"default-src 'none'; style-src 'sha256-{_CSS_HASH}'; script-src 'none'; "
    "img-src 'none'; base-uri 'none'; form-action 'none'"
)


def scrub(value: Any) -> Any:
    """Re-redact a JSON value: secret-named fields first, then every string."""
    return _strings(_redact(value))


def _strings(value: Any) -> Any:
    # Loops, not comprehensions: each comprehension level costs an extra frame.
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            out[_scrub(str(key))] = _strings(item)
        return out
    if isinstance(value, list | tuple):
        items = []
        for item in value:
            items.append(_strings(item))
        return items
    if isinstance(value, str):
        return _scrub(value)
    return value


def evidence(source: Path, data: Any, report: dict[str, Any]) -> dict[str, Any]:
    """The evidence document the page shows and embeds; deterministic for one run."""
    report = dict(report)
    report["path"] = source.name
    run_id = str(data.get("run_id") or data.get("id") or "") if isinstance(data, dict) else ""
    return scrub(
        {
            "schema": SCHEMA,
            "source": source.name,
            "run_id": run_id,
            "verify": report,
            "timeline": timeline_rows(run_id, data),
            "run": data,
        }
    )


def canonical(doc: dict[str, Any]) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def _when(stamp: Any) -> str:
    """The run's own time, in UTC; never the time the report is written."""
    if isinstance(stamp, int | float) and not isinstance(stamp, bool):
        return datetime.datetime.fromtimestamp(stamp, datetime.UTC).isoformat()
    return "" if stamp is None else str(stamp)


def _rows(pairs: list[tuple[str, Any]]) -> str:
    return "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in pairs if v != "")


def render_html(doc: dict[str, Any]) -> str:
    run = doc.get("run") if isinstance(doc.get("run"), dict) else {}
    verify = doc["verify"]
    verdict = "pass" if verify.get("ok", verify.get("verdict") == "pass") else "fail"
    summary = _rows(
        [
            ("Run", doc["run_id"]),
            ("Source", doc["source"]),
            ("Created", _when(run.get("created_at"))),
            ("Status", run.get("status", "")),
            ("Verification", verdict),
        ]
    )
    checks = "".join(
        f'<tr><td>{_e(c.get("name"))}</td><td class="{_e(c.get("outcome"))}">'
        f"{_e(c.get('outcome'))}</td><td>{_e(c.get('reason') or c.get('detail') or '')}</td></tr>"
        for c in verify.get("checks") or []
        if isinstance(c, dict)
    )
    steps = "".join(
        f"<tr><td>{r['index']}</td><td>{_e(r['kind'])}</td><td>{_e(r['tool'])}</td>"
        f"<td>{_e(r['time'])}</td><td><code>{_e(r['step_id'])}</code></td></tr>"
        for r in doc["timeline"]
    )
    data = canonical(doc).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    digest = hashlib.sha256(canonical(doc).encode("utf-8")).hexdigest()
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>tine evidence {_e(doc['run_id'][:12])}</title><style>{_CSS}</style></head>"
        f"<body><main><h1>Evidence report</h1><table>{summary}</table>"
        f"<h2>Offline verification</h2><table><tr><th>Check</th><th>Outcome</th>"
        f"<th>Detail</th></tr>{checks}</table>"
        f"<h2>Timeline</h2><table><tr><th>#</th><th>Kind</th><th>Tool</th><th>Time</th>"
        f"<th>Step</th></tr>{steps}</table>"
        f'<p class="meta">{_e(doc["schema"])}; evidence sha256 <code>{digest}</code>; '
        "the canonical JSON is embedded below as tine-evidence.</p>"
        f'<script type="application/json" id="tine-evidence">{data}</script>'
        "</main></body></html>\n"
    )


__all__ = ["CSP", "SCHEMA", "canonical", "evidence", "render_html", "scrub"]
