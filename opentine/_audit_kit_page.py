"""The two human pages of an audit kit: ``verify.html`` and ``REPORT.md``/``report.html``.

``verify.html`` is one self-contained file: the browser build of the TS
verifier (``opentine/data/ui/tine-verifier.js``, the file ``tine ui`` ships)
inlined as a module, the kit's runs embedded as base64 of their uncompressed
bytes, and a small script that re-checks every embedded run when the page
opens. It loads nothing: no ``src``, no ``href`` to the network, no fetch. A
reader may also drop any other ``.tine`` file on it. No key is pinned in a
browser, so an Ed25519 signature that holds under the key the file embeds
reads ``verified-tofu``; the pinned check is the pyz's (``tine-verify.pyz
--pubkey``) and ``tine audit-kit verify``'s.

The report is printed, not rendered to PDF: Markdown for the record and the
same table as a static HTML page. Both are pure functions of the build
summary they are handed.
"""

from __future__ import annotations

import base64
import re
from html import escape
from pathlib import Path
from typing import Any

UI = Path(__file__).resolve().parent / "data" / "ui"
VERIFIER = UI / "tine-verifier.js"
_EXPORT = re.compile(r"export\{([^}]*)\};?")
#: Lets a test (or Node) run the page's check without a DOM: see :func:`page_script`.
SCRIPT_START = "/*tine-audit-kit:script*/"
SCRIPT_END = "/*tine-audit-kit:end*/"

_CHECK = """
const runs = JSON.parse(document_runs());
function bytes(b64) { const s = atob(b64); const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i); return out; }
async function checkAll() {
  const out = [];
  for (const r of runs) {
    try { const rep = await TineVerifier.verifyArtifact(bytes(r.b64), r.file);
      out.push({ file: r.file, expected: r.digest, root: rep.root,
        ok: rep.ok && String(rep.root).split(":").pop() === r.digest.split(":").pop(),
        digest_match: String(rep.root).split(":").pop() === r.digest.split(":").pop(),
        integrity: rep.integrity, signature: rep.signature ? rep.signature.state : "none" });
    } catch (e) { out.push({ file: r.file, ok: false, error: String(e && e.message || e) }); }
  }
  return out;
}
globalThis.tineKitResults = checkAll();
"""

_DOM = """
function cell(t) { const td = document.createElement("td"); td.textContent = t; return td; }
function row(r) { const tr = document.createElement("tr");
  const verdict = r.ok ? "pass" : "fail";
  [r.file, verdict, r.integrity ? r.integrity.reason : (r.error || ""), r.signature || ""]
    .forEach((t, i) => { const td = cell(t); if (i === 1) td.className = verdict;
      tr.appendChild(td); });
  return tr; }
if (globalThis.document) {
  globalThis.tineKitResults.then((rows) => {
    const body = document.getElementById("results");
    rows.forEach((r) => body.appendChild(row(r)));
    const all = rows.length > 0 && rows.every((r) => r.ok);
    const head = document.getElementById("verdict");
    head.textContent = all ? "PASS: every embedded run verified in this browser"
                           : "FAIL: at least one embedded run did not verify";
    head.className = all ? "pass" : "fail";
  });
  document.getElementById("pick").addEventListener("change", async (ev) => {
    for (const f of ev.target.files) {
      const rep = await TineVerifier.verifyArtifact(new Uint8Array(await f.arrayBuffer()), f.name)
        .catch((e) => ({ ok: false, integrity: { reason: String(e.message || e) },
                         signature: null }));
      document.getElementById("results").appendChild(row({ file: f.name, ok: rep.ok,
        integrity: rep.integrity, signature: rep.signature ? rep.signature.state : "none" }));
    }
  });
}
"""

_STYLE = (
    ":root{--fg:#1b1b1b;--bg:#fff;--ok:#11703a;--bad:#b3261e;--line:#ccc}"
    "@media (prefers-color-scheme: dark){:root{--fg:#eee;--bg:#161616;--ok:#5fd38d;"
    "--bad:#ff8a80;--line:#444}}body{font:15px/1.5 system-ui,sans-serif;color:var(--fg);"
    "background:var(--bg);margin:0 auto;max-width:960px;padding:16px}table{border-collapse:"
    "collapse;width:100%}td,th{border:1px solid var(--line);padding:4px 8px;text-align:left;"
    "vertical-align:top;overflow-wrap:anywhere}.pass{color:var(--ok)}.fail{color:var(--bad)}"
)


def verifier_module(source: str | None = None) -> str:
    """``tine-verifier.js`` with its ES ``export{...}`` turned into ``TineVerifier``."""
    text = VERIFIER.read_text(encoding="utf-8") if source is None else source
    found = None
    for found in _EXPORT.finditer(text):
        pass  # the bundle's own export list is its last one
    if found is None:
        raise ValueError("tine-verifier.js has no trailing export list")
    pairs = []
    for item in found.group(1).split(","):
        local, _, public = item.strip().partition(" as ")
        pairs.append(f"{(public or local).strip()}:{local.strip()}")
    exports = "globalThis.TineVerifier={" + ",".join(pairs) + "};\n"
    body = text[: found.start()] + exports + text[found.end() :]
    return body.replace("</script", "<\\/script")


def page_script(runs: list[dict[str, Any]], *, dom: bool = True) -> str:
    """The page's one inline module: verifier, embedded runs and the check."""
    import json

    data = json.dumps(json.dumps(runs, sort_keys=True), ensure_ascii=True)
    data = data.replace("</", "<\\/")
    tail = _DOM if dom else ""
    return (
        f"{SCRIPT_START}\n{verifier_module()}\nfunction document_runs(){{return {data};}}\n"
        f"{_CHECK}{tail}{SCRIPT_END}"
    )


def embedded(file: str, digest: str, raw: bytes) -> dict[str, Any]:
    """One run as the page embeds it: the uncompressed bytes, base64."""
    return {"file": file, "digest": digest, "b64": base64.b64encode(raw).decode("ascii")}


def verify_html(runs: list[dict[str, Any]], title: str) -> str:
    rows = "".join(f"<li><code>{escape(r['file'])}</code> {escape(r['digest'])}</li>" for r in runs)
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "script-src 'unsafe-inline'; style-src 'unsafe-inline'\">"
        f"<title>Offline run check</title><style>{_STYLE}</style></head><body>"
        f"<h1>Offline run check</h1><p>{escape(title)}</p>"
        "<p>This page carries its own verifier (the OpenTine TypeScript verifier) and "
        "makes no network request. It re-checks each embedded run's integrity and its "
        "signature under the key the run embeds. Pinned-key checks are in REPORT.md.</p>"
        f'<ul>{rows}</ul><h2 id="verdict">checking...</h2>'
        "<table><thead><tr><th>File</th><th>Verdict</th><th>Integrity</th><th>Signature</th>"
        '</tr></thead><tbody id="results"></tbody></table>'
        '<p><label>Check another .tine file: <input id="pick" type="file" multiple></label></p>'
        f'<script type="module">{page_script(runs)}</script></body></html>\n'
    )


def _cells(row: list[str]) -> str:
    return "| " + " | ".join(" ".join(c.split()).replace("|", "\\|") for c in row) + " |"


def report_rows(summary: dict[str, Any]) -> list[list[str]]:
    return [[c["name"], c["outcome"], c["detail"]] for c in summary["checks"]]


def report_markdown(summary: dict[str, Any]) -> str:
    verdict = "PASS" if summary["ok"] else "FAIL"
    lines = [
        "# Verification report",
        "",
        f"Kit built by tine {summary['tine_version']} from {summary['source']['kind']} "
        f"`{summary['source']['name']}` (sha256 `{summary['source']['sha256']}`).",
        "",
        f"**Verdict at build time: {verdict}.** Re-run every check offline with "
        "`tine audit-kit verify .`, or without opentine: `python -I -S tine-verify.pyz evidence` "
        "and open `verify.html`.",
        "",
        "## Runs",
        "",
        _cells(["Run", "File", "Digest"]),
        _cells(["---", "---", "---"]),
        *(_cells([r["run_id"], r["file"], r["digest"]]) for r in summary["runs"]),
        "",
        "## Checks",
        "",
        _cells(["Check", "Outcome", "Detail"]),
        _cells(["---", "---", "---"]),
        *(_cells(row) for row in report_rows(summary)),
        "",
    ]
    return "\n".join(lines)


def report_html(summary: dict[str, Any]) -> str:
    verdict = "pass" if summary["ok"] else "fail"
    runs = "".join(
        f"<tr><td>{escape(r['run_id'])}</td><td>{escape(r['file'])}</td>"
        f"<td><code>{escape(r['digest'])}</code></td></tr>"
        for r in summary["runs"]
    )
    checks = "".join(
        f'<tr><td>{escape(a)}</td><td class="{escape(b)}">{escape(b)}</td><td>{escape(c)}</td></tr>'
        for a, b, c in report_rows(summary)
    )
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'unsafe-inline'\">"
        f"<title>Verification report</title><style>{_STYLE}</style></head><body>"
        f'<h1>Verification report</h1><p class="{verdict}">Verdict at build time: '
        f"{verdict.upper()}</p><p>tine {escape(summary['tine_version'])}; source "
        f"{escape(summary['source']['kind'])} <code>{escape(summary['source']['name'])}</code>"
        "</p><h2>Runs</h2><table><tr><th>Run</th><th>File</th><th>Digest</th></tr>"
        f"{runs}</table><h2>Checks</h2><table><tr><th>Check</th><th>Outcome</th>"
        f"<th>Detail</th></tr>{checks}</table></body></html>\n"
    )


__all__ = ["embedded", "page_script", "report_html", "report_markdown", "verify_html"]
