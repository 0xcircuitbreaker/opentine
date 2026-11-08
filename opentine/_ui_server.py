"""The ``tine ui`` HTTP server: static viewer assets plus a read-only JSON API.

It binds 127.0.0.1 only, answers GET and HEAD only, and never opens an outbound
connection. The page's Content-Security-Policy allows scripts, styles, workers
and fetches from its own origin and nothing else. Runs are loaded once, lazily,
and cached by id; the JSON is redacted by :mod:`opentine._ui_model`.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

HOST = "127.0.0.1"
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; worker-src 'self'; "
    "connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/verify-browser.js": ("verify-browser.js", "text/javascript; charset=utf-8"),
}


def asset(name: str) -> bytes:
    return resources.files("opentine").joinpath("data", "ui", name).read_bytes()


class Catalog:
    """The runs this server shows: one explicit file, or a runs directory."""

    def __init__(self, paths: list[Path]) -> None:
        self.paths = paths
        self._runs: dict[str, tuple[Path, Any]] | None = None
        self._docs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def runs(self) -> dict[str, tuple[Path, Any]]:
        with self._lock:
            if self._runs is None:
                from opentine.core import Run

                found: dict[str, tuple[Path, Any]] = {}
                for path in self.paths:
                    try:
                        run = Run.load(path)
                    except (OSError, RecursionError, ValueError):
                        continue  # an unreadable artifact is skipped, not served
                    found[run.id] = (path, run)
                self._runs = found
            return self._runs

    def get(self, run_id: str) -> tuple[Path, Any] | None:
        runs = self.runs()
        if run_id in runs:
            return runs[run_id]
        hits = [key for key in runs if key.startswith(run_id)] if len(run_id) >= 4 else []
        return runs[hits[0]] if len(hits) == 1 else None

    def doc(self, run_id: str) -> dict[str, Any] | None:
        from opentine._ui_model import run_doc

        found = self.get(run_id)
        if found is None:
            return None
        run = found[1]
        if run.id not in self._docs:
            self._docs[run.id] = run_doc(run)
        return self._docs[run.id]


def _int(query: dict[str, list[str]], key: str, default: int) -> int:
    try:
        return int(query.get(key, [str(default)])[0])
    except ValueError:
        return default


def api(catalog: Catalog, path: str, query: dict[str, list[str]]) -> tuple[int, Any]:
    from opentine._ui_model import (
        attribution,
        diff_between,
        run_summary,
        step_doc,
        tree_at,
        verification,
    )

    parts = [unquote(p) for p in path.strip("/").split("/")]
    if parts == ["api", "runs"]:
        return 200, [run_summary(run) for _, run in catalog.runs().values()]
    if len(parts) >= 3 and parts[:2] == ["api", "run"]:
        found = catalog.get(parts[2])
        if found is None:
            return 404, {"error": "run not found"}
        artifact, run = found
        if len(parts) == 3:
            return 200, catalog.doc(parts[2])
        last = len(run.steps) - 1
        if len(parts) == 5 and parts[3] == "step" and parts[4].isdigit():
            index = int(parts[4])
            if index > last:
                return 404, {"error": "no such step"}
            return 200, step_doc(index, run.steps[index])
        if parts[3:] == ["verify"]:
            return 200, verification(artifact, run)
        if parts[3:] == ["attribution"]:
            return 200, attribution(run)
        if parts[3:] == ["tree"]:
            return 200, tree_at(run, _int(query, "step", last))
        if parts[3:] == ["diff"]:
            return 200, diff_between(run, _int(query, "a", 0), _int(query, "b", last))
    return 404, {"error": "not found"}


class Handler(BaseHTTPRequestHandler):
    server_version = "tine-ui"
    sys_version = ""
    catalog: Catalog

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return  # quiet: request lines may carry run ids the user did not print

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _host_ok(self) -> bool:
        """Refuse a foreign Host: a DNS-rebinding page must not read the runs."""
        port = self.server.server_address[1]
        host = (self.headers.get("Host") or "").strip().lower()
        return host in {f"127.0.0.1:{port}", f"localhost:{port}"}

    def do_GET(self) -> None:  # noqa: N802
        if not self._host_ok():
            self._send(403, b"forbidden host", "text/plain; charset=utf-8")
            return
        url = urlsplit(self.path)
        if url.path in ASSETS:
            name, ctype = ASSETS[url.path]
            self._send(200, asset(name), ctype)
            return
        if url.path.startswith("/api/"):
            try:
                status, payload = api(self.catalog, url.path, parse_qs(url.query))
            except Exception:  # never a traceback (which may quote run data) on stderr
                status, payload = 500, {"error": "internal error"}
            body = json.dumps(payload, ensure_ascii=True, sort_keys=True).encode("ascii")
            self._send(status, body, "application/json")
            return
        self._send(404, b"not found", "text/plain; charset=utf-8")

    do_HEAD = do_GET  # noqa: N815


def make_server(catalog: Catalog, port: int = 0) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"catalog": catalog})
    server = ThreadingHTTPServer((HOST, port), handler)
    server.daemon_threads = True
    return server


__all__ = ["CSP", "HOST", "Catalog", "api", "asset", "make_server"]
