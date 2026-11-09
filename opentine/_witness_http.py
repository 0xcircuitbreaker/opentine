"""The C2SP tlog-witness HTTP protocol (0.45): ``POST /add-checkpoint``.

https://c2sp.org/tlog-witness. A request body is::

    old <size the client believes the witness last saw>
    <base64 consistency proof hash>      (zero to 63 lines)

    <signed-note checkpoint>

The witness answers ``200`` with its ``cosignature/v1`` line(s) only, ``409``
with ``text/x.tlog.size`` naming the size it really holds when ``old`` is
wrong, ``404`` for a log origin it does not witness, ``403`` when the log's
signature does not verify, ``422`` when the proof does not show consistency
(a fork or rollback: the split-view refusal) and ``400`` for a malformed body.
The decisions themselves are :func:`_witness.witness`; this module is wire only.

0.47 (``_witness_ops``): ``GET /health``, ``GET /keys``, a per-client rate
limit (``429`` with ``Retry-After``) and several cosigning keys for rotation.
The client (:func:`submit`) starts with ``old 0`` (or a caller's guess), and on
``409`` builds the consistency proof from a local tile mirror and retries once.
"""

from __future__ import annotations

import base64
import json
import math
import urllib.error
import urllib.request
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from opentine import _witness
from opentine.repository import _tlog, _tlog_note, _tlog_proof

MAX_BODY = 1 << 16
MAX_PROOF_LINES = 63
SIZE_TYPE = "text/x.tlog.size"
JSON = "application/json"


class WitnessHTTPError(ValueError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"{status}: {message}")
        self.status = status


def encode_request(old: int, proof: list[bytes], note: bytes) -> bytes:
    lines = [f"old {old}"] + [base64.b64encode(h).decode() for h in proof]
    return ("\n".join(lines) + "\n\n").encode() + note


def parse_request(body: bytes) -> tuple[int, list[bytes], bytes]:
    head, sep, note = body.partition(b"\n\n")
    lines = head.decode("ascii", "replace").split("\n")
    if not sep or not lines[0].startswith("old ") or len(lines) - 1 > MAX_PROOF_LINES:
        raise WitnessHTTPError(400, "malformed add-checkpoint request")
    text = lines[0][4:]
    if not text.isdigit() or str(int(text)) != text:
        raise WitnessHTTPError(400, "malformed old size")
    try:
        proof = [base64.b64decode(line, validate=True) for line in lines[1:]]
    except ValueError as exc:
        raise WitnessHTTPError(400, "proof line is not base64") from exc
    if any(len(h) != 32 for h in proof):
        raise WitnessHTTPError(400, "proof hash is not 32 bytes")
    return int(text), proof, note


def _origin(note: bytes) -> str:
    return note.split(b"\n", 1)[0].decode("utf-8", "replace")


def stored_size(state: Path, origin: str, vkey: str) -> int:
    path = _witness._state(state, origin)
    if not path.exists():
        return 0
    return _tlog_note.open_checkpoint(path.read_bytes(), vkey)[1]


def add_checkpoint(
    body: bytes, logs: dict[str, str], private: Any, name: str, state: Path
) -> bytes:
    """The cosignature line(s) for a request body, or WitnessHTTPError."""
    old, proof, note = parse_request(body)
    vkey = logs.get(_origin(note))
    if vkey is None:
        raise WitnessHTTPError(404, "unknown log")
    try:
        _tlog_note.open_checkpoint(note, vkey)
    except _tlog.LogError as exc:
        raise WitnessHTTPError(403, str(exc)) from exc
    held = stored_size(state, _origin(note), vkey)
    if old != held:
        raise WitnessHTTPError(409, str(held))
    try:
        result = _witness.witness(note, vkey, private, name, state, proof=proof)
    except _tlog.LogError as exc:
        raise WitnessHTTPError(422, str(exc)) from exc
    full = result["checkpoint"].encode("utf-8")
    base = note if note.endswith(b"\n") else note + b"\n"
    return full[len(base) :]


def make_server(
    address: tuple[str, int], logs: dict[str, str], private: Any, name: str, state: Path,
    *, operator: Any = None,
) -> ThreadingHTTPServer:  # fmt: skip
    from opentine._witness_ops import Operator

    keys = list(private) if isinstance(private, list | tuple) else [private]
    ops = operator or Operator(keys, name, logs, state, rate_limit=0)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:  # quiet by default
            return

        def _send(self, status: int, body: bytes, kind: str = "text/plain", **extra) -> None:
            self.send_response(status)
            self.send_header("Content-Type", kind)
            for header, value in extra.items():
                self.send_header(header.replace("_", "-"), value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            if self.path == "/health":
                status, body = ops.health()
                return self._send(status, json.dumps(body, sort_keys=True).encode(), JSON)
            if self.path == "/keys":
                return self._send(200, "".join(v + "\n" for v in ops.vkeys()).encode())
            self._send(404, b"not found\n")

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            if self.path != "/add-checkpoint":
                return self._send(404, b"not found\n")
            wait = ops.limiter.allow(str(self.client_address[0]))
            if wait:
                ops.count("429")
                return self._send(429, b"rate limited\n", Retry_After=str(math.ceil(wait)))
            text = self.headers.get("Content-Length") or "0"
            length = int(text) if text.isdigit() else 0
            if not 0 < length <= MAX_BODY:
                return self._send(400, b"bad length\n")
            try:
                lines = add_checkpoint(self.rfile.read(length), logs, keys, name, state)
            except WitnessHTTPError as exc:
                ops.count(str(exc.status))
                kind = SIZE_TYPE if exc.status == 409 else "text/plain"
                text = str(exc).split(": ", 1)[1]
                return self._send(exc.status, (text + "\n").encode(), kind)
            except (OSError, ValueError):  # no local paths or state details on the wire
                ops.count("500")
                return self._send(500, b"internal error\n")
            ops.count("200")
            self._send(200, lines)

    return ThreadingHTTPServer(address, Handler)


def _post(url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(url.rstrip("/") + "/add-checkpoint", data=body, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, response.read(MAX_BODY)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY)


MAX_COSIGNATURE_LINES = 4


def _cosignature_lines(body: bytes) -> bytes:
    """A witness's 200 body, only if it is a few well-formed signature lines.

    The lines are appended to the caller's note verbatim, so a hostile or broken
    witness must not be able to inject a blank line, a body or dozens of lines
    that would make the whole cosigned checkpoint unparseable for every verifier.
    """
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WitnessHTTPError(502, "cosignature is not UTF-8") from exc
    lines = text.split("\n")
    if not text.endswith("\n") or not 0 < len(lines) - 1 <= MAX_COSIGNATURE_LINES:
        raise WitnessHTTPError(502, "malformed cosignature response")
    for line in lines[:-1]:
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != "\u2014" or not parts[1]:
            raise WitnessHTTPError(502, "malformed cosignature line")
        try:
            base64.b64decode(parts[2], validate=True)
        except ValueError as exc:
            raise WitnessHTTPError(502, "cosignature is not base64") from exc
    return body


def submit(
    url: str,
    note: bytes,
    *,
    proof_for: Callable[[int], list[bytes]],
    old: int = 0,
    timeout: float = 10.0,
) -> bytes:
    """Ask the witness at ``url`` to cosign ``note``; return its cosignature lines."""
    for attempt in range(2):
        proof = proof_for(old) if old else []
        status, body = _post(url, encode_request(old, proof, note), timeout)
        if status == 200:
            return _cosignature_lines(body)
        if status == 409 and attempt == 0:
            text = body.decode("ascii", "replace").strip()
            if text.isdigit():
                old = int(text)
                continue
        raise WitnessHTTPError(status, body.decode("utf-8", "replace").strip() or "refused")
    raise WitnessHTTPError(409, "witness size changed during the request")


def tile_proofs(tiles: Path, size: int) -> Callable[[int], list[bytes]]:
    def proof_for(old: int) -> list[bytes]:
        hashes = _tlog_proof.Hashes(size, lambda rel: _tlog._read(tiles, rel))
        return _tlog_proof.consistency_proof(hashes, old, size)

    return proof_for


def gather(urls: list[str], note: bytes, tiles: Path | None, **kwargs: Any) -> tuple[bytes, dict]:
    """``note`` with every reachable witness's cosignature added, plus per-URL errors."""
    try:
        size = int(note.split(b"\n")[1])
    except (IndexError, ValueError) as exc:
        raise _tlog.LogError("checkpoint is not a signed note") from exc
    proof_for = tile_proofs(tiles, size) if tiles else (lambda _old: [])
    out = note if note.endswith(b"\n") else note + b"\n"
    errors: dict[str, str] = {}
    for url in urls:
        try:
            out += submit(url, note, proof_for=proof_for, **kwargs)
        except (OSError, WitnessHTTPError) as exc:
            errors[url] = str(exc)
    return out, errors


__all__ = ["add_checkpoint", "gather", "make_server", "parse_request", "submit"]
