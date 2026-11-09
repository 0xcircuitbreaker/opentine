"""0.47: ``tine witness serve`` for operators (health, keys, rotation, rate limits, restarts)."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _witness_http
from opentine._witness_ops import Operator, RateLimiter
from opentine.repository import _tlog_cosign, _tlog_note

LOG = "example.com/log"
NAME = "w.example"


def _log(root: Path, n: int, start: int = 0) -> bytes:
    for i in range(start, n):
        _tlog_note.append(root, LOG, lambda _e, i=i: f"entry {i}".encode())
    return (root / "checkpoint").read_bytes()


def _opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _get(url: str) -> tuple[int, bytes, dict]:
    try:
        with _opener().open(url, timeout=10) as reply:
            return reply.status, reply.read(), dict(reply.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def _post(url: str, body: bytes) -> tuple[int, bytes, dict]:
    request = urllib.request.Request(url + "/add-checkpoint", data=body, method="POST")
    try:
        with _opener().open(request, timeout=10) as reply:
            return reply.status, reply.read(), dict(reply.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


class _Running:
    def __init__(self, keys, logs, state, rate_limit=0):
        self.operator = Operator(keys, NAME, logs, state, rate_limit=rate_limit)
        self.server = _witness_http.make_server(("127.0.0.1", 0), logs, keys, NAME, state,
                                                operator=self.operator)  # fmt: skip
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()


def test_two_keys_both_cosign_and_keys_lists_them_current_first(tmp_path):
    root = tmp_path / "log"
    note = _log(root, 3)
    logs = {LOG: _tlog_note.stored_vkey(root)}
    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    vkeys = [_tlog_cosign.witness_vkey(NAME, k.public_key().public_bytes_raw()) for k in (old, new)]
    with _Running([old, new], logs, tmp_path / "state") as running:
        status, body, _ = _get(running.url + "/keys")
        assert status == 200 and body.decode().splitlines() == vkeys
        status, lines, _ = _post(running.url, _witness_http.encode_request(0, [], note))
        assert status == 200 and len(lines.decode().splitlines()) == 2
    cosigned = note + lines
    for vkey in vkeys:  # a verifier pinning either key during the rotation accepts it
        assert _tlog_cosign.cosigners(cosigned, [vkey]) != {}


def test_health_reports_sizes_and_survives_a_restart(tmp_path):
    root = tmp_path / "log"
    note = _log(root, 3)
    logs, key, state = (
        {LOG: _tlog_note.stored_vkey(root)},
        Ed25519PrivateKey.generate(),
        tmp_path / "s",
    )
    with _Running([key], logs, state) as running:
        status, body, _ = _get(running.url + "/health")
        health = json.loads(body)
        assert status == 200 and health["status"] == "ok" and health["logs"] == {LOG: 0}
        assert _post(running.url, _witness_http.encode_request(0, [], note))[0] == 200
        health = json.loads(_get(running.url + "/health")[1])
        assert health["logs"] == {LOG: 3} and health["requests"] == {"200": 1}
        assert tmp_path.as_posix() not in json.dumps(health)
    newer = _log(root, 5, start=3)
    with _Running([key], logs, state) as running:  # a restart remembers what it cosigned
        status, body, headers = _post(running.url, _witness_http.encode_request(0, [], newer))
        assert status == 409 and body.strip() == b"3"
        assert headers["Content-Type"] == _witness_http.SIZE_TYPE


def test_an_unwritable_state_directory_is_degraded(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    operator = Operator([Ed25519PrivateKey.generate()], NAME, {}, blocker / "state")
    status, body = operator.health()
    assert status == 503 and body["status"] == "degraded"


def test_the_rate_limit_is_a_token_bucket_per_client():
    now = [0.0]
    limiter = RateLimiter(2, clock=lambda: now[0])
    assert limiter.allow("a") == 0 and limiter.allow("a") == 0
    assert limiter.allow("a") > 0 and limiter.allow("b") == 0  # one client cannot starve another
    now[0] += 30.0  # half a minute refills one token at 2 a minute
    assert limiter.allow("a") == 0 and limiter.allow("a") > 0
    assert RateLimiter(0).allow("a") == 0


def test_an_empty_bucket_is_429_with_retry_after(tmp_path):
    root = tmp_path / "log"
    note = _log(root, 2)
    logs = {LOG: _tlog_note.stored_vkey(root)}
    with _Running([Ed25519PrivateKey.generate()], logs, tmp_path / "s", rate_limit=1) as running:
        assert _post(running.url, _witness_http.encode_request(0, [], note))[0] == 200
        status, _body, headers = _post(running.url, _witness_http.encode_request(2, [], note))
        assert status == 429 and int(headers["Retry-After"]) >= 1
        assert _get(running.url + "/health")[0] == 200  # health is never rate limited


def test_the_cli_serves_every_key(tmp_path):
    from opentine._signing_keys import generate_ed25519

    paths = []
    for name in ("a", "b"):
        path = tmp_path / f"{name}.key"
        path.write_text(generate_ed25519()[0] + "\n")
        path.chmod(0o600)
        paths.append(path.as_posix())
    root = tmp_path / "log"
    _log(root, 1)
    argv = [sys.executable, "-c", "from opentine.cli import main; main()", "witness", "serve",
            "--key", paths[0], "--key", paths[1], "--name", NAME, "--rate-limit", "5",
            "--log-vkey", _tlog_note.stored_vkey(root),
            "--state", (tmp_path / "state").as_posix()]  # fmt: skip
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True)
    try:
        line = process.stdout.readline().strip()
        assert line.startswith("listening on http://127.0.0.1:"), line
        url = line.split(" ", 2)[2]
        vkeys = _get(url + "/keys")[1].decode().splitlines()
        assert len(vkeys) == 2 and json.loads(_get(url + "/health")[1])["keys"] == vkeys
    finally:
        process.terminate()
        process.wait(timeout=10)
        process.stdout.close()
