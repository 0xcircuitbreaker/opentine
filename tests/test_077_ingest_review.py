"""0.77 red-team review: ways a loop or a hostile client could hide episodes from ingest."""

from __future__ import annotations

import http.client
import json

import pytest

from opentine import _ingest_batch, _ingest_holds, _ingest_http, _ingest_policy, _ingest_verify
from opentine._ingest_policy import IngestError
from opentine.repository import Repo
from tests.key_roles_helpers import (
    isolated_trust_config,  # noqa: F401
    pin_roles,
)
from tests.test_077_ingest import SEED, SEEDS, T0, _codes, _events, _fpr, _key, _set_head

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


@pytest.fixture(name="repo")
def _repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    roles = {"runner": [_fpr("runner")], "policy": [_fpr("policy")],
             "optimizer": [_fpr("optimizer")]}  # fmt: skip
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    assert "stranger" in SEEDS
    return repo


def _policy(repo, rate=0.5, seed=SEED, issued="2027-01-15T08:00:00Z", **kw) -> str:
    doc = _ingest_policy.build("rl", capture=kw.get("capture", []), drop=kw.get("drop", []),
                               rate=rate, seed=seed, issued_at=issued)  # fmt: skip
    return _ingest_policy.record(repo, doc, _key("policy"))


def _resign(repo, oid: str, signer: str, **changes) -> str:
    stored = repo.get(oid).payload()
    claim = stored["value"] | changes
    return _ingest_holds.write(repo, stored["target_id"], claim, _key(signer),
                               previous=claim["previous"], signed_at=claim["at"])  # fmt: skip


def test_batches_signed_by_an_optimizer_or_unpinned_key_fail(repo):
    _policy(repo)
    row = _ingest_batch.append(repo, "rl", _events(20), _key("runner"), at_ms=T0)
    assert _ingest_verify.verify(repo, "rl")["ok"]
    _set_head(repo, _resign(repo, row["id"], "optimizer"))
    assert "ingest.batch-optimizer-key" in _codes(_ingest_verify.verify(repo, "rl"))
    _set_head(repo, _resign(repo, row["id"], "stranger"))
    assert "ingest.batch-role" in _codes(_ingest_verify.verify(repo, "rl"))
    with pytest.raises(IngestError, match="optimizer"):
        _ingest_batch.append(repo, "rl", _events(3), _key("optimizer"), at_ms=T0)


def test_a_captured_event_relabelled_as_rate_dropped_is_detected(repo):
    _policy(repo, rate=0.5)
    row = _ingest_batch.append(repo, "rl", _events(40), _key("runner"), at_ms=T0)
    stored = repo.get(row["id"]).payload()["value"]
    lines = stored["events"].splitlines(keepends=True)
    assert len(lines) >= 2
    hidden = "".join(lines[1:])  # hide the first captured episode, call it a rate drop
    by = {"kind": 0, "rate": row["dropped_by"]["rate"] + 1}
    _set_head(repo, _resign(repo, row["id"], "runner", events=hidden, captured=len(lines) - 1,
                            dropped=row["dropped"] + 1, dropped_by=by))  # fmt: skip
    assert "ingest.sampling-hidden" in _codes(_ingest_verify.verify(repo, "rl"))


def test_switching_back_to_an_older_policy_mid_stream_is_detected(repo):
    old = _policy(repo, rate=0.9, seed="11" * 32, issued="2027-01-15T08:00:00Z")
    _policy(repo, rate=0.9, seed="22" * 32, issued="2027-01-16T08:00:00Z")
    _ingest_batch.append(repo, "rl", _events(10), _key("runner"), at_ms=T0)
    with pytest.raises(IngestError, match="older"):
        _ingest_batch.append(repo, "rl", _events(10), _key("runner"), at_ms=T0, policy_id=old)
    head = _ingest_holds.head(repo, "rl")
    claim = repo.get(head).payload()["value"]
    doc = _ingest_holds.read(repo, old, _ingest_policy.CONVENTION)["claim"]
    forged = _resign(repo, head, "runner", seq=1, previous=head, first_index=10,
                     next_index=20, policy=old, policy_digest=_ingest_policy.digest(doc),
                     events="", captured=0, dropped=10, received=10,
                     dropped_by={"kind": 0, "rate": 10}, at=claim["at"])  # fmt: skip
    _set_head(repo, forged)
    assert "ingest.policy-switch" in _codes(_ingest_verify.verify(repo, "rl"))


def test_a_batch_claiming_more_than_max_events_fails_closed(repo):
    _policy(repo, rate=1.0)
    row = _ingest_batch.append(repo, "rl", _events(5), _key("runner"), at_ms=T0)
    n = _ingest_batch.MAX_EVENTS + 1
    forged = _resign(repo, row["id"], "runner", events="", captured=0, received=n, dropped=n,
                     next_index=n, dropped_by={"kind": n, "rate": 0})  # fmt: skip
    _set_head(repo, forged)
    report = _ingest_verify.verify(repo, "rl")
    assert not report["ok"]
    assert "ingest.counts" in _codes(report)


def test_issued_at_must_be_a_utc_time():
    with pytest.raises(IngestError):
        _ingest_policy.build("rl", capture=[], drop=[], rate=1, seed=SEED, issued_at="9999")


@pytest.mark.parametrize("line", [b'{"kind":"debug","kind":"episode"}',
                                  b'{"kind":"step","x":NaN}', b'{"kind":"step","x":-Infinity}',
                                  b'{"kind":"step","x":1e999}'])  # fmt: skip
def test_duplicate_keys_and_non_finite_numbers_are_refused(line):
    with pytest.raises(IngestError):
        _ingest_batch.parse(line + b"\n")


def _raw(port: int, headers: dict[str, str], body: bytes = b"") -> int:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)  # a hang guard only
    try:
        conn.putrequest("POST", _ingest_http.ROUTE, skip_host=True)
        for k, v in headers.items():
            conn.putheader(k, v)
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        return conn.getresponse().status
    finally:
        conn.close()


def test_browser_and_rebound_hosts_are_refused(repo):
    _policy(repo)
    server = _ingest_http.start(repo, "rl", _key("runner"), clock_ms=lambda: T0)
    try:
        port = server.server_address[1]
        body = _events(2)
        assert _raw(port, {"Host": "evil.example:80"}, body) == 403
        assert _raw(port, {"Host": f"127.0.0.1:{port}", "Origin": "http://evil.example"},
                    body) == 403  # fmt: skip
        assert _ingest_holds.head(repo, "rl") is None
        assert _raw(port, {"Host": f"127.0.0.1:{port}"}, body) == 200
    finally:
        server.stop()


def test_slow_clients_are_bounded(repo):
    _policy(repo)
    server = _ingest_http.start(repo, "rl", _key("runner"), clock_ms=lambda: T0)
    try:
        assert server.timeout_s is not None and server.timeout_s > 0
        assert server.slots._value == _ingest_http.MAX_CLIENTS  # noqa: SLF001
    finally:
        server.stop()


def test_a_client_dripping_its_body_is_dropped_at_the_request_deadline(repo):
    import socket
    import threading

    _policy(repo)
    server = _ingest_http.start(repo, "rl", _key("runner"), clock_ms=lambda: T0)
    now = [0.0]
    server.monotonic = lambda: now[0]
    server.timeout_s = 3600.0  # the per-read socket timeout never fires: only the deadline can
    port = server.server_address[1]
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=60) as sock:
            sock.sendall(f"POST /v1/ingest HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                         "Content-Length: 100000\r\n\r\nx".encode())  # fmt: skip
            # The header was read under the deadline; the server now waits on the body.
            got = threading.Event()
            for _ in range(10_000):
                if server.slots._value < _ingest_http.MAX_CLIENTS:  # noqa: SLF001
                    got.set()
                    break
                threading.Event().wait(0.01)
            assert got.is_set()
            now[0] = server.timeout_s + 1  # the whole-request budget is spent
            # One more drip: the next read sees the deadline and the server drops us.
            # Closing with unread bytes may reset the connection (macOS) instead of
            # a clean EOF; both mean the client was dropped.
            try:
                sock.sendall(b"y")
                assert sock.recv(4096) == b""
            except (ConnectionResetError, BrokenPipeError):
                pass
        for _ in range(10_000):
            if server.slots._value == _ingest_http.MAX_CLIENTS:  # noqa: SLF001
                break
            threading.Event().wait(0.01)
        assert server.slots._value == _ingest_http.MAX_CLIENTS  # noqa: SLF001
    finally:
        server.stop()
