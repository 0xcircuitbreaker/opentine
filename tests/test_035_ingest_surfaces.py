"""0.35: ingest surfaces refuse rebinding, hostile shapes and bad lengths."""

from __future__ import annotations

import http.client
import json
import random
import socket
import threading

import pytest

from opentine import _codec, _record_proxy
from opentine._otlp_collect import OtlpCollector
from opentine._otlp_http import MAX_ATTRIBUTES, MAX_ITEMS, _Refused, check_limits, start


@pytest.fixture
def otlp():
    collector = OtlpCollector(lambda run: None, idle=3600)
    server = start(collector, "127.0.0.1", 0, max_bytes=1 << 20)
    yield server.server_address[1]
    server.stop()


def _post(port, body, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    conn.request(
        "POST",
        "/v1/traces",
        body=data,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    response = conn.getresponse()
    status, payload = response.status, json.loads(response.read())
    conn.close()
    return status, payload


@pytest.mark.parametrize("host", ["evil.example:4318", "attacker.test", "127.0.0.1.nip.io"])
def test_a_rebound_host_name_is_refused(otlp, host):
    assert _post(otlp, {}, {"Host": host})[0] == 403


@pytest.mark.parametrize(
    "host", ["127.0.0.1:4318", "localhost", "[::1]:4318", "LOCALHOST:1", "localhost.:4318"]
)
def test_loopback_host_names_are_accepted(otlp, host):
    assert _post(otlp, {}, {"Host": host}) == (200, {})


def test_a_browser_origin_is_refused(otlp):
    assert _post(otlp, {}, {"Origin": "http://127.0.0.1"})[0] == 403


@pytest.mark.parametrize("body", [b"5", b"-1", b"true", b"null", b'"x"', b"[1, 2]", b"[[]]"])
def test_a_scalar_or_array_body_is_a_400_not_a_reset(otlp, body):
    assert _post(otlp, body)[0] == 400


def test_too_many_spans_are_refused():
    spans = [{"traceId": "a" * 32, "spanId": "b"}] * (MAX_ITEMS + 1)
    with pytest.raises(_Refused) as caught:
        check_limits({"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]})
    assert caught.value.status == 413


def test_too_many_attributes_are_refused(otlp):
    attrs = [{"key": str(i), "value": {"intValue": "1"}} for i in range(MAX_ATTRIBUTES + 1)]
    span = {"traceId": "a" * 32, "spanId": "b", "attributes": attrs}
    assert _post(otlp, {"resourceSpans": [{"scopeSpans": [{"spans": [span]}]}]})[0] == 413


KEYS = (
    "resourceSpans scopeSpans spans attributes traceId spanId parentSpanId resource key "
    "value stringValue intValue startTimeUnixNano endTimeUnixNano events name kvlistValue "
    "arrayValue values"
).split()
ATOMS = [0, -1, 1.5, True, None, "", "x", [], {}, "a" * 32]


def _fuzz_body(rng):
    def node(depth):
        roll = rng.random()
        if depth > 5 or roll < 0.3:
            return rng.choice(ATOMS)
        if roll < 0.55:
            return [node(depth + 1) for _ in range(rng.randint(0, 3))]
        return {rng.choice(KEYS): node(depth + 1) for _ in range(rng.randint(0, 4))}

    document = node(0) if rng.random() < 0.3 else {"resourceSpans": node(1)}
    data = json.dumps(document).encode()
    if rng.random() < 0.1:
        cut = rng.randrange(len(data))
        data = data[:cut] + bytes([rng.randrange(256)]) + data[cut + 1 :]
    return data


def test_fuzzed_bodies_never_crash_the_receiver(otlp):
    rng = random.Random(35)
    statuses = {_post(otlp, _fuzz_body(rng))[0] for _ in range(2000)}
    assert statuses <= {200, 400, 413}


def test_record_proxy_refuses_a_negative_content_length():
    server = _record_proxy.RecordingServer({}, lambda record: None)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with socket.create_connection(server.server_address, timeout=5) as conn:
            conn.sendall(
                b"POST /openai/v1/chat HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: -1\r\n\r\n"
            )
            # Before the fix the handler read to EOF and never answered.
            reply = conn.recv(64)
        assert reply.split(b" ")[1] == b"400"
    finally:
        server.shutdown()
        server.server_close()


def test_a_body_compressed_past_1000_to_1_is_readable():
    if _codec._zstd() is None:
        pytest.skip("zstd is not installed")
    raw = b"GET /healthz 200 OK\n" * 500_000
    frame = _codec.compress_frame(raw, "zstd")
    assert len(raw) > len(frame) * _codec.MAX_RATIO
    stored = _codec.MAGIC + bytes([_codec.ZSTD]) + _codec._uvarint(len(raw)) + frame
    assert _codec.unwrap(stored, limit=64 << 20) == raw


def test_the_read_ratio_still_bounds_declared_sizes():
    big = _codec.MAGIC + bytes([_codec.ZLIB]) + _codec._uvarint(_codec.READ_RATIO_BYTES + 1)
    with pytest.raises(_codec.CodecError, match="ratio"):
        _codec.unwrap(big + b"x" * 100, limit=1 << 40)
    small = _codec.MAGIC + bytes([_codec.ZLIB]) + _codec._uvarint(10**6) + b"x"
    with pytest.raises(_codec.CodecError, match="ratio"):
        _codec.unwrap(small, limit=1 << 40)


def test_existing_wrapped_bodies_still_read():
    raw = json.dumps({"k": list(range(5000))}).encode()
    wrapped = _codec.wrap(raw, "zlib")
    assert wrapped is not None and _codec.unwrap(wrapped, limit=1 << 30) == raw
