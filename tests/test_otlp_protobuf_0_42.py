"""0.42: OTLP/HTTP protobuf traces, decoded by a stdlib wire reader, fuzzed."""

from __future__ import annotations

import json
import random
import struct
import urllib.error
import urllib.request

import pytest

from opentine import Run
from opentine._otlp_collect import OtlpCollector
from opentine._otlp_http import start
from opentine.cli import main
from opentine.trace._otlp_proto import decode_traces
from opentine.trace._protobuf_wire import WireError, fields, varint
from opentine.trace.importers import otel_genai_events


def _varint(value: int) -> bytes:
    value &= (1 << 64) - 1
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _len(number: int, payload: bytes) -> bytes:
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def _num(number: int, value: int) -> bytes:
    return _varint(number << 3) + _varint(value)


def _fixed64(number: int, value: int) -> bytes:
    return _varint(number << 3 | 1) + struct.pack("<Q", value)


def _any(value) -> bytes:
    if isinstance(value, bool):
        return _num(2, int(value))
    if isinstance(value, int):
        return _num(3, value)
    if isinstance(value, float):
        return _varint(4 << 3 | 1) + struct.pack("<d", value)
    if isinstance(value, list):
        return _len(5, b"".join(_len(1, _any(item)) for item in value))
    return _len(1, str(value).encode())


def _kv(key: str, value) -> bytes:
    return _len(1, key.encode()) + _len(2, _any(value))


def _span(span_id: str, parent: str | None, start: int, attributes: dict) -> bytes:
    body = _len(1, bytes.fromhex("ab" * 16)) + _len(2, bytes.fromhex(span_id))
    if parent:
        body += _len(4, bytes.fromhex(parent))
    body += _len(5, b"chat claude-x") + _num(6, 3)
    body += _fixed64(7, start) + _fixed64(8, start + 2_000_000_000)
    body += b"".join(_len(9, _kv(k, v)) for k, v in attributes.items())
    body += _len(15, _len(2, b"ok") + _num(3, 1))
    return body


ATTRS = {
    "gen_ai.operation.name": "chat",
    "gen_ai.system": "anthropic",
    "gen_ai.request.model": "claude-x",
    "gen_ai.usage.input_tokens": 12,
    "gen_ai.usage.output_tokens": 5,
    "custom.tags": ["a", "b"],
    "custom.ratio": 0.5,
    "custom.flag": True,
}
START = 1_791_000_000 * 1_000_000_000


def _request() -> bytes:
    spans = _len(2, _span("01" * 8, None, START, ATTRS))
    spans += _len(2, _span("02" * 8, "01" * 8, START + 10**9, ATTRS))
    resource = _len(1, _len(1, _kv("service.name", "agent")))
    return _len(1, resource + _len(2, _len(1, _len(1, b"scope")) + spans))


def _json_equivalent() -> dict:
    def attrs(values):
        out = []
        for key, value in values.items():
            if isinstance(value, bool):
                v = {"boolValue": value}
            elif isinstance(value, int):
                v = {"intValue": str(value)}
            elif isinstance(value, float):
                v = {"doubleValue": value}
            elif isinstance(value, list):
                v = {"arrayValue": {"values": [{"stringValue": x} for x in value]}}
            else:
                v = {"stringValue": value}
            out.append({"key": key, "value": v})
        return out

    def span(span_id, parent, start):
        item = {"traceId": "ab" * 16, "spanId": span_id, "name": "chat claude-x", "kind": 3}
        item.update(startTimeUnixNano=str(start), endTimeUnixNano=str(start + 2 * 10**9))
        item.update(attributes=attrs(ATTRS), status={"message": "ok", "code": 1})
        if parent:
            item["parentSpanId"] = parent
        return item

    spans = [span("01" * 8, None, START), span("02" * 8, "01" * 8, START + 10**9)]
    resource = {"attributes": attrs({"service.name": "agent"})}
    return {"resourceSpans": [{"resource": resource, "scopeSpans": [{"spans": spans}]}]}


def test_protobuf_decodes_to_the_otlp_json_shape():
    document = decode_traces(_request())
    (group,) = document["resourceSpans"]
    span = group["scopeSpans"][0]["spans"][1]
    assert span["traceId"] == "ab" * 16 and span["parentSpanId"] == "01" * 8
    assert span["startTimeUnixNano"] == str(START + 10**9)
    assert {"key": "gen_ai.usage.input_tokens", "value": {"intValue": "12"}} in span["attributes"]
    assert group["scopeSpans"][0]["scope"] == {"name": "scope"}


def test_protobuf_and_json_exports_import_alike():
    from_proto = otel_genai_events(decode_traces(_request()))
    from_json = otel_genai_events(_json_equivalent())
    assert [e.to_dict() for e in from_proto] == [e.to_dict() for e in from_json]
    assert from_proto[0].usage["input"] == 12 and from_proto[0].model == "claude-x"


def test_negative_int64_and_unknown_fields():
    value = _len(9, _kv("n", -3)) + _num(99, 7) + _len(98, b"skip")
    span = _len(1, b"\x11" * 16) + _len(2, b"\x22" * 8) + value
    document = decode_traces(_len(1, _len(2, _len(2, span))))
    attribute = document["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"][0]
    assert attribute == {"key": "n", "value": {"intValue": "-3"}}


@pytest.mark.parametrize(
    "data",
    [
        b"\x80" * 11,  # overlong varint
        b"\x0a\x05ab",  # length past the end
        b"\x0b",  # group wire type
        b"\x00\x00",  # field number 0
        b"\x09\x00\x00",  # truncated fixed64
    ],
)
def test_malformed_bytes_are_clean_refusals(data):
    with pytest.raises(WireError):
        decode_traces(data)


def test_nesting_is_capped():
    value = _any("leaf")
    for _ in range(200):
        value = _len(5, _len(1, value))
    kv = _len(1, b"k") + _len(2, value)
    span = _len(1, b"\x11" * 16) + _len(2, b"\x22" * 8) + _len(9, kv)
    with pytest.raises(WireError, match="nesting"):
        decode_traces(_len(1, _len(2, _len(2, span))))


def test_varint_helpers():
    assert varint(_varint(300), 0) == (300, 2)
    assert fields(_num(1, 1) + _len(2, b"x")) == [(1, 0, 1), (2, 2, b"x")]


def test_fuzz_random_and_mutated_bytes_never_crash():
    rng = random.Random(42)
    seed = _request()
    for round_ in range(3000):
        if round_ % 2:
            data = bytearray(seed)
            for _ in range(rng.randint(1, 8)):
                choice = rng.random()
                at = rng.randrange(len(data))
                if choice < 0.5:
                    data[at] = rng.randrange(256)
                elif choice < 0.75:
                    del data[at : at + rng.randint(1, 16)]
                else:
                    data[at:at] = rng.randbytes(rng.randint(1, 16))
            data = bytes(data)
        else:
            data = rng.randbytes(rng.randint(0, 256))
        try:
            document = decode_traces(data)
        except ValueError:
            continue
        try:
            otel_genai_events(document)
        except ValueError:
            pass


@pytest.fixture
def receiver():
    runs = []
    server = start(OtlpCollector(runs.append, idle=3600), "127.0.0.1", 0, max_bytes=64 * 1024)
    yield f"http://127.0.0.1:{server.server_address[1]}", server, runs
    server.stop()


def _post(url, data):
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/x-protobuf")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_serve_accepts_protobuf_traces(receiver):
    url, server, runs = receiver
    assert _post(url + "/v1/traces", _request()) == (200, {})
    server.collector.flush_all()
    assert len(runs) == 1 and len(runs[0].graph.steps) == 2


def test_serve_refuses_bad_protobuf_with_400(receiver):
    url, _, runs = receiver
    status, body = _post(url + "/v1/traces", b"\x0a\x05ab")
    assert status == 400 and "protobuf" in body["message"]
    assert runs == []


def test_import_format_otlp_proto(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "trace.binpb"
    source.write_bytes(_request())
    main(["import", str(source), "--save", "out.tine"])  # auto by extension
    run = Run.load(tmp_path / "out.tine")
    assert len(run.graph.steps) == 2
    main(["import", str(source), "--format", "otlp-proto", "--save", "b.tine"])
    assert len(Run.load(tmp_path / "b.tine").graph.steps) == 2
