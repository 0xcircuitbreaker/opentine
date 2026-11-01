"""0.21: ``tine serve --otlp`` -- a live OTLP/HTTP receiver that saves runs."""

from __future__ import annotations

import gzip
import json
import time
import urllib.error
import urllib.request

import pytest

from opentine import cli
from opentine._otlp_collect import OtlpCollector
from opentine._otlp_http import PROTOBUF_HINT, start

MODEL = "claude-opus-5-5"
TRACE = "a" * 32
SECRET = "sk-ant-api03-" + "x" * 40


def _attrs(**values):
    out = []
    for key, value in values.items():
        wrapped = {"intValue": str(value)} if isinstance(value, int) else {"stringValue": value}
        out.append({"key": key, "value": wrapped})
    return out


def _span(span_id, parent=None, trace=TRACE, offset=0, **attributes):
    start_ns = (1_791_000_000 + offset) * 1_000_000_000
    span = {
        "traceId": trace,
        "spanId": span_id,
        "name": "chat",
        "startTimeUnixNano": str(start_ns),
        "endTimeUnixNano": str(start_ns + 1_000_000_000),
        "attributes": _attrs(**attributes),
    }
    if parent:
        span["parentSpanId"] = parent
    return span


def _model_span(span_id, parent, offset, tokens_in, tokens_out, **extra):
    return _span(
        span_id,
        parent,
        offset=offset,
        **{
            "gen_ai.operation.name": "chat",
            "gen_ai.system": "anthropic",
            "gen_ai.request.model": MODEL,
            "gen_ai.usage.input_tokens": tokens_in,
            "gen_ai.usage.output_tokens": tokens_out,
            **extra,
        },
    )


def _traces(*spans):
    return {"resourceSpans": [{"scopeSpans": [{"spans": list(spans)}]}]}


def _logs(*records):
    return {"resourceLogs": [{"scopeLogs": [{"logRecords": list(records)}]}]}


def _log(offset, session, **attributes):
    nanos = (1_791_000_000 + offset) * 1_000_000_000
    fields = {"event.name": "api_request", "session.id": session, "model": MODEL, **attributes}
    return {"timeUnixNano": str(nanos), "attributes": _attrs(**fields)}


@pytest.fixture
def receiver():
    runs = []
    collector = OtlpCollector(runs.append, idle=3600)
    server = start(collector, "127.0.0.1", 0, max_bytes=64 * 1024)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    yield url, server, collector, runs
    server.stop()


def _post(url, body, content_type="application/json", headers=None):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", content_type)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _model_steps(run):
    # An invoke_agent root imports as an (unbilled) agent model step; keep the calls.
    return [step for step in run.steps if step.kind.value == "model" and step.model_info]


def test_root_span_end_saves_the_trace_as_one_run(receiver):
    url, _, collector, runs = receiver
    child = _model_span("b1", "r1", 1, 100, 20, **{"gen_ai.prompt": f"key {SECRET}"})
    assert _post(url + "/v1/traces", _traces(child)) == (200, {})
    assert runs == [] and collector.pending() == 1
    second = _model_span("b2", "r1", 2, 50, 10)
    root = _span("r1", offset=0, **{"gen_ai.operation.name": "invoke_agent"})
    assert _post(url + "/v1/traces", _traces(second, root)) == (200, {})
    assert len(runs) == 1 and collector.pending() == 0
    models = _model_steps(runs[0])
    assert len(models) == 2
    assert {step.model_info for step in models} == {MODEL}
    usage = sorted((step.usage["input"], step.usage["output"]) for step in models)
    assert usage == [(50, 10), (100, 20)]
    assert SECRET not in json.dumps(runs[0].to_dict(), default=str)


def test_traces_are_grouped_by_trace_id(receiver):
    url, _, _, runs = receiver
    other = "b" * 32
    body = _traces(
        _model_span("x1", None, 1, 1, 1),
        {**_model_span("y1", None, 1, 2, 2), "traceId": other},
    )
    assert _post(url + "/v1/traces", body)[0] == 200
    assert len(runs) == 2
    assert sorted(len(_model_steps(run)) for run in runs) == [1, 1]


def test_span_without_trace_id_is_a_partial_success(receiver):
    url, _, _, _ = receiver
    span = _model_span("z1", None, 1, 1, 1)
    del span["traceId"]
    status, body = _post(url + "/v1/traces", _traces(span))
    assert status == 200 and body["partialSuccess"]["rejectedSpans"] == 1


def test_logs_endpoint_groups_by_session_and_saves_on_stop(receiver):
    url, server, collector, runs = receiver
    body = _logs(_log(1, "s1", input_tokens=10, output_tokens=5), _log(2, "s1", input_tokens=7))
    assert _post(url + "/v1/logs", body) == (200, {})
    assert runs == [] and collector.pending() == 2
    server.stop()
    assert len(runs) == 1
    models = _model_steps(runs[0])
    assert [step.usage["input"] for step in models] == [10, 7]
    assert models[0].model_info == MODEL


def test_stop_flushes_open_traces(receiver):
    url, server, _, runs = receiver
    _post(url + "/v1/traces", _traces(_model_span("c1", "never-ends", 1, 3, 4)))
    assert runs == []
    server.stop()
    assert len(runs) == 1 and _model_steps(runs[0])[0].usage["output"] == 4


def test_idle_timeout_flushes():
    runs = []
    collector = OtlpCollector(runs.append, idle=0.1)
    server = start(collector, "127.0.0.1", 0)
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/v1/traces"
        _post(url, _traces(_model_span("d1", "open", 1, 1, 1)))
        deadline = time.monotonic() + 10
        while not runs and time.monotonic() < deadline:
            time.sleep(0.05)
        assert len(runs) == 1
    finally:
        server.stop()


def test_gzip_body_is_accepted(receiver):
    url, _, _, runs = receiver
    raw = gzip.compress(json.dumps(_traces(_model_span("g1", None, 1, 1, 1))).encode())
    assert _post(url + "/v1/traces", raw, headers={"Content-Encoding": "gzip"})[0] == 200
    assert len(runs) == 1


def test_refusals(receiver):
    url, _, collector, runs = receiver
    status, body = _post(url + "/v1/traces", b"\x0a\x00", "application/x-protobuf")
    assert status == 415 and body["message"] == PROTOBUF_HINT
    assert _post(url + "/v1/traces", b"x", "text/plain")[0] == 415
    assert _post(url + "/v1/traces", b"{not json")[0] == 400
    assert _post(url + "/v1/metrics", {})[0] == 404
    huge = {"pad": "x" * (128 * 1024)}
    assert _post(url + "/v1/traces", huge)[0] == 413
    bomb = gzip.compress(b'{"pad": "' + b"x" * (1024 * 1024) + b'"}')
    assert _post(url + "/v1/traces", bomb, headers={"Content-Encoding": "gzip"})[0] == 413
    assert runs == [] and collector.pending() == 0


def test_serve_otlp_flags_parse_and_refuse_non_loopback():
    import argparse

    from opentine.remote.server import add_serve_parser

    parser = argparse.ArgumentParser()
    add_serve_parser(parser.add_subparsers())
    args = parser.parse_args(["serve", "--otlp", "--otlp-port", "0", "--otlp-idle", "5"])
    assert args.otlp and args.otlp_port == 0 and args.otlp_idle == 5
    with pytest.raises(SystemExit) as exc:
        cli.main(["serve", "--otlp", "--host", "0.0.0.0"])
    assert "loopback" in str(exc.value)
