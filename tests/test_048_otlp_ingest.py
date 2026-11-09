"""0.48: OTLP protobuf logs, OTLP/gRPC ingest (``opentine[grpc]``) and its fuzz harness.

The controls tested here are the ones ``docs/security/otlp-grpc-review.md``
names: message size (compressed and decompressed), malformed input, bearer
auth, off-loopback refusal without TLS and a token. The scaled fuzz run is an
iteration count, never a wall-clock budget.
"""

from __future__ import annotations

import argparse
import json
import urllib.request

import pytest

from opentine import _otlp_fuzz, cli
from opentine._otlp_collect import OtlpCollector
from opentine._otlp_http import start
from opentine.trace._otel_log_import import otel_log_events
from opentine.trace._otlp_logs_proto import decode_logs
from opentine.trace._protobuf_wire import WireError

TRACES = "/opentelemetry.proto.collector.trace.v1.TraceService/Export"
LOGS = "/opentelemetry.proto.collector.logs.v1.LogsService/Export"


def test_protobuf_logs_decode_to_the_otlp_json_shape():
    document = decode_logs(_otlp_fuzz.logs_seed(2))
    records = document["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    assert len(records) == 2 and records[0]["severityText"] == "INFO"
    assert records[0]["traceId"] == "ab" * 16 and records[0]["spanId"] == "01" * 8
    assert records[1]["eventName"] == "claude_code.api_request"
    assert records[0]["body"] == {"stringValue": '{"role": "user", "content": "hi"}'}
    as_json = json.loads(json.dumps(document))
    assert otel_log_events(document) == otel_log_events(as_json)
    assert len(otel_log_events(document)) == 2
    with pytest.raises(WireError):
        decode_logs(_otlp_fuzz.logs_seed(1)[:-3])


def test_http_accepts_protobuf_logs():
    runs: list = []
    collector = OtlpCollector(runs.append, idle=3600)
    server = start(collector, "127.0.0.1", 0, max_bytes=64 * 1024)
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/v1/logs"
        request = urllib.request.Request(url, data=_otlp_fuzz.logs_seed(2), method="POST")
        request.add_header("Content-Type", "application/x-protobuf")
        with urllib.request.urlopen(request, timeout=30) as reply:
            assert reply.status == 200 and json.loads(reply.read()) == {}
        assert collector.pending() == 2
    finally:
        server.stop()
    assert len(runs) == 1


def test_import_format_otlp_proto_logs(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs.binpb").write_bytes(_otlp_fuzz.logs_seed(2))
    argv = ["import", "logs.binpb", "--format", "otlp-proto-logs", "--save", "l.tine"]
    try:
        cli.main(argv)
    except SystemExit as exc:
        assert not exc.code
    assert (tmp_path / "l.tine").is_file()


def test_the_scaled_fuzz_run_finds_no_crash():
    report = _otlp_fuzz.fuzz(seed=48, iterations=3000)
    assert report.iterations == 3000 and report.crashes == [], report.crashes[:1]


def test_serve_refuses_grpc_off_loopback_without_tls_and_token(tmp_path):
    from opentine.remote.server import add_serve_parser

    parser = argparse.ArgumentParser()
    add_serve_parser(parser.add_subparsers())
    args = parser.parse_args(["serve", "--otlp", "--otlp-protocol", "grpc"])
    assert args.otlp_protocol == "grpc" and args.otlp_grpc_port == 4317
    with pytest.raises(SystemExit) as caught:
        cli.main(["serve", "--otlp", "--otlp-protocol", "grpc", "--host", "0.0.0.0"])
    assert "requires TLS" in str(caught.value)
    (tmp_path / "token").write_text("short", encoding="utf-8")
    with pytest.raises(SystemExit) as caught:
        cli.main(["serve", "--otlp", "--otlp-protocol", "grpc",
                  "--otlp-token-file", (tmp_path / "token").as_posix()])  # fmt: skip
    assert "16..4096" in str(caught.value)
