"""0.48: OTLP/gRPC ingest (``opentine[grpc]``) against the controls of
``docs/security/otlp-grpc-review.md``: size limits before and after
decompression, malformed input, bearer auth."""

from __future__ import annotations

import gzip

import pytest

from opentine import _otlp_fuzz
from opentine._otlp_collect import OtlpCollector
from opentine._otlp_grpc import response

TRACES = "/opentelemetry.proto.collector.trace.v1.TraceService/Export"
LOGS = "/opentelemetry.proto.collector.logs.v1.LogsService/Export"

# --- gRPC ------------------------------------------------------------------- #

grpc = pytest.importorskip("grpc")


@pytest.fixture
def grpc_receiver():
    from opentine._otlp_grpc import start_grpc

    kept: list = []
    collector = OtlpCollector(kept.append, idle=3600)
    collector.kept = kept  # type: ignore[attr-defined]
    servers = []

    def make(**kw):
        server, port = start_grpc(collector, "127.0.0.1", 0, **kw)
        servers.append(server)
        return grpc.insecure_channel(f"127.0.0.1:{port}")

    yield make, collector
    for server in servers:
        server.stop(None)


def _call(channel, method, data, **kw):
    stub = channel.unary_unary(method)
    return stub(data, timeout=30, **kw)


def test_grpc_traces_and_logs_reach_the_collector(grpc_receiver):
    make, collector = grpc_receiver
    channel = make(max_bytes=1 << 20)
    assert _call(channel, TRACES, _otlp_fuzz.traces_seed(2)) == b""
    assert _call(channel, LOGS, _otlp_fuzz.logs_seed(2)) == b""
    assert len(collector.kept) == 1  # the root span ended: the trace is a run
    assert collector.pending() == 2  # the log records wait for their session to idle
    assert response(2, "x") == b"\x0a\x05\x08\x02\x12\x01x"


def test_grpc_refuses_malformed_and_oversized_messages(grpc_receiver):
    make, _ = grpc_receiver
    channel = make(max_bytes=64 * 1024)
    with pytest.raises(grpc.RpcError) as bad:
        _call(channel, TRACES, b"\x0a\xff")
    assert bad.value.code() == grpc.StatusCode.INVALID_ARGUMENT
    with pytest.raises(grpc.RpcError) as big:
        _call(channel, TRACES, b"\x00" * (128 * 1024))
    assert big.value.code() == grpc.StatusCode.RESOURCE_EXHAUSTED


def test_grpc_bounds_the_decompressed_size(grpc_receiver):
    """A gzip bomb: tiny on the wire, past the limit once inflated."""
    make, _ = grpc_receiver
    channel = make(max_bytes=64 * 1024)
    bomb = _otlp_fuzz.traces_seed(1) + b"\x52" + b"\x80\x80\x40" + b"\x00" * (1 << 20)
    assert len(gzip.compress(bomb)) < 8 * 1024
    with pytest.raises(grpc.RpcError) as caught:
        _call(channel, TRACES, bomb, compression=grpc.Compression.Gzip)
    assert caught.value.code() == grpc.StatusCode.RESOURCE_EXHAUSTED


def test_grpc_requires_the_bearer_token(grpc_receiver):
    make, collector = grpc_receiver
    channel = make(token=b"t" * 32)
    with pytest.raises(grpc.RpcError) as caught:
        _call(channel, TRACES, _otlp_fuzz.traces_seed(1))
    assert caught.value.code() == grpc.StatusCode.UNAUTHENTICATED
    with pytest.raises(grpc.RpcError):
        _call(channel, TRACES, b"", metadata=(("authorization", "Bearer " + "u" * 32),))
    good = (("authorization", "Bearer " + "t" * 32),)
    assert _call(channel, TRACES, _otlp_fuzz.traces_seed(1), metadata=good) == b""
    assert len(collector.kept) == 1
