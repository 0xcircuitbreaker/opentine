"""The ``tine record`` proxy refuses oversized bodies and foreign Host/Origin."""

from __future__ import annotations

import http.client
import threading

from opentine import _record_proxy as rp


def _send(server, headers, body=b"x", length=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    try:
        conn.putrequest("POST", "/openai/v1/chat/completions", skip_host=True)
        for key, value in headers.items():
            conn.putheader(key, value)
        conn.putheader("Content-Length", str(len(body) if length is None else length))
        conn.endheaders()
        conn.send(body)
        return conn.getresponse().status
    finally:
        conn.close()


def _server(records):
    # Port 9 on loopback: nothing listens, so a forward fails fast with 502.
    server = rp.RecordingServer({"openai": "http://127.0.0.1:9"}, records.append)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_a_foreign_host_is_refused_and_not_captured():
    records = []
    server = _server(records)
    try:
        assert _send(server, {"Host": "rebind.evil.example"}, b"INJECTED") == 403
        assert records == []
    finally:
        server.shutdown()


def test_a_foreign_origin_is_refused_and_not_captured():
    records = []
    server = _server(records)
    try:
        hdrs = {"Host": f"127.0.0.1:{server.port}", "Origin": "http://evil.example"}
        assert _send(server, hdrs, b"INJECTED") == 403
        assert records == []
    finally:
        server.shutdown()


def test_an_oversized_request_body_is_refused_unread():
    records = []
    server = _server(records)
    try:
        hdrs = {"Host": f"127.0.0.1:{server.port}"}
        assert _send(server, hdrs, b"x", length=rp.MAX_CAPTURE + 1) == 413
        assert records == []
    finally:
        server.shutdown()


def test_a_loopback_request_is_still_forwarded_and_captured():
    records = []
    server = _server(records)
    try:
        hdrs = {"Host": f"localhost:{server.port}", "Origin": "http://127.0.0.1"}
        assert _send(server, hdrs, b"{}") == 502
        assert len(records) == 1 and records[0]["request"] == b"{}"
    finally:
        server.shutdown()
