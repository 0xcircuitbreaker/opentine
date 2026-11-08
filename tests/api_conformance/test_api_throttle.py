"""API v1 conformance: repeated failed authentication is a 429 with Retry-After.

It locks this client out for a while, so it runs against its own loopback server
unless ``TINE_API_THROTTLE=1`` points it at the target under test.
"""

from __future__ import annotations

import os

from tests.api_conformance.conftest import _local_target


def test_failed_authentications_back_off_with_429_and_retry_after(api, tmp_path):
    target, httpd = (api, None)
    if not (os.environ.get("TINE_API_BASE_URL") and os.environ.get("TINE_API_THROTTLE") == "1"):
        target, httpd = _local_target(tmp_path / "throttle")
    try:
        statuses = []
        for _ in range(12):
            reply = target.call("GET", target.tenant_path("refs"), token="wrong-token")
            statuses.append(reply.status)
            if reply.status == 429:
                assert int(reply.headers["Retry-After"]) >= 1
                assert target.schema_errors("Error", reply.json()) == []
                break
        assert statuses[0] == 401 and statuses[-1] == 429, statuses
    finally:
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
