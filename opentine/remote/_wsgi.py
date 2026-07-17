"""Small WSGI response helpers shared by the reference transport."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any


def response(
    start_response,
    status: str,
    body: bytes,
    content_type: str,
    headers: Iterable[tuple[str, str]] = (),
):
    start_response(
        status,
        [
            ("Content-Length", str(len(body))),
            ("Content-Type", content_type),
            ("Cache-Control", "no-store"),
            *headers,
        ],
    )
    return [body]


def json_response(
    start_response,
    status: str,
    value: Any,
    headers: Iterable[tuple[str, str]] = (),
):
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return response(start_response, status, body, "application/json", headers)
