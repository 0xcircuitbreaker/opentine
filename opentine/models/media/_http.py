"""Bounded HTTP for media endpoints: one request, a capped body, no redirects.

Media responses are large and untrusted (an image, a minute of audio), so the
body is streamed into a hard cap rather than read whole, and a redirect is never
followed -- the API key would travel with it. A key reaches a host over
cleartext HTTP only under the same rule every adapter follows
(:func:`~opentine.models._endpoint_security.require_key_transport`).
"""

from __future__ import annotations

import json
from typing import Any

from opentine.models._endpoint_security import require_key_transport

#: Largest response body accepted from a media endpoint (an image or audio file).
MAX_MEDIA_BYTES = 64 * 1024 * 1024
#: Largest JSON body (transcripts, image JSON with base64 payloads aside).
MAX_JSON_BYTES = 96 * 1024 * 1024
#: Largest upload accepted for transcription (OpenAI documents 25 MB).
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
DEFAULT_TIMEOUT = 300.0


class MediaError(RuntimeError):
    """A media endpoint refused the request or answered out of bounds."""


async def post(
    url: str,
    api_key: str,
    *,
    json_body: dict[str, Any] | None = None,
    files: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    limit: int | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[bytes, str]:
    """POST and return ``(body, content_type)``; raise :class:`MediaError` on failure."""
    import httpx

    require_key_transport(url, api_key)
    limit = MAX_MEDIA_BYTES if limit is None else limit
    headers = {"Authorization": f"Bearer {api_key}"}
    async with httpx.AsyncClient(
        follow_redirects=False, trust_env=False, timeout=timeout
    ) as client:
        request = client.build_request(
            "POST", url, headers=headers, json=json_body, files=files, data=data
        )
        response = await client.send(request, stream=True)
        try:
            body = bytearray()
            async for chunk in response.aiter_raw():
                body.extend(chunk)
                if len(body) > limit:
                    raise MediaError(f"media response exceeds {limit} bytes")
        finally:
            await response.aclose()
    if response.status_code >= 300:
        raise MediaError(f"media endpoint returned HTTP {response.status_code}")
    encoding = response.headers.get("content-encoding", "identity").lower()
    if encoding not in ("", "identity"):
        raise MediaError("media endpoint sent an encoded body; only identity is accepted")
    return bytes(body), response.headers.get("content-type", "")


def parse_json(body: bytes) -> dict[str, Any]:
    if len(body) > MAX_JSON_BYTES:
        raise MediaError("media JSON response is too large")
    try:
        value = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise MediaError("media endpoint returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise MediaError("media endpoint returned a non-object JSON body")
    return value


__all__ = [
    "DEFAULT_TIMEOUT",
    "MAX_JSON_BYTES",
    "MAX_MEDIA_BYTES",
    "MAX_UPLOAD_BYTES",
    "MediaError",
    "parse_json",
    "post",
]
