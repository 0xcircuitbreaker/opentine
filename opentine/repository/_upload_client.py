"""Bounded resumable pack-upload state machine for the repository client."""

from __future__ import annotations

import hashlib
import re
from typing import Any

import httpx

from opentine.repository._http import read_json, request_json, run_request
from opentine.repository.pack import minimum_upload_chunk

_UPLOAD_ID = re.compile(r"[0-9a-f]{32}")


def _offset(state: dict[str, Any], default: int = -1) -> int:
    raw = state.get("offset", default)
    if type(raw) is not int:
        raise ValueError("remote returned an invalid upload offset")
    return raw


def _head_offset(
    client: httpx.Client, upload: str, *, current: int, size: int, timeout: float
) -> int | None:
    def operation() -> int | None:
        with client.stream("HEAD", upload) as response:
            if response.status_code == 404:
                return None
            response.raise_for_status()
            raw = response.headers.get("upload-offset")
            if raw is None:
                raw = str(_offset(read_json(response, max_seconds=timeout)))
            try:
                recovered = int(raw)
            except ValueError as exc:
                raise ValueError("remote returned an invalid upload offset") from exc
            if str(recovered) != raw.strip() or not current <= recovered <= size:
                raise ValueError("remote returned an invalid recovery offset")
            return recovered

    return run_request(client, timeout, "upload recovery", operation)


def upload(
    client: httpx.Client,
    endpoint: str,
    data: bytes,
    *,
    chunk_size: int,
    timeout: float = 30,
    max_recoveries: int = 3,
) -> dict[str, Any]:
    if chunk_size < minimum_upload_chunk(len(data)):
        raise ValueError("upload chunk size is below the safe resumable minimum")
    if type(max_recoveries) is not int or max_recoveries < 0:
        raise ValueError("upload recovery limit must be a non-negative integer")
    _, state = request_json(
        client,
        "POST",
        endpoint,
        allowed=(200, 201),
        max_seconds=timeout,
        json={"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
    )
    upload_id = state.get("upload_id")
    if not isinstance(upload_id, str) or not _UPLOAD_ID.fullmatch(upload_id):
        raise ValueError("remote returned an invalid upload id")
    upload_url = endpoint + "/" + upload_id
    offset = _offset(state, 0)
    if not 0 <= offset <= len(data):
        raise ValueError("remote returned an invalid upload offset")
    chunks = (len(data) + chunk_size - 1) // chunk_size
    max_iterations = chunks + max_recoveries + 4
    recoveries = 0
    iterations = 0
    while offset < len(data):
        iterations += 1
        if iterations > max_iterations:
            raise ValueError("remote upload did not converge")
        chunk = data[offset : offset + chunk_size]
        try:
            status, state = request_json(
                client,
                "PATCH",
                upload_url,
                allowed=(200, 201, 409),
                max_seconds=timeout,
                content=chunk,
                headers={"Upload-Offset": str(offset)},
            )
        except httpx.RequestError:
            recoveries += 1
            if recoveries > max_recoveries:
                raise
            recovered = _head_offset(
                client, upload_url, current=offset, size=len(data), timeout=timeout
            )
            if recovered is None:
                raise ValueError("remote lost resumable upload state after a transport failure")
            offset = recovered
            continue
        next_offset = _offset(state)
        if not offset < next_offset <= len(data):
            raise ValueError("remote upload offset did not advance")
        if status != 409 and next_offset != offset + len(chunk):
            raise ValueError("remote acknowledged an invalid upload length")
        offset = next_offset
    return state
