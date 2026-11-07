"""Bounded retry of ``429 Too Many Requests``, honouring ``Retry-After``.

A remote with X15 quota (``tine serve --quota-rate``) answers an empty bucket
with 429 and ``Retry-After``. The client waits that long and retries, at most
``MAX_RETRIES`` times, never longer than ``MAX_WAIT`` seconds at a time and
never past the request's own deadline; after that the 429 surfaces as the usual
``remote returned HTTP 429`` error. A 0.34-era client, which has no retry, gets
that same error on the first 429 -- a clean refusal, not a crash.
"""

from __future__ import annotations

import time
from email.utils import parsedate_to_datetime

import httpx

MAX_RETRIES = 3
MAX_WAIT = 30.0
#: Used when a 429 carries no usable ``Retry-After``.
DEFAULT_WAIT = 1.0


def parse_retry_after(value: str | None, now: float | None = None) -> float | None:
    if value is None:
        return None
    text = value.strip()
    if text.isdigit():
        return float(int(text[:9]))
    try:
        when = parsedate_to_datetime(text).timestamp()
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    return max(0.0, when - (time.time() if now is None else now))


def retry_wait(
    response: httpx.Response, attempt: int, started: float, max_seconds: float
) -> float | None:
    """Seconds to wait before retrying *response*, or None to not retry it."""
    if response.status_code != 429 or attempt >= MAX_RETRIES:
        return None
    wait = parse_retry_after(response.headers.get("retry-after"))
    wait = DEFAULT_WAIT if wait is None else wait
    if wait > MAX_WAIT or time.monotonic() - started + wait >= max_seconds:
        return None
    return wait
