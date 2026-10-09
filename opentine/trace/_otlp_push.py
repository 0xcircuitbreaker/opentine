"""POST an OTLP/JSON document to a collector, bounded like the repository client.

The push used to re-implement its HTTP read and leave out what
``repository/_http`` already enforces: it advertised gzip/deflate/zstd and read a
rejecting collector's reply with ``iter_bytes()``, which decompresses a whole
network chunk before any cap is checked (a 60 KB zstd reply drove the CLI to
2.1 GB), and its 30 s timeout applied per read, so a collector trickling a byte
every few seconds held it forever. Now the request asks for ``identity``, the
reply is read raw (an encoded one is not read at all), and the whole exchange
runs under a wall deadline.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

import httpx

from opentine.repository._http import run_request

TRACES_PATH = "/v1/traces"
CONTENT_TYPE = "application/json"
OTLP_TIMEOUT = 30.0
#: The whole push, connect to last byte.
OTLP_DEADLINE = 120.0
#: How much of a rejecting collector's reply is read back to explain the refusal.
MAX_RECEIPT_BYTES = 4096
MAX_RECEIPT_CHARS = 200


def traces_url(endpoint: str) -> str:
    """The OTLP/HTTP traces URL for a base endpoint, or the endpoint if it is one.

    ``/v1/traces`` joins the *path*: appended to the raw string it landed after a
    query (``?tenant=a/v1/traces``) or a fragment, which is never sent at all.
    """
    parts = urlsplit(endpoint)
    path = parts.path.rstrip("/")
    if not path.endswith(TRACES_PATH):
        path += TRACES_PATH
    return urlunsplit(parts._replace(path=path, fragment=""))


def _detail(response: httpx.Response) -> str:
    """A bounded, single-line excerpt of a rejecting collector's reply."""
    encoding = response.headers.get("content-encoding", "").strip().lower()
    if encoding not in {"", "identity"}:
        return ""  # asked for identity; an encoded body is not decompressed to explain
    body = bytearray()
    # An in-memory transport hands the reply over already read; the network does not.
    chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
    try:
        for chunk in chunks:
            body.extend(chunk)
            if len(body) >= MAX_RECEIPT_BYTES:
                break
    except httpx.HTTPError:
        return ""
    text = bytes(body[:MAX_RECEIPT_BYTES]).decode("utf-8", "replace")
    return " ".join(text.split())[:MAX_RECEIPT_CHARS]


def post(url: str, body: bytes) -> tuple[int, str]:
    """POST *body*; return the status and, for a refusal, why it was refused.

    Raises ``httpx.HTTPError`` / ``httpx.InvalidURL`` when the collector cannot
    be reached, and ``ValueError`` when the exchange outlives ``OTLP_DEADLINE``.
    """
    session = httpx.Client(timeout=OTLP_TIMEOUT, follow_redirects=False, trust_env=False)
    headers = {"Content-Type": CONTENT_TYPE, "Accept-Encoding": "identity"}

    def send() -> tuple[int, str]:
        with session.stream("POST", url, content=body, headers=headers) as response:
            if 200 <= response.status_code < 300:
                return response.status_code, ""
            return response.status_code, _detail(response)

    try:
        return run_request(session, OTLP_DEADLINE, "OTLP push", send)
    finally:
        session.close()
