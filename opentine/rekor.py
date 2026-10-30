"""Upload a DSSE envelope to a Rekor v1 transparency log; return its receipt.

``upload_dsse`` POSTs a ``dsse`` 0.0.1 entry (the envelope plus the PEM key or
certificate that verifies it) to ``/api/v1/log/entries`` and converts the
response into a Sigstore bundle ``TransparencyLogEntry``. Nothing here trusts
the response: the caller runs :func:`opentine.sigstore_bundle.check_entry`
against a Rekor public key it obtained out of band, e.g.::

    curl https://rekor.sigstore.dev/api/v1/log/publicKey > rekor.pub

HTTP goes through :func:`post_json` -- HTTPS only, no redirects, no proxy
environment, a bounded body. Tests swap ``TRANSPORT`` for an
``httpx.MockTransport``; nothing in the test suite reaches a real log.
"""

from __future__ import annotations

import base64
import json
from typing import Any

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
MAX_RESPONSE_BYTES = 1 << 20
TIMEOUT_SECONDS = 30.0
#: ``httpx`` transport override for tests (``httpx.MockTransport``); ``None`` is the network.
TRANSPORT: Any = None

__all__ = [
    "DEFAULT_REKOR_URL",
    "SigstoreHTTPError",
    "entry_from_response",
    "post_json",
    "request_json",
    "upload_dsse",
]


class SigstoreHTTPError(ValueError):
    """A Rekor/Fulcio/token request failed; the message never carries a credential."""


def _scrub(text: str, secrets: tuple[str, ...]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def request_json(
    method: str,
    url: str,
    *,
    body: Any = None,
    headers: dict[str, str] | None = None,
    secrets: tuple[str, ...] = (),
) -> Any:
    """One bounded JSON request; errors are scrubbed of every string in *secrets*."""
    import httpx

    if not isinstance(url, str) or not url.startswith("https://"):
        raise SigstoreHTTPError("Sigstore services must be reached over https://")
    try:
        with httpx.Client(
            transport=TRANSPORT, timeout=TIMEOUT_SECONDS, follow_redirects=False, trust_env=False
        ) as client:
            with client.stream(
                method, url, json=body, headers={"Accept": "application/json", **(headers or {})}
            ) as response:
                raw = b""
                for chunk in response.iter_bytes():
                    raw += chunk
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise SigstoreHTTPError(f"{url}: response exceeds {MAX_RESPONSE_BYTES}")
                status = response.status_code
    except httpx.HTTPError as exc:
        raise SigstoreHTTPError(_scrub(f"{url}: {type(exc).__name__}: {exc}", secrets)) from None
    if status not in (200, 201):
        raise SigstoreHTTPError(f"{url}: HTTP {status}")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SigstoreHTTPError(f"{url}: response is not JSON") from None


def post_json(url: str, body: Any, **kwargs: Any) -> Any:
    return request_json("POST", url, body=body, **kwargs)


def _b64_hex(value: Any) -> str:
    return base64.b64encode(bytes.fromhex(str(value))).decode("ascii")


def entry_from_response(response: Any) -> dict[str, Any]:
    """A bundle ``TransparencyLogEntry`` from Rekor's ``{uuid: LogEntry}`` reply."""
    if not isinstance(response, dict) or len(response) != 1:
        raise SigstoreHTTPError("Rekor reply is not one log entry")
    entry = next(iter(response.values()))
    try:
        verification = entry["verification"]
        proof = verification["inclusionProof"]
        return {
            "logIndex": str(int(entry["logIndex"])),
            "logId": {"keyId": _b64_hex(entry["logID"])},
            "kindVersion": {"kind": "dsse", "version": "0.0.1"},
            "integratedTime": str(int(entry["integratedTime"])),
            "inclusionPromise": {"signedEntryTimestamp": verification["signedEntryTimestamp"]},
            "inclusionProof": {
                "logIndex": str(int(proof["logIndex"])),
                "rootHash": _b64_hex(proof["rootHash"]),
                "treeSize": str(int(proof["treeSize"])),
                "hashes": [_b64_hex(h) for h in proof["hashes"]],
                "checkpoint": {"envelope": str(proof["checkpoint"])},
            },
            "canonicalizedBody": str(entry["body"]),
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise SigstoreHTTPError(f"Rekor reply is missing receipt fields: {exc}") from None


def upload_dsse(envelope: dict, verifier_pem: bytes, url: str = DEFAULT_REKOR_URL) -> dict:
    """Log *envelope* (verified by *verifier_pem*) and return its unverified receipt."""
    proposed = {
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "proposedContent": {
                "envelope": json.dumps(envelope, sort_keys=True, separators=(",", ":")),
                "verifiers": [base64.b64encode(verifier_pem).decode("ascii")],
            }
        },
    }
    return entry_from_response(post_json(url.rstrip("/") + "/api/v1/log/entries", proposed))
