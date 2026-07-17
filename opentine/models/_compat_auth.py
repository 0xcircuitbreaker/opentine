"""Small authentication helpers for compatible endpoints."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


def glm_jwt(api_key: str) -> str:
    """Convert a legacy Zhipu ``id.secret`` key into its short-lived JWT."""
    key_id, secret = api_key.split(".", 1)
    now = int(time.time() * 1000)

    def encode(value: dict[str, object]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = encode({"alg": "HS256", "sign_type": "SIGN"})
    payload = encode({"api_key": key_id, "exp": now + 3_600_000, "timestamp": now})
    signing_input = f"{header}.{payload}"
    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    ).rstrip(b"=")
    return f"{signing_input}.{signature.decode()}"
