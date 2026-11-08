"""Reference op for SPEC 8.13: a signed ``tine-webhook/1`` delivery, as a verdict."""

from __future__ import annotations

import base64
from typing import Any

from opentine import _webhook_sig


def op_webhook_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    value = inp.value
    try:
        body = base64.b64decode(value["body_b64"], validate=True)
        keys = {kid: _webhook_sig.unb64url(raw) for kid, raw in value["keys"].items()}
        _webhook_sig.verify(body, value["header"], keys, now=value["now"], window=value["window"])
    except _webhook_sig.WebhookSignatureError as exc:
        return {"ok": False, "class": exc.kind}
    except (KeyError, TypeError, ValueError, AttributeError):
        return {"ok": False, "class": "malformed"}
    return {"ok": True, "class": "valid"}


OPS = {"webhook.verify": op_webhook_verify}
