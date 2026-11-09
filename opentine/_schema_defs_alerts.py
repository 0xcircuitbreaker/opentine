"""JSON Schema for ``tine alert ACTION --json`` (0.49).

Only the command's output: an alert delivery is a ``tine-webhook/1`` body (its
``alert`` member rides in that open envelope) or an OTLP log record, so this
adds no object kind or wire format.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, STR, closed, doc, open_, opt

_TRIGGER = {"enum": ["verify.failed", "policy.denied", "cost.threshold", "witness.disagreement"]}
_NAME = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"}
_NUM = {"type": "number"}
_RULE = closed(["name", "on", "threshold", "webhook", "otlp", "allow_private"], {
    "name": _NAME, "on": _TRIGGER, "threshold": opt(_NUM), "webhook": opt(STR),
    "otlp": opt(STR), "allow_private": BOOL})  # fmt: skip
_DELIVERY = open_(["sink", "target", "outcome"], {
    "sink": {"enum": ["webhook", "otlp"]}, "target": STR,
    "outcome": {"enum": ["delivered", "failed", "dry-run"]},
    "status": {"type": ["integer", "string"]}, "attempts": {"type": "integer", "minimum": 1},
    "delivery": STR, "detail": STR})  # fmt: skip
_ALERT = closed(
    ["rule", "on", "subject", "detail", "value", "threshold", "test", "deliveries"],
    {
        "rule": _NAME,
        "on": _TRIGGER,
        "subject": opt(STR),
        "detail": STR,
        "value": opt(_NUM),
        "threshold": opt(_NUM),
        "test": BOOL,
        "deliveries": {"type": "array", "items": _DELIVERY},
    },
)

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-alert-1": doc("tine-cli-alert-1", "tine alert ACTION --json",
        "Every `tine alert` action. `add`: the stored `rule`; `list`: `rules` and "
        "`webhook_key` (kid, alg, public_key: pin it in the receiver); `remove`: the remaining "
        "`rules`; `test`: the `event` evaluated (id, kind) and one `alerts` entry per rule it "
        "tripped (or, with --always, a `test: true` alert per other rule), each with its "
        "`deliveries`. `ok` is false, and the command exits 1, when a delivery failed.",
        open_(["command", "action", "ok"], {
            "command": {"const": "alert"},
            "action": {"enum": ["add", "list", "remove", "test"]},
            "ok": BOOL, "rule": _RULE, "rules": {"type": "array", "items": _RULE},
            "webhook_key": closed(["kid", "alg", "public_key"], {
                "kid": {"type": "string", "pattern": "^ed25519:[0-9a-f]{16}$"},
                "alg": {"const": "ed25519"}, "public_key": STR}),
            "event": open_(["id", "kind"], {"id": opt(STR), "kind": opt(STR)}),
            "alerts": {"type": "array", "items": _ALERT}})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {"alert": "tine-cli-alert-1"}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
