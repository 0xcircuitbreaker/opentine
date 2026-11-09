"""JSON Schemas for the 0.49 witness network.

``opentine-witness-network-1`` is the registry a hosted log publishes of the
witnesses it requires (``_witness_network``): configuration a verifier pins,
not a signed object kind. ``tine-cli-witness-doctor-1`` is the ``--json``
output of ``tine witness doctor``.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, STR, closed, doc, open_, strs

_URL: dict[str, Any] = {"type": "string", "pattern": "^https?://"}
_CHECK = closed(
    ["check", "ok", "detail"],
    {
        "check": {
            "enum": [
                "keys",
                "key-files",
                "state",
                "logs",
                "registry",
                "health",
                "keys-served",
                "url",
            ]
        },
        "ok": BOOL,
        "detail": STR,
    },
)

SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-witness-network-1": doc("opentine-witness-network-1", "Witness-network registry",
        "The witness set a hosted log requires: its log key, the cosignature quorum and every "
        "witness (distinct operators and names, https URLs, each vkey it cosigns with, current "
        "first). `tine verify --offline --witnesses FILE` refuses a registry whose quorum is "
        "not a strict majority of three or more witnesses (e.g. 2-of-3).",
        closed(["schema", "log", "policy", "witnesses"], {
            "schema": {"const": "opentine-witness-network/1"}, "description": STR,
            "log": closed(["origin", "vkey"], {"origin": STR, "vkey": STR}),
            "policy": closed(["quorum"], {"quorum": {"type": "string",
                                                     "pattern": "^[0-9]+-of-[0-9]+$"}}),
            "witnesses": {"type": "array", "minItems": 3, "maxItems": 64, "items": closed(
                ["name", "operator", "url", "vkeys"], {
                    "name": STR, "operator": STR, "url": _URL, "contact": STR,
                    "jurisdiction": STR,
                    "vkeys": {"type": "array", "minItems": 1, "maxItems": 4, "items": STR}})}})),
    "tine-cli-witness-doctor-1": doc("tine-cli-witness-doctor-1", "tine witness doctor --json",
        "Every operator check `tine witness doctor` ran, in order; `ok` is false (exit 4) "
        "when any failed. Checks without their input (`--registry`, `--url`) are absent.",
        open_(["command", "schema", "ok", "witness", "vkeys", "checks"], {
            "command": {"const": "witness doctor"},
            "schema": {"const": "tine-cli-witness-doctor/1"}, "ok": BOOL, "witness": STR,
            "vkeys": strs(), "checks": {"type": "array", "items": _CHECK}})),
}  # fmt: skip

__all__ = ["SCHEMAS"]
