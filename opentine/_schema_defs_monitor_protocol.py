"""JSON Schema shapes for ``tine monitor protocol-sign|protocol-run --json`` (0.83).

Joined into ``tine-cli-monitor-1`` by :mod:`opentine._schema_defs_monitor`, with
the two file and claim conventions: ``opentine.collusion-protocol/1`` (a signed
manifest file) and ``opentine.collusion-verdict/1`` (the claim an eval verdict's
``item_digest`` binds). Neither is an object kind.
"""

from __future__ import annotations

from typing import Any

from opentine._collusion_run import PROBES
from opentine._schema_defs import BOOL, FPR, INT, NUM, STR, closed, doc, opt

_HEAD = {"schema": {"const": "tine-cli-monitor/1"}}
_DEC = {"type": "string", "pattern": "^(0|0\\.[0-9]+)$"}
_CI = opt({"type": "array", "minItems": 2, "maxItems": 2,
           "items": {"type": "string", "pattern": "^[01]\\.[0-9]{6}$"}})  # fmt: skip
_RATE_KEYS = ["trials", "flagged", "rate", "wilson", "clopper_pearson", "events"]
_RATE = closed(_RATE_KEYS, {"trials": INT, "flagged": INT, "rate": opt(NUM), "wilson": _CI,
                            "clopper_pearson": _CI, "events": INT})  # fmt: skip
_SIGN = closed(["command", "schema", "ok", "protocol", "protocol_name", "signer",
                "seed_commitment", "out"], {
    **_HEAD, "command": {"const": "monitor protocol-sign"}, "ok": {"const": True},
    "protocol": FPR, "protocol_name": STR, "signer": FPR, "seed_commitment": FPR,
    "out": STR})  # fmt: skip
_RUN = closed(["command", "schema", "ok", "advisory_only", "cleared", "protocol",
               "protocol_name", "monitor", "monitor_digest", "reference_digest",
               "seed_commitment", "trials", "collusion", "probes", "reference_used",
               "verdicts", "verdicts_file", "recorded"], {
    **_HEAD, "command": {"const": "monitor protocol-run"}, "ok": BOOL, "advisory_only": BOOL,
    "cleared": BOOL, "protocol": FPR, "protocol_name": STR, "monitor": STR,
    "monitor_digest": FPR, "reference_digest": opt(FPR), "seed_commitment": FPR,
    "trials": INT, "collusion": _RATE, "reference_used": BOOL,
    "probes": closed(list(PROBES), dict.fromkeys(PROBES, _RATE)),
    "verdicts": {"type": "array", "items": FPR}, "verdicts_file": opt(STR),
    "recorded": {"type": "array", "items": STR}})  # fmt: skip

_STRS = {"type": "array", "maxItems": 64, "items": {"type": "string", "minLength": 1}}
MANIFEST = closed(["convention", "protocol", "trials", "sample", *PROBES, "alpha",
                   "max_flag_rate", "required", "seed_commitment", "signer", "created_at",
                   "signature"], {
    "convention": {"const": "opentine.collusion-protocol/1"}, "protocol": STR,
    "trials": INT, "sample": INT,
    "paraphrase": closed(["variants"], {"variants": INT}),
    "resample": closed(["samples"], {"samples": INT}),
    "honeypot": closed(["rate", "templates"], {"rate": _DEC, "templates": _STRS}),
    "disagreement": closed(["reference_digest"], {"reference_digest": opt(FPR)}),
    "stego": closed(["markers"], {"markers": _STRS}),
    "alpha": _DEC, "max_flag_rate": _DEC, "required": BOOL, "seed_commitment": FPR,
    "signer": FPR, "created_at": STR, "signature": {"type": "object"}})  # fmt: skip
_ITEMS = ["collusion", *(f"collusion:{p}" for p in PROBES)]
CLAIM = closed(["convention", "protocol", "monitor_digest", "reference_digest",
                "seed_commitment", "item", "alpha", "trials", "flagged", "events", "rate",
                "wilson", "clopper_pearson"], {
    "convention": {"const": "opentine.collusion-verdict/1"}, "protocol": FPR,
    "monitor_digest": FPR, "reference_digest": opt(FPR), "seed_commitment": FPR,
    "item": {"enum": _ITEMS}, "alpha": _DEC, "trials": INT, "flagged": INT, "events": INT,
    "rate": opt(NUM), "wilson": _CI, "clopper_pearson": _CI})  # fmt: skip

PROTOCOL_DESCRIPTION = (
    " `protocol-sign` signs an `opentine.collusion-protocol/1` manifest that commits to a "
    "secret seed; `protocol-run` verifies it against the pinned roles (a `policy` key, never "
    "an `optimizer` key; refused when unpinned), checks the revealed seed, applies the "
    "paraphrase, re-sampling, honeypot, cross-monitor disagreement and steganography probes "
    "over seeded trials and reports flagged-trial rates with Wilson and Clopper-Pearson "
    "intervals; `ok` is false only when the signed manifest sets `required` and the monitor "
    "does not clear."
)
PROTOCOL_SHAPES = [_SIGN, _RUN]
PROTOCOL_COMMANDS = ("monitor protocol-sign", "monitor protocol-run")
SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-collusion-protocol-1": doc("opentine-collusion-protocol-1",
        "opentine.collusion-protocol/1 manifest",
        "A signed collusion-testing protocol manifest (a file convention, not an object "
        "kind); see docs/MONITOR-COLLUSION.md.", MANIFEST),
    "opentine-collusion-verdict-1": doc("opentine-collusion-verdict-1",
        "opentine.collusion-verdict/1 claim",
        "The claim a collusion-protocol `tine-eval-verdict/1` binds through `item_digest`. "
        "A claim convention, not an object kind.", CLAIM),
}  # fmt: skip

__all__ = ["CLAIM", "MANIFEST", "PROTOCOL_COMMANDS", "PROTOCOL_DESCRIPTION",
           "PROTOCOL_SHAPES", "SCHEMAS"]  # fmt: skip
