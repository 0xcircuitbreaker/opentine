"""JSON Schema for ``tine dataset contrib-redact|check|withdraw --json`` (0.75).

Licence annotations and withdrawals are claims on attestations (an existing
object kind), published as ``opentine-dataset-licence-1`` and
``opentine-dataset-withdraw-1``; a tombstone manifest is a file convention,
``opentine-dataset-tombstones-1``. None is an object kind
(docs/DATASET_CONTRIBUTORS.md).
"""

from __future__ import annotations

from typing import Any

from opentine._dataset_withdraw import REASONS
from opentine._schema_defs import BOOL, FPR, INT, STR, closed, doc, opt, strs

_HEAD = {"schema": {"const": "tine-cli-dataset-contrib/1"}}
_RUN = {"type": "string", "pattern": "^run:sha256:[0-9a-f]{64}$"}
_AT = {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"}
_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_SPDX = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$"}
_REASON = {"enum": list(REASONS)}
_TOMB = closed(["digest", "date", "reason"], {
    "digest": FPR, "date": {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}$"},
    "reason": _REASON})  # fmt: skip
_SCAN = closed(["objects", "hits"], {"objects": INT, "hits": INT})
_REDACT = closed(["command", "schema", "ok", "out", "sha256", "source_run", "public_run",
                  "objects", "redacted", "ruleset", "totals", "licence_record", "leak_scan"], {
    **_HEAD, "command": {"const": "dataset contrib-redact"}, "ok": BOOL, "out": opt(STR),
    "sha256": opt(_HEX), "source_run": _RUN, "public_run": _RUN, "objects": INT,
    "redacted": INT, "ruleset": STR, "totals": {"type": "object", "additionalProperties": INT},
    "licence_record": STR, "leak_scan": _SCAN})  # fmt: skip
_NOTE = closed(["record", "spdx", "relicensing_grant", "contributor", "state"], {
    "record": STR, "spdx": opt(STR), "relicensing_grant": opt(BOOL), "contributor": opt(STR),
    "state": STR})  # fmt: skip
_CHECK = closed(["command", "schema", "ok", "bundle", "contributor", "public_run",
                 "record_state", "licence", "scan", "allow", "problems"], {
    **_HEAD, "command": {"const": "dataset check"}, "ok": BOOL, "bundle": STR,
    "contributor": opt(FPR), "public_run": opt(STR), "record_state": opt(STR),
    "licence": {"type": "array", "items": _NOTE},
    "scan": {"type": "array", "items": closed(["object", "finding"], {
        "object": STR, "finding": STR})},
    "allow": strs(), "problems": strs()})  # fmt: skip
_WITHDRAW = closed(["command", "schema", "ok", "record", "run", "reason", "contributor", "state",
                    "tombstone", "tombstones"], {
    **_HEAD, "command": {"const": "dataset withdraw"}, "ok": {"const": True}, "record": STR,
    "run": _RUN, "reason": _REASON, "contributor": FPR, "state": STR, "tombstone": _TOMB,
    "tombstones": opt(INT)})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-dataset-contrib-1": doc("tine-cli-dataset-contrib-1",
        "tine dataset contrib-redact|check|withdraw --json",
        "Contributor tooling for open run datasets. `contrib-redact` writes a signed "
        "--redacted-public bundle of one run with the contributor's local deny-list applied "
        "and a signed licence annotation, and keeps it only when the leak scan of the "
        "unbundled copy finds zero deny-list hits (`ok` false, `out` null, exit 1 otherwise); "
        "nothing of the deny-list is reported. `check` refuses (exit 1) a bundle without a "
        "verified licence annotation by the key that signed its redacted-copy record, with an "
        "SPDX id outside the allow-list, a dirty file-level licence scan, or a tombstoned run. "
        "`withdraw` signs and holds a withdrawal claim and reports its tombstone.",
        {"oneOf": [_REDACT, _CHECK, _WITHDRAW]}),
    "opentine-dataset-licence-1": doc("opentine-dataset-licence-1",
        "opentine-dataset/licence/1 claim",
        "A contributor's licence and consent annotation on a public run, signed by the key "
        "that signed the bundle's redacted-copy record. A claim convention on an existing "
        "attestation, not an object kind.",
        closed(["convention", "run", "spdx", "relicensing_grant", "contributor",
                "annotated_at"], {
            "convention": {"const": "opentine-dataset/licence/1"}, "run": _RUN,
            "spdx": _SPDX, "relicensing_grant": BOOL, "contributor": FPR,
            "annotated_at": _AT})),
    "opentine-dataset-withdraw-1": doc("opentine-dataset-withdraw-1",
        "opentine-dataset/withdraw/1 claim",
        "A contributor's signed, held withdrawal of a run. A claim convention on an existing "
        "attestation, not an object kind.",
        closed(["convention", "run", "reason", "contributor", "withdrawn_at"], {
            "convention": {"const": "opentine-dataset/withdraw/1"}, "run": _RUN,
            "reason": _REASON, "contributor": FPR, "withdrawn_at": _AT})),
    "opentine-dataset-tombstones-1": doc("opentine-dataset-tombstones-1",
        "opentine-dataset/tombstones/1 manifest",
        "Tombstones a dataset build honours: digest, date and reason category of each "
        "withdrawn run, never content. A file convention, not an object kind.",
        closed(["format", "tombstones"], {
            "format": {"const": "opentine-dataset/tombstones/1"},
            "tombstones": {"type": "array", "items": _TOMB}})),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"dataset {verb}": "tine-cli-dataset-contrib-1"
    for verb in ("contrib-redact", "check", "withdraw")
}
__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
