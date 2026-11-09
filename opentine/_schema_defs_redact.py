"""JSON Schemas for redaction and ``tine doctor`` (0.45.1).

``opentine-redaction-report-1`` is the report object (SPEC 4.13) and
``opentine-redaction-report-2`` its PII version (SPEC 4.13.1, 0.46);
``tine-redaction-rules-1`` the ruleset export. The ``tine-cli-*`` entries are
the ``--json`` outputs of ``tine redact check|verify`` and ``tine doctor``.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, SIG, STR, closed, doc, open_, opt

_NAME: dict[str, Any] = {"type": "string", "pattern": "^[A-Za-z0-9_.:/@+-]{1,256}$"}
_HEX_DIGEST: dict[str, Any] = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_REPORT = {
    "anyOf": [
        {"$ref": "opentine-redaction-report-1.schema.json"},
        {"$ref": "opentine-redaction-report-2.schema.json"},
    ]
}

SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-redaction-report-1": doc("opentine-redaction-report-1",
        "opentine.redaction-report (report_version 1)",
        "One run re-scanned with the current redaction ruleset (SPEC 4.13): what `tine redact "
        "check` prints per run. Findings name objects, never the matched bytes. `signature` "
        "is a tine-sig/3 block over `opentine.redaction-report.v1:` + JCS({body, header}).",
        closed(["kind", "report_version", "ruleset", "run", "objects", "findings", "clean"], {
            "kind": {"const": "opentine.redaction-report"}, "report_version": {"const": 1},
            "ruleset": _NAME, "run": _NAME, "objects": INT,
            "findings": {"type": "array", "items": closed(["oid", "kind"], {
                "oid": _NAME, "kind": _NAME})},
            "clean": BOOL, "signature": SIG})),
    "opentine-redaction-report-2": doc("opentine-redaction-report-2",
        "opentine.redaction-report (report_version 2)",
        "One run re-scanned with `opentine-redaction/3` (SPEC 4.13.1): `tine redact check "
        "--pii`. Each finding names the detectors that fired (`secret`, the PII detectors, "
        "`classifier:<kind>`), never the matched text. `signature` is a tine-sig/3 block over "
        "`opentine.redaction-report.v2:` + JCS({body, header}).",
        closed(["kind", "report_version", "ruleset", "classifier", "run", "objects", "findings",
                "clean"], {
            "kind": {"const": "opentine.redaction-report"}, "report_version": {"const": 2},
            "ruleset": _NAME, "classifier": _NAME, "run": _NAME, "objects": INT,
            "findings": {"type": "array", "items": closed(["oid", "kind", "detectors"], {
                "oid": _NAME, "kind": _NAME,
                "detectors": {"type": "array", "minItems": 1, "items": _NAME}})},
            "clean": BOOL, "signature": SIG})),
    "tine-redaction-rules-1": doc("tine-redaction-rules-1", "tine-redaction-rules/1",
        "`tine redact rules --json`: the redaction ruleset as data, one row per scan step in "
        "the order the redactor runs them. `digest` is SHA-256 of JCS({ruleset, rules}).",
        open_(["schema", "ruleset", "rules_version", "digest", "marker", "rules",
               "token_prefixes"], {
            "command": {"const": "redact-rules"}, "schema": {"const": "tine-redaction-rules/1"},
            "ruleset": STR, "rules_version": {"const": 1}, "digest": _HEX_DIGEST, "marker": STR,
            "rules": {"type": "array", "minItems": 1, "items": closed(
                ["order", "id", "family", "description"], {
                    "order": INT, "id": {"type": "string", "pattern": "^[a-z0-9-]+$"},
                    "family": STR, "description": STR})},
            "token_prefixes": {"type": "array", "items": STR}})),
    "tine-cli-redact-check-1": doc("tine-cli-redact-check-1", "tine redact check --json",
        "One redaction report per run; `clean` is true only when every report is clean. "
        "The command exits 4 when any report has findings.",
        open_(["command", "clean", "reports"], {
            "command": {"const": "redact-check"}, "clean": BOOL,
            "reports": {"type": "array", "items": _REPORT}})),
    "tine-cli-redact-verify-1": doc("tine-cli-redact-verify-1", "tine redact verify --json",
        "One row per report in the file: the verified fields, or the `redaction-report.*` "
        "reason it was refused with. The command exits 4 unless every row is ok.",
        open_(["command", "file", "ok", "reports"], {
            "command": {"const": "redact-verify"}, "file": STR, "ok": BOOL,
            "reports": {"type": "array", "items": {"anyOf": [
                closed(["ok", "run", "clean", "objects", "findings", "state"], {
                    "ok": {"const": True}, "run": STR, "clean": BOOL, "objects": INT,
                    "findings": INT, "state": {"enum": ["verified", "verified-tofu"]}}),
                closed(["ok", "run", "reason", "message"], {
                    "ok": {"const": False}, "run": opt(STR),
                    "reason": {"type": "string", "pattern": "^redaction-report\\."},
                    "message": STR})]}}})),
    "tine-cli-doctor-1": doc("tine-cli-doctor-1", "tine doctor --json",
        "Offline environment checks. `status` is `fail` when any row fails (the command then "
        "exits 1); `warn` rows do not change it. `--bundle` writes the same object, without "
        "`command`, redacted, as canonical JSON.",
        open_(["command", "kind", "doctor_version", "status", "checks"], {
            "command": {"const": "doctor"}, "kind": {"const": "opentine.doctor"},
            "doctor_version": {"const": 1}, "status": {"enum": ["ok", "fail"]},
            "checks": {"type": "array", "items": closed(["check", "status", "detail"], {
                "check": STR, "status": {"enum": ["ok", "warn", "fail"]}, "detail": STR})}})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {
    "redact-check": "tine-cli-redact-check-1",
    "redact-verify": "tine-cli-redact-verify-1",
    "doctor": "tine-cli-doctor-1",
}

#: ``kind`` value -> schema stem, for documents that carry neither a tag nor a ``command``.
KIND_SCHEMAS: dict[str, str] = {"opentine.redaction-report": "opentine-redaction-report-1"}

#: ``(kind, report_version)`` -> schema stem, where one kind has more than one version.
KIND_VERSION_SCHEMAS: dict[tuple[str, int], str] = {
    ("opentine.redaction-report", 2): "opentine-redaction-report-2",
}

__all__ = ["COMMAND_SCHEMAS", "KIND_SCHEMAS", "KIND_VERSION_SCHEMAS", "SCHEMAS"]
