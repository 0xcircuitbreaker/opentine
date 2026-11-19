"""JSON Schemas for Inspect / METR interop (0.64).

``tine-cli-inspect-1`` is the ``tine inspect ... --json`` output (``tine import
inspect`` and ``tine export inspect`` are spellings of it).
``opentine-inspect-sample-1`` is the ``inspect`` value of an imported run's
annotation and ``opentine-inspect-log-sig-1`` the detached log signature the
Inspect hook writes; both are claim conventions, not object kinds
(docs/INSPECT.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, OBJ, SIG, STR, closed, doc, opt

_HEAD = {"schema": {"const": "tine-cli-inspect/1"}}
_ID = {"type": ["string", "integer"]}
_ROW = closed(["sample_id", "epoch", "run", "ref", "scorers"], {
    "sample_id": _ID, "epoch": INT, "run": STR, "ref": STR,
    "scorers": {"type": "array", "items": STR}})  # fmt: skip
_SCORER = closed(["folder", "eval", "items", "scorer_version"],
                 {"folder": STR, "eval": FPR, "items": INT, "scorer_version": STR})  # fmt: skip
_VERDICTS = closed(["scorers", "skipped"], {
    "scorers": {"type": "object", "additionalProperties": _SCORER},
    "skipped": {"type": "array", "items": closed(["scorer", "sample_id", "epoch"], {
        "scorer": STR, "sample_id": _ID, "epoch": INT})}})  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "task", "eval_id", "ref_prefix", "samples", "verdicts"], {
        **_HEAD, "command": {"const": "inspect import"}, "task": STR, "eval_id": opt(STR),
        "ref_prefix": STR, "samples": {"type": "array", "items": _ROW},
        "verdicts": opt(_VERDICTS)}),
    closed(["command", "schema", "output", "format", "samples"], {
        **_HEAD, "command": {"const": "inspect export"}, "output": STR,
        "format": {"enum": ["json", "eval"]}, "samples": INT}),
    closed(["command", "schema", "family", "tasks", "dynamic", "out"], {
        **_HEAD, "command": {"const": "inspect metr"}, "family": STR, "tasks": INT,
        "dynamic": BOOL, "out": STR}),
    closed(["command", "schema", "signature"], {
        **_HEAD, "command": {"const": "inspect sign"}, "signature": STR}),
    closed(["command", "schema", "ok", "reason", "signer"], {
        **_HEAD, "command": {"const": "inspect verify"}, "ok": BOOL, "reason": STR,
        "signer": opt(FPR)}),
]  # fmt: skip
SAMPLE_VALUE = closed(
    ["sample_id", "epoch", "index", "input", "target", "scores", "output", "metadata", "eval",
     "status", "version", "results"], {
        "sample_id": _ID, "epoch": {"type": "integer", "minimum": 1}, "index": INT,
        "input": {}, "target": {}, "scores": OBJ, "output": OBJ, "metadata": OBJ,
        "eval": {"type": "object", "required": ["task"], "properties": {"task": STR}},
        "status": STR, "version": {"type": "integer"}, "results": opt(OBJ)})  # fmt: skip
LOG_SIG = closed(["scheme", "log", "bytes", "sha256", "signer", "signed_at", "signature"], {
    "scheme": {"const": "opentine-inspect-log-sig/1"}, "log": STR, "bytes": INT,
    "sha256": FPR, "signer": FPR, "signed_at": STR, "signature": SIG})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-inspect-1": doc("tine-cli-inspect-1", "tine inspect ... --json",
        "Inspect AI and METR interop. `import` records each sample of an Inspect log as a "
        "run under `ref_prefix` and, with `--key`, signs one tine-eval-verdict/1 eval folder "
        "per scorer; `export --output` reports the log it wrote; `metr` reads a METR "
        "task-standard family into an eval dataset without running it; `sign` and `verify` "
        "handle the detached log signature.", {"anyOf": _SHAPES}),
    "opentine-inspect-sample-1": doc("opentine-inspect-sample-1",
        "inspect run annotation value",
        "The `inspect` value of an imported run's annotation: the Inspect sample id (JSON "
        "type kept), epoch, raw scores and the eval header. A claim convention, not a kind.",
        SAMPLE_VALUE),
    "opentine-inspect-log-sig-1": doc("opentine-inspect-log-sig-1",
        "opentine-inspect-log-sig/1 detached signature",
        "Written beside an Inspect log as `<log>.tine-sig.json`: the log's name, length and "
        "SHA-256 under a tine-sig/3 block. A file convention, not an object kind.", LOG_SIG),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"inspect {verb}": "tine-cli-inspect-1"
    for verb in ("import", "export", "metr", "sign", "verify")
}

__all__ = ["COMMAND_SCHEMAS", "LOG_SIG", "SAMPLE_VALUE", "SCHEMAS"]
