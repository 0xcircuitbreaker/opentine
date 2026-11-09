"""JSON Schema for ``tine publish zenodo | hf --json`` (0.49).

A CLI output schema only: publishing adds no object kind or wire format. The
bundle is an ordinary ``opentine-bundle`` file; on the Hub it is the 0.46
redacted public copy with its signed ``opentine.redacted-copy`` record.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, STR, closed, doc, open_, opt

_HTTPS = {"type": "string", "pattern": "^https://"}
_STEP = closed(["method", "path"], {"method": STR, "path": STR})
_FILE = open_(["name"], {"name": STR, "bytes": INT, "checksum": opt(STR)})
_BUNDLE = closed(["digest", "bytes", "refs"], {
    "digest": FPR, "bytes": INT,
    "refs": {"type": "object", "additionalProperties": STR}})  # fmt: skip
_ZENODO = closed(["deposition", "state", "doi", "url", "files"], {
    "deposition": INT, "state": {"enum": ["draft", "published"]}, "doi": opt(STR),
    "url": opt(_HTTPS), "files": {"type": "array", "items": _FILE}})  # fmt: skip
_HF = closed(["commit", "url"], {"commit": opt(STR), "url": opt(_HTTPS)})

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-publish-1": doc("tine-cli-publish-1", "tine publish zenodo | hf --json",
        "`bundle` is what was (or, with `--dry-run`, would be) uploaded, after the push "
        "gate's redaction scan passed; `files` every file sent. With `--dry-run`, `plan` lists "
        "the requests and nothing is sent; otherwise `published` is the Zenodo deposition "
        "(`draft` unless `--publish`) or the Hub commit. `dataset` and `public_run` are the "
        "Hub dataset and the redacted copy's run id. Tokens never appear.",
        open_(["command", "action", "ok", "dry_run", "api", "bundle", "files"], {
            "command": {"const": "publish"}, "action": {"enum": ["zenodo", "hf"]},
            "ok": BOOL, "dry_run": BOOL, "api": _HTTPS, "bundle": _BUNDLE,
            "files": {"type": "array", "items": _FILE},
            "plan": {"type": "array", "items": _STEP},
            "published": {"anyOf": [_ZENODO, _HF]},
            "dataset": STR, "public_run": STR})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {"publish": "tine-cli-publish-1"}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
