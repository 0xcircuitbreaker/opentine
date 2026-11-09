"""JSON Schemas for ``tine audit-kit build|verify --json`` (0.49).

``tine-cli-audit-kit-build-1`` is also the kit's own ``kit.json`` (without the
``files`` and ``zip`` keys, which only the command output carries). No new
object kind: a kit places existing ones (SPEC Part 8).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc

_CHECK = closed(
    ["name", "outcome", "detail"],
    {"name": STR, "outcome": {"enum": ["pass", "fail", "skip"]}, "detail": STR},
)
_CHECKS = {"type": "array", "items": _CHECK}

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-audit-kit-build-1": doc("tine-cli-audit-kit-build-1",
        "tine audit-kit build --json",
        "The kit just written: its source, its runs by digest, and every build-time check. "
        "The same document, without files and zip, is the kit's kit.json.",
        closed(["command", "kit_version", "tine_version", "source", "runs", "checks", "ok"], {
            "command": {"const": "audit-kit-build"}, "kit_version": {"const": 1},
            "tine_version": STR,
            "source": closed(["kind", "name", "sha256"], {
                "kind": {"enum": ["run", "bundle"]}, "name": STR, "sha256": STR}),
            "runs": {"type": "array", "items": closed(["run_id", "file", "digest"], {
                "run_id": STR, "file": STR, "digest": STR})},
            "checks": _CHECKS, "ok": BOOL, "files": INT,
            "zip": {"type": ["string", "null"]}})),
    "tine-cli-audit-kit-verify-1": doc("tine-cli-audit-kit-verify-1",
        "tine audit-kit verify --json",
        "Each check of a kit, run with the network refused; ok is false when any check fails.",
        closed(["command", "kit", "ok", "checks"], {
            "command": {"const": "audit-kit-verify"}, "kit": STR, "ok": BOOL,
            "checks": _CHECKS})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {
    "audit-kit-build": "tine-cli-audit-kit-build-1",
    "audit-kit-verify": "tine-cli-audit-kit-verify-1",
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
