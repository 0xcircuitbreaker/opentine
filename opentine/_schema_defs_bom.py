"""JSON Schema for the AI-BOM export (0.78).

``tine-cli-bom-1`` is the ``tine bom export --out FILE --json`` summary. The
exported documents themselves are CycloneDX 1.6 and SPDX 3.0.1 JSON, validated
against the official schemas (docs/AIBOM.md); they are files, not object kinds.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-bom-1": doc("tine-cli-bom-1", "tine bom export --json",
        "The summary of an AI-BOM export of one lineage node: the format, the file written, "
        "its sha256 and size. The document is CycloneDX 1.6 or SPDX 3.0.1 JSON.",
        closed(["command", "schema", "ok", "format", "variant", "out", "sha256", "bytes"], {
            "command": {"const": "bom export"}, "schema": {"const": "tine-cli-bom/1"},
            "ok": BOOL, "format": {"enum": ["cyclonedx", "spdx"]}, "variant": STR, "out": STR,
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "bytes": INT})),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {"bom export": "tine-cli-bom-1"}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
