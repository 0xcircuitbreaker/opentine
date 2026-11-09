"""Reference ops for the six pre-cutoff kinds that had no vectors until 0.50.

``tine-verify-report/2`` (SPEC 8.1, 8.7), ``tine-custody/1`` records (8.4,
8.9), the in-toto ``replay/v1`` predicate (8.8), the ``TINEAES6`` header
(Part 11), ``opentine-line-attribution/1`` git-note records and
``tine-cost-statement/1``. Each op calls the function the CLI's own verify
path calls; none needs a repository, a git binary, a TSA or a network.
"""

from __future__ import annotations

from typing import Any

from opentine import (
    _cost_export,
    _custody,
    _evidence_export,
    _intoto_replay,
    _line_attrib,
    _verify_report_sign,
)
from opentine.remote import _sealed6


def _key(value: dict[str, Any]) -> bytes | None:
    key = value.get("public_key")
    return bytes.fromhex(key) if key else None


def op_verify_report(inp, args: dict[str, Any]) -> dict[str, Any]:
    value = inp.value
    return _verify_report_sign.check(value["report"], None, public_key=_key(value))


def op_custody_chain(inp, args: dict[str, Any]) -> dict[str, Any]:
    value = inp.value
    return _custody.check_records(value["records"], public_key=_key(value))


def op_custody_record(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 8.4: an evidence folder's ``custody.jsonl`` record (``tine-custody/1``)."""
    record = inp.value["record"]
    return {
        "schema": record.get("schema"),
        "manifest_sha256": record.get("manifest_sha256"),
        "signed": isinstance(record.get("signature"), dict),
        "valid": _evidence_export.verify_custody(record),
    }


def op_replay_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    value = inp.value
    return _intoto_replay.verify_envelope(value["envelope"], _key(value))


def op_sealed6_header(inp, args: dict[str, Any]) -> dict[str, Any]:
    key_id, epoch, flags, codec, size, length = _sealed6.parse_header(inp.bytes_())
    return {"key_id": key_id, "epoch": epoch, "flags": flags, "codec": codec, "size": size,
            "header_length": length}  # fmt: skip


def op_line_attribution(inp, args: dict[str, Any]) -> dict[str, Any]:
    value = inp.value
    added = {
        path: {int(n): text for n, text in lines.items()} for path, lines in value["added"].items()
    }
    return _line_attrib.verify_lines(value["record"], added, _key(value))


def op_cost_statement(inp, args: dict[str, Any]) -> dict[str, Any]:
    value = inp.value
    return _cost_export.verify_against(value["statement"], value["expected"], _key(value))


OPS = {
    "verify-report.verify": op_verify_report,
    "custody.chain": op_custody_chain,
    "custody.record": op_custody_record,
    "replay.verify": op_replay_verify,
    "sealed6.header": op_sealed6_header,
    "line-attribution.verify": op_line_attribution,
    "cost-statement.verify": op_cost_statement,
}
