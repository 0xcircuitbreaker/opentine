"""The record-family conformance ops the pyz answers case by case (0.50 parity).

Before 0.50 these families (SPEC 4.13 to 4.26, 8.13, 8.16, 8.17) reached the
pyz only through per-family tests; here each op calls the same pyz verifier a
``tine-verify.pyz`` file check calls, with the vector's input, so the freeze
audit runs every case of every family through the built archive. Every op has
the ``(raw, value, args)`` shape of :mod:`._conform`.
"""

from __future__ import annotations

import base64
from typing import Any

from . import (
    _finding,
    _forgecheck,
    _hook,
    _merge,
    _mergerec,
    _oms,
    _project,
    _records,
    _redactr,
    _registry,
    _review,
    _reviewfile,
    _vsa,
    _webhook,
)


def _hex(value: Any) -> bytes | None:
    return bytes.fromhex(value) if value else None


def _keys(value: dict) -> dict[str, bytes | None]:
    return {
        "hmac_key": _hex(value.get("hmac_key_hex")),
        "public_key": _hex(value.get("public_key")),
    }


def _report(raw: Any, value: dict, args: dict) -> dict:
    return _redactr.verify(value["report"], **_keys(value))


def _tombstone(raw: Any, value: dict, args: dict) -> dict:
    return _records.verify(value["tombstone"], **_keys(value))


def _copy(raw: Any, value: dict, args: dict) -> dict:
    return _records.verify(value["record"], pack=value.get("pack"), **_keys(value))


def _closure(raw: Any, value: dict, args: dict) -> dict:
    objects = {row["id"]: base64.b64decode(row["data_b64"]) for row in value["objects"]}
    return _records.closure(value["run"], objects, value["tombstones"])


def _merge_record(raw: Any, value: dict, args: dict) -> dict:
    return _mergerec.verify(value["record"], run=value.get("run"), **_keys(value))


def _approval(raw: Any, value: dict, args: dict) -> dict:
    return _mergerec.verify(value["record"], kind=_mergerec.APPROVAL, **_keys(value))


def _git_object(raw: Any, value: dict, args: dict) -> dict:
    data = base64.b64decode(value["data_b64"])
    return _project.git_object_check(value["type"], data, value["oid"])


def _forge_check(raw: Any, value: dict, args: dict) -> dict:
    data = value["bundle_b64"]
    return _forgecheck.forge_check_verify(
        value["check"], None if data is None else base64.b64decode(data)
    )


OPS = {
    "webhook.verify": lambda raw, value, args: _webhook.verify_case(value),
    "vsa.verify": lambda raw, value, args: _vsa.verify_case(value),
    "redaction-report.verify": _report,
    "tombstone.verify": _tombstone,
    "tombstone.closure": _closure,
    "redacted-copy.verify": _copy,
    "project.verify": lambda raw, value, args: _project.project_verify(
        value["manifest"], value["previous"], value["owner_key"]
    ),
    "project.chain": lambda raw, value, args: _project.project_chain(
        value["versions"], value["owner_key"]
    ),
    "mirror-state.verify": lambda raw, value, args: _project.mirror_verify(
        value["state"], _hex(value.get("host_key")), value["owners"]
    ),
    "git-object.check": _git_object,
    "hook.normalize": lambda raw, value, args: _hook.normalize_case(value),
    "hook.respond": lambda raw, value, args: _hook.respond_case(value),
    "merge.compute": lambda raw, value, args: _merge.compute_case(value),
    "merge.pick": lambda raw, value, args: _merge.pick_case(value),
    "merge.verify": _merge_record,
    "merge-approval.verify": _approval,
    "prompt.verify": lambda raw, value, args: _registry.prompt_verify(
        value["record"], value["previous"], _hex(value.get("public_key"))
    ),
    "memory.verify": lambda raw, value, args: _registry.memory_verify(
        value["record"], _hex(value.get("public_key")), value["team"]
    ),
    "review.verify": lambda raw, value, args: _review.review_verify(
        value["version"], value["previous"], value["reviewer_key"]
    ),
    "review-gate.verify": lambda raw, value, args: _review.gate_verify(
        value["decision"], value["version"]
    ),
    "review.bundle": lambda raw, value, args: _reviewfile.bundle_verify(
        value["bundle"], value["reviewer_key"]
    ),
    "forge-check.verify": _forge_check,
    "review-finding.verify": lambda raw, value, args: _finding.finding_verify(
        value["record"], _hex(value["public_key"]), value["reviewers"]
    ),
    "oms.verify": lambda raw, value, args: _oms.oms_verify(
        value["bundle"], value["files"], value["public_key"]
    ),
}

__all__ = ["OPS"]
