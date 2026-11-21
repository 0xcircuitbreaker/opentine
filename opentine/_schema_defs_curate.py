"""JSON Schemas for curated dataset versions (0.75).

``tine-cli-dataset-curate-1`` is the ``tine dataset
curate|justify|versions|verify-version|materialize --json`` output.
``opentine-dataset-version-1`` is the ``opentine.dataset-version/1`` claim: a
convention on an existing attestation, not an object kind (docs/DATASETS.md).
"""

from __future__ import annotations

from typing import Any

from opentine._dataset_claims import CHUNKING, SOURCES
from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt, strs

_HEAD = {"schema": {"const": "tine-cli-dataset-curate/1"}}
_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_RUN = {"type": "string", "pattern": "^run:sha256:[0-9a-f]{64}$"}
_RUNS = {"type": "array", "items": _RUN}
_AT = {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"}
_STATE = {"type": "string", "pattern": "^(verified|unverified: .+)$"}
_SIG = {"enum": ["verified-tofu", "unsigned", "signer-mismatch", "curator-mismatch",
                 "bad-signature"]}  # fmt: skip
_DROPPED = {"type": "array", "items": closed(["run", "same_as"], {"run": _RUN, "same_as": _RUN})}
_VERSION_ROW = closed(["record", "hold", "name", "version", "previous", "selection", "members",
                       "excluded", "signature", "curator", "created_at", "verification"], {
    "record": _ATT, "hold": STR, "name": opt(STR), "version": opt(INT), "previous": opt(STR),
    "selection": opt(STR), "members": INT, "excluded": INT, "signature": _SIG,
    "curator": opt(STR), "created_at": opt(STR), "verification": _STATE})  # fmt: skip
_SHAPES = [
    closed(["command", "schema", "ok", "record", "name", "version", "previous", "selection",
            "members", "members_digest", "dropped", "excluded", "included_tainted", "mode",
            "withdrawn", "tombstones"], {
        **_HEAD, "command": {"const": "dataset curate"}, "ok": {"const": True}, "record": _ATT,
        "name": STR, "version": INT, "previous": opt(_ATT), "selection": STR, "members": _RUNS,
        "members_digest": _DIGEST, "dropped": _DROPPED, "excluded": _RUNS,
        "included_tainted": _RUNS, "mode": {"enum": ["default", "include-tainted"]},
        "withdrawn": _RUNS, "tombstones": {"type": "array", "items": _ATT}}),
    closed(["command", "schema", "ok", "record", "name", "runs"], {
        **_HEAD, "command": {"const": "dataset justify"}, "ok": {"const": True},
        "record": _ATT, "name": STR, "runs": _RUNS}),
    closed(["command", "schema", "ok", "record", "name", "version", "out", "items", "digest",
            "withdrawn"], {
        **_HEAD, "command": {"const": "dataset materialize"}, "ok": {"const": True},
        "record": _ATT, "name": STR, "version": INT, "out": STR, "items": INT, "digest": STR,
        "withdrawn": _RUNS}),
    closed(["command", "schema", "ok", "versions"], {
        **_HEAD, "command": {"const": "dataset versions"}, "ok": {"const": True},
        "versions": {"type": "array", "items": _VERSION_ROW}}),
    closed(["command", "schema", "record", "ok", "signature", "problems", "members",
            "excluded"], {
        **_HEAD, "command": {"const": "dataset verify-version"}, "record": opt(_ATT),
        "ok": BOOL, "signature": _SIG, "problems": strs(), "members": INT, "excluded": INT}),
]  # fmt: skip
_CLAIM = closed(["convention", "name", "version", "previous", "selection", "members",
                 "members_digest", "dedup", "taint_filter", "withdrawn", "curator",
                 "created_at"], {
    "convention": {"const": "opentine.dataset-version/1"},
    "name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"},
    "version": {"type": "integer", "minimum": 1}, "previous": opt(_ATT), "selection": STR,
    "members": {"type": "array", "items": closed(["run", "content"], {
        "run": _RUN, "content": _DIGEST})},
    "members_digest": _DIGEST,
    "dedup": closed(["chunking", "candidates", "dropped"], {
        "chunking": {"const": dict(CHUNKING)}, "candidates": INT, "dropped": _DROPPED}),
    "taint_filter": closed(["mode", "sources", "excluded", "included_tainted",
                            "justification"], {
        "mode": {"enum": ["default", "include-tainted"]}, "sources": {"const": list(SOURCES)},
        "excluded": _RUNS, "included_tainted": _RUNS, "justification": opt(_ATT)}),
    "withdrawn": _RUNS, "curator": _DIGEST, "created_at": _AT})  # fmt: skip
SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-dataset-curate-1": doc("tine-cli-dataset-curate-1",
        "tine dataset curate|justify|versions|verify-version|materialize --json",
        "Signed dataset versions curated from runs. `curate` selects runs, leaves out "
        "withdrawn and tainted runs (integrity taints, monitor verdicts, oversight rejections, "
        "sabotage task records, verified behaviour flags), dedups by content-defined chunks "
        "and signs the version; `--include-tainted` needs a justification signed by a pinned "
        "curator or policy key. `verify-version` checks one version offline and exits 1 when "
        "`ok` is false. `materialize` writes a verified version as eval items.",
        {"oneOf": _SHAPES}),
    "opentine-dataset-version-1": doc("opentine-dataset-version-1",
        "opentine.dataset-version/1 claim",
        "One signed version of a curated dataset. A claim convention on an existing "
        "attestation, not an object kind (docs/DATASETS.md).", _CLAIM),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"dataset {verb}": "tine-cli-dataset-curate-1"
    for verb in ("curate", "justify", "versions", "verify-version", "materialize")
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
