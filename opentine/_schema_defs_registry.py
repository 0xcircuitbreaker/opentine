"""JSON Schemas for the prompt registry, team memory and push-triggered evals (0.47).

``opentine-prompt-1`` (an ``opentine.prompt`` version, SPEC 4.21) and
``opentine-memory-1`` (an ``opentine.memory`` note, SPEC 4.22) are the two
records; ``tine-cli-prompt-1``, ``tine-cli-memory-1`` and ``tine-cli-eval-ci-1``
are the ``--json`` outputs of ``tine prompt``, ``tine memory`` and ``tine eval
ci``. The schemas check shape; the signature, the chain and the placeholder rule
are the verifier's (``opentine._prompt``, ``opentine._memory``).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, NUM, SIG, STR, closed, doc, open_, opt

_ID: dict[str, Any] = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"}
_BLOB: dict[str, Any] = {"type": "string", "pattern": "^blob:sha256:[0-9a-f]{64}$"}
_HEX64: dict[str, Any] = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_NAME: dict[str, Any] = {"type": "string", "pattern": "^[A-Za-z0-9_.:/@+-]{1,256}$"}
_WHEN: dict[str, Any] = {
    "type": "string",
    "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
}
_VAR = {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]{0,63}$"}
_TAG = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._:-]{0,63}$"}
_SUBJECT = {"type": "string", "pattern": "^(run|blob):sha256:[0-9a-f]{64}$"}
_PROMPT = {"$ref": "opentine-prompt-1.schema.json"}
_NOTE = {"$ref": "opentine-memory-1.schema.json"}
_SUMMARY = closed(["name", "version", "digest", "variables", "model"], {
    "name": _ID, "version": INT, "digest": _BLOB, "variables": {"type": "array", "items": _VAR},
    "model": opt(_NAME)})  # fmt: skip
_LABELS = {"type": "object", "additionalProperties": INT}
_CHECK = open_(["scope", "topic", "digest", "signer", "subject", "supersedes", "tags", "state"], {
    "scope": _ID, "topic": _ID, "digest": _BLOB, "signer": _HEX64, "subject": opt(_SUBJECT),
    "supersedes": opt(_BLOB), "tags": {"type": "array", "items": _TAG},
    "state": {"enum": ["verified", "verified-tofu"]}, "text": STR, "author": _NAME,
    "created_at": _WHEN})  # fmt: skip
_LINK = opt(closed(["name", "version", "digest"], {"name": _ID, "version": INT, "digest": _BLOB}))

SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-prompt-1": doc("opentine-prompt-1", "opentine.prompt (prompt_version 1)",
        "One version of a registered prompt template (SPEC 4.21). `prev` is the previous "
        "version's blob-oid digest (null for version 1); `variables` are the template's "
        "sorted, distinct {{name}} placeholders; `signature` is an Ed25519 tine-sig/3 block, "
        "by the same key as the previous version, over `opentine.prompt.v1:` + JCS({body, "
        "header}).",
        closed(["kind", "prompt_version", "name", "version", "prev", "template", "variables",
                "model", "created_at", "signature"], {
            "kind": {"const": "opentine.prompt"}, "prompt_version": {"const": 1}, "name": _ID,
            "version": {"type": "integer", "minimum": 1, "maximum": 2147483647},
            "prev": opt(_BLOB), "template": {"type": "string", "minLength": 1},
            "variables": {"type": "array", "items": _VAR}, "model": opt(_NAME),
            "created_at": _WHEN, "signature": SIG})),
    "opentine-memory-1": doc("opentine-memory-1", "opentine.memory (memory_version 1)",
        "One signed team-memory note (SPEC 4.22): a scope, a topic, at most 8 KiB of text, "
        "sorted distinct tags, an optional subject (run or blob) and an optional note it "
        "supersedes. `signature` is an Ed25519 tine-sig/3 block over `opentine.memory.v1:` + "
        "JCS({body, header}); a reader keeps notes its team's keys signed.",
        closed(["kind", "memory_version", "scope", "topic", "text", "tags", "subject",
                "supersedes", "author", "created_at", "signature"], {
            "kind": {"const": "opentine.memory"}, "memory_version": {"const": 1},
            "scope": _ID, "topic": _ID, "text": {"type": "string", "minLength": 1},
            "tags": {"type": "array", "items": _TAG, "maxItems": 32},
            "subject": opt(_SUBJECT), "supersedes": opt(_BLOB), "author": _NAME,
            "created_at": _WHEN, "signature": SIG})),
    "tine-cli-prompt-1": doc("tine-cli-prompt-1", "tine prompt ACTION --json",
        "Every `tine prompt` action. `push`/`get`: `prompt` (the version's summary), its "
        "`labels` and the signed `record` (`get --var` adds `rendered`); `label`: `prompt` and "
        "`labels`; `list`: `prompts`; `verify`: `result`, the history check; `link`: `run` and "
        "`prompt`. A refusal is the error envelope, exit 4 for a verification failure.",
        open_(["command", "action", "ok"], {
            "command": {"const": "prompt"},
            "action": {"enum": ["push", "label", "get", "list", "verify", "link"]},
            "ok": BOOL, "prompt": _SUMMARY, "labels": _LABELS, "record": _PROMPT,
            "rendered": STR, "run": STR,
            "prompts": {"type": "array", "items": open_(["name", "version", "digest", "labels"],
                                                        {"labels": _LABELS})},
            "result": open_(["name", "version", "digest", "signer", "versions", "state"], {
                "name": _ID, "version": INT, "digest": _BLOB, "signer": _HEX64,
                "versions": INT, "state": {"enum": ["verified", "verified-tofu"]}})})),
    "tine-cli-memory-1": doc("tine-cli-memory-1", "tine memory ACTION --json",
        "Every `tine memory` action. `add`: `note` (the check) and the signed `record`; "
        "`list`/`recall`: `notes` (checks with `text`, `author`, `created_at`) and `team`, "
        "the number of trusted keys; `trust`: `team`, the trusted keys.",
        open_(["command", "action", "ok"], {
            "command": {"const": "memory"},
            "action": {"enum": ["add", "list", "recall", "trust"]},
            "ok": BOOL, "note": _CHECK, "record": _NOTE,
            "notes": {"type": "array", "items": _CHECK},
            "team": {"anyOf": [INT, {"type": "array", "items": _HEX64}]}})),
    "tine-cli-eval-ci-1": doc("tine-cli-eval-ci-1", "tine eval ci --json",
        "Every eval `.tine/evals.toml` declares, run and signed: per eval its id, folder, "
        "counts, pass rate and gate, and the registered `judge_prompt` it used (name, version, "
        "digest) or null. `ok` is true only when every eval reaches its `min_pass_rate`; the "
        "command then exits 0, else 1.",
        open_(["command", "ok", "config", "out", "evals"], {
            "command": {"const": "eval ci"}, "ok": BOOL, "config": STR, "out": STR,
            "evals": {"type": "array", "items": closed(
                ["name", "eval", "dir", "items", "passed", "mean_score", "pass_rate",
                 "min_pass_rate", "ok", "judge_prompt"], {
                    "name": _ID, "eval": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                    "dir": STR, "items": INT, "passed": INT, "mean_score": STR,
                    "pass_rate": NUM, "min_pass_rate": NUM, "ok": BOOL,
                    "judge_prompt": _LINK})}})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {
    "prompt": "tine-cli-prompt-1",
    "memory": "tine-cli-memory-1",
    "eval ci": "tine-cli-eval-ci-1",
}

#: ``kind`` value -> schema stem, for the records (they carry no tag or ``command``).
KIND_SCHEMAS: dict[str, str] = {
    "opentine.prompt": "opentine-prompt-1",
    "opentine.memory": "opentine-memory-1",
}

__all__ = ["COMMAND_SCHEMAS", "KIND_SCHEMAS", "SCHEMAS"]
