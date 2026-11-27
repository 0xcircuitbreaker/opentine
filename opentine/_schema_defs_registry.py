"""JSON Schemas for the prompt registry, team memory and push-triggered evals (0.47).

``opentine-prompt-1`` (an ``opentine.prompt`` version, SPEC 4.21) and
``opentine-memory-1`` (an ``opentine.memory`` note, SPEC 4.22) are the two
records; ``tine-cli-prompt-1``, ``tine-cli-memory-1`` and ``tine-cli-eval-ci-1``
are the ``--json`` outputs of ``tine prompt``, ``tine memory`` and ``tine eval
ci``. The schemas check shape; the signature, the chain and the placeholder rule
are the verifier's (``opentine._prompt``, ``opentine._memory``).
``tine-cli-eval-compare-1`` and ``tine-cli-promote-1`` (0.58) are the outputs
of ``tine eval compare`` and ``tine promote``.
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
_RUN = {"type": "string", "pattern": "^run:sha256:[0-9a-f]{64}$"}
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
    "created_at": _WHEN, "assurance": {"enum": ["T0", "T1", "T2", "T3"]}})  # fmt: skip
_STRS: dict[str, Any] = {"type": "array", "items": STR}
_SIDE = open_(["eval", "ok"], {"eval": opt(STR), "ok": BOOL})
_DEC = {"type": "string", "pattern": "^-?[0-9]+\\.[0-9]{6}$"}
_METRIC = closed(
    ["a", "b", "delta", "ci", "p_value", "significant", "regression", "improvement"],
    {
        "a": opt(_DEC),
        "b": opt(_DEC),
        "delta": _DEC,
        "ci": opt({"type": "array", "items": _DEC, "minItems": 2, "maxItems": 2}),
        "p_value": opt(_DEC),
        "significant": BOOL,
        "regression": BOOL,
        "improvement": BOOL,
    },
)
_STATS = closed(
    ["convention", "method", "alpha", "seed", "resamples", "n", "metrics", "regressions"],
    {
        "convention": {"const": "opentine.eval-compare/1"},
        "method": {"enum": ["paired-bootstrap", "permutation"]},
        "alpha": STR,
        "seed": INT,
        "resamples": INT,
        "n": INT,
        "metrics": closed(["score", "pass_rate"], {"score": _METRIC, "pass_rate": _METRIC}),
        "regressions": {"type": "array", "items": {"enum": ["score", "pass_rate"]}},
    },
)
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
        "the number of trusted keys; `trust`: `team`, the trusted keys. 0.61: `recall` rows "
        "carry `assurance` with `--min-assurance` and `recorded_run` with `--record-to`; "
        "`quarantine` adds `note` (the quarantined digest), `quarantine`, `signer`, `held` "
        "and the signed `record`; `quarantine` and `served` give `served_note`, `quarantined`, "
        "`runs` (every run that lists a step serving the note) and `variants` (lineage "
        "variants whose mutation or eval runs did), and `verification`: `verified` when a "
        "`curator` key of the owner-pinned key roles signed the quarantine, else "
        "`unverified: WHY` (it still blocks), null when the note is not quarantined.",
        open_(["command", "action", "ok"], {
            "command": {"const": "memory"},
            "action": {"enum": ["add", "list", "recall", "trust", "sync", "quarantine",
                                "served"]},
            "ok": BOOL, "note": {"anyOf": [_CHECK, _BLOB]}, "record": _NOTE,
            "notes": {"type": "array", "items": _CHECK},
            "team": {"anyOf": [INT, {"type": "array", "items": _HEX64}]},
            "recorded_run": opt(_RUN), "quarantine": _BLOB, "signer": _HEX64, "held": _BLOB,
            "served_note": _BLOB, "quarantined": BOOL,
            "verification": {"anyOf": [{"type": "null"}, {"type": "string",
                             "pattern": "^(verified$|unverified: )"}]},
            "runs": {"type": "array", "items": closed(["run", "event"], {
                "run": _RUN, "event": STR})},
            "variants": {"type": "array", "items": closed(["variant", "runs"], {
                "variant": STR, "runs": {"type": "array", "items": _RUN}})}})),
    "tine-cli-eval-ci-1": doc("tine-cli-eval-ci-1", "tine eval ci --json",
        "Every eval `.tine/evals.toml` declares, run and signed: per eval its id, folder, "
        "counts, pass rate and gate, and the registered `judge_prompt` it used (name, version, "
        "digest) or null, and `cost`, the LLM-judge calls' total in USD. `ok` is true only "
        "when every eval reaches its `min_pass_rate`; the command then exits 0, else 1.",
        open_(["command", "ok", "config", "out", "evals"], {
            "command": {"const": "eval ci"}, "ok": BOOL, "config": STR, "out": STR,
            "cost": STR,
            "evals": {"type": "array", "items": closed(
                ["name", "eval", "dir", "items", "passed", "mean_score", "pass_rate",
                 "min_pass_rate", "ok", "judge_prompt"], {
                    "name": _ID, "eval": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                    "dir": STR, "items": INT, "passed": INT, "mean_score": STR,
                    "pass_rate": NUM, "min_pass_rate": NUM, "ok": BOOL,
                    "judge_prompt": _LINK})}})),
    "tine-cli-eval-compare-1": doc("tine-cli-eval-compare-1", "tine eval compare --json",
        "Two evals, both verified, compared item by item (`regressed`, `fixed`, `changed`, "
        "`only_a`, `only_b`, `mean_delta`). With `--ci` (0.58) `stats` follows the "
        "`opentine.eval-compare/1` convention: per metric (`score`, `pass_rate`) both means, "
        "the delta, a paired-bootstrap interval `ci` or a permutation `p_value`, and whether "
        "it is significant, a regression or an improvement; `export` and `attestation` name "
        "the files `--export` and `--attest --out` wrote.",
        open_(["command", "ok", "a", "b", "regressed", "fixed"], {
            "command": {"const": "eval compare"}, "ok": BOOL, "a": _SIDE, "b": _SIDE,
            "mean_delta": STR, "regressed": _STRS, "fixed": _STRS, "only_a": _STRS,
            "only_b": _STRS, "stats": opt(_STATS), "export": opt(STR),
            "attestation": STR})),
    "tine-cli-promote-1": doc("tine-cli-promote-1", "tine promote --json",
        "`tine promote TARGET --name NAME` moves a `promotions/<name>` ref (`run_id`, `ref`, "
        "`created`). With `--baseline LABEL` (0.58) it is the signed promotion gate: "
        "`action` is `promote`, `revert`, `canary`, `approve`, `sign-policy` (`--sign-policy`, "
        "the `opentine.promotion-policy/1` attestation) or `refused`; `refusals` "
        "lists each named reason (`promote.*`); `previous` and `current` are the label's "
        "holder before and after; `stats` holds the `opentine.eval-compare/1` statistics; "
        "`advisories` (0.85) lists non-blocking findings such as `advisory:scorer.in-process`; "
        "`plan` (0.86) is the pre-registered, corrected analysis under `--plan`; `skills` "
        "(0.88) is the skill tree change (`from`, `to`, `label`) when the candidate's signed "
        "lineage record names another skill than the holder's.",
        open_(["command"], {
            "command": {"const": "promote"}, "ok": BOOL,
            "action": {"enum": ["promote", "revert", "canary", "approve", "sign-policy",
                                "refused"]},
            "label": _ID, "candidate": STR, "previous": opt(STR), "current": opt(STR),
            "out": STR, "reason": STR, "refusals": {"type": "array", "items": closed(
                ["code", "detail"], {"code": {"type": "string", "pattern": "^promote\\.[a-z-]+$"},
                                     "detail": STR})},
            "stats": {"type": "object", "additionalProperties": _STATS},
            "inputs": {"type": "array"}, "run_id": STR, "ref": STR, "name": STR,
            "created": BOOL, "plan": opt({"type": "object"}),
            "skills": opt(closed(["from", "to", "label"], {"from": opt(STR), "to": opt(STR),
                                                          "label": _ID})),
            "advisories": {"type": "array", "items": closed(
                ["code", "detail"], {"code": {"type": "string",
                                              "pattern": "^advisory:[a-z.-]+$"},
                                     "detail": STR})}})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {
    "prompt": "tine-cli-prompt-1",
    "memory": "tine-cli-memory-1",
    "eval ci": "tine-cli-eval-ci-1",
    "eval compare": "tine-cli-eval-compare-1",
    "promote": "tine-cli-promote-1",
}

#: ``kind`` value -> schema stem, for the records (they carry no tag or ``command``).
KIND_SCHEMAS: dict[str, str] = {
    "opentine.prompt": "opentine-prompt-1",
    "opentine.memory": "opentine-memory-1",
}

__all__ = ["COMMAND_SCHEMAS", "KIND_SCHEMAS", "SCHEMAS"]
