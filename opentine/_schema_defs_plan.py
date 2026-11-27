"""JSON Schemas for pre-registered eval plans and eval coverage (0.86).

``tine-cli-eval-plan-1`` and ``tine-cli-eval-reveal-1`` are ``--json`` outputs.
``opentine-eval-plan-1``, ``opentine-eval-plan-reveal-1`` and
``opentine-eval-coverage-1`` are claim conventions on the existing
``attestation`` kind (docs/EVAL-PLANS.md), not object kinds.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, STR, closed, doc, opt

_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_DEC = {"type": "string", "pattern": "^(0|1|0\\.[0-9]*[1-9])$"}
_POS = {"type": "integer", "minimum": 1}
_STRS = {"type": "array", "items": STR}
PLAN = closed([
    "schema", "dataset", "metric", "reducer", "epochs", "test", "alpha", "resamples",
    "correction", "max_candidates", "cluster_key", "mde", "min_coverage",
    "seed_commitment"], {
    "schema": {"const": "opentine.eval-plan/1"}, "dataset": FPR,
    "metric": {"enum": ["score", "pass_rate"]},
    "reducer": {"enum": ["mean", "pass@k", "pass^k"]}, "epochs": _POS,
    "test": {"enum": ["paired-bootstrap", "permutation"]}, "alpha": _DEC,
    "resamples": _POS, "correction": {"enum": ["holm", "bonferroni"]},
    "max_candidates": _POS, "cluster_key": opt(STR), "mde": _DEC, "min_coverage": _DEC,
    "seed_commitment": FPR})  # fmt: skip
REVEAL = closed(["schema", "plan_sha256", "secret"], {
    "schema": {"const": "opentine.eval-plan-reveal/1"}, "plan_sha256": _HEX,
    "secret": _HEX})  # fmt: skip
COVERAGE = closed([
    "schema", "eval", "dataset", "epochs", "planned", "scored", "skipped", "errored",
    "cluster_key", "clusters", "plan_sha256"], {
    "schema": {"const": "opentine.eval-coverage/1"}, "eval": FPR, "dataset": FPR,
    "epochs": _POS, "planned": INT, "scored": INT, "skipped": _STRS, "errored": _STRS,
    "cluster_key": opt(STR), "clusters": {"type": "object", "additionalProperties": STR},
    "plan_sha256": opt(_HEX)})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-eval-plan-1": doc("tine-cli-eval-plan-1", "tine eval plan --json",
        "A signed opentine.eval-plan/1 written to `path`; the seed secret its commitment "
        "opens with is in `secret_path` (keep it from the optimizer).",
        closed(["command", "schema", "ok", "plan", "signer", "plan_sha256", "path",
                "secret_path"], {
            "command": {"const": "eval plan"}, "schema": {"const": "tine-cli-eval-plan/1"},
            "ok": BOOL, "plan": PLAN, "signer": FPR, "plan_sha256": _HEX, "path": STR,
            "secret_path": STR})),
    "tine-cli-eval-reveal-1": doc("tine-cli-eval-reveal-1", "tine eval reveal --json",
        "A signed opentine.eval-plan-reveal/1 written to `path`; `seed` is the analysis "
        "seed derived from the secret and the plan digest.",
        closed(["command", "schema", "ok", "plan_sha256", "seed", "path"], {
            "command": {"const": "eval reveal"},
            "schema": {"const": "tine-cli-eval-reveal/1"}, "ok": BOOL, "plan_sha256": _HEX,
            "seed": {"type": "integer", "minimum": 0, "maximum": 9007199254740991},
            "path": STR})),
    "opentine-eval-plan-1": doc("opentine-eval-plan-1", "opentine.eval-plan/1",
        "The claim of a pre-registered analysis plan: metric, reducer, epochs, test, alpha, "
        "multiplicity correction and candidate count, cluster key, minimum detectable "
        "effect, coverage floor and the seed commitment. A claim convention on an "
        "attestation, not an object kind.", PLAN),
    "opentine-eval-plan-reveal-1": doc("opentine-eval-plan-reveal-1",
        "opentine.eval-plan-reveal/1",
        "The claim that opens a plan's seed commitment after the runs. A claim convention "
        "on an attestation, not an object kind.", REVEAL),
    "opentine-eval-coverage-1": doc("opentine-eval-coverage-1", "opentine.eval-coverage/1",
        "The claim of an eval folder's coverage.json: items times epochs planned, scored, "
        "skipped and errored, the cluster of each item and the plan the run was bound to. "
        "A claim convention on an attestation, not an object kind.", COVERAGE),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    "eval plan": "tine-cli-eval-plan-1",
    "eval reveal": "tine-cli-eval-reveal-1",
}

__all__ = ["COMMAND_SCHEMAS", "COVERAGE", "PLAN", "REVEAL", "SCHEMAS"]
