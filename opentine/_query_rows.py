"""Rows of the derived query index, one object (or record) at a time (0.65).

Each function turns one stored object, lineage record or eval verdict into
the index row it contributes, or ``None``. The index build and ``tine query
--verify`` call the same functions, so a verified row is one the object still
derives. Every row carries the ``oid`` it came from: the object id for
repository objects, ``sha256:<hex>`` of the record bytes for lineage records and eval lines.
Nothing here judges trust beyond "the signature holds"; which roles a signer
has comes from the owner-pinned key roles only (:mod:`opentine._query_verify`).
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, InvalidOperation
from typing import Any

from opentine import _collusion_verdicts, _json_shallow
from opentine._query_containment import COLUMNS as _CONTAINMENT_COLUMNS
from opentine._query_custody import COLUMNS as _CUSTODY_COLUMNS
from opentine._query_datasets import COLUMNS as _DATASET_COLUMNS
from opentine._query_experiments import COLUMNS as _EXPERIMENT_COLUMNS
from opentine._query_ingest import COLUMNS as _INGEST_COLUMNS
from opentine._query_merges import COLUMNS as _MERGE_COLUMNS
from opentine._query_policy import COLUMNS as _POLICY_COLUMNS
from opentine._query_research import COLUMNS as _RESEARCH_COLUMNS
from opentine._query_transcripts import COLUMNS as _TRANSCRIPT_COLUMNS
from opentine._query_uplift import COLUMNS as _UPLIFT_COLUMNS

#: The tables and the columns each row has, in order (``oid`` first).
COLUMNS: dict[str, tuple[str, ...]] = {
    "runs": ("oid", "status", "model", "created_at", "steps", "source_run_id"),
    "steps": ("oid", "run", "seq", "kind", "model", "provider", "cost", "duration",
              "time_unix", "input_tokens", "output_tokens", "error"),
    "monitor_verdicts": ("oid", "target", "signer", "signed", "monitor", "session", "tool",
                         "action", "score", "threshold", "enforced", "mode", "decided_by",
                         "decided_at"),
    "oversight_decisions": ("oid", "item", "anchor", "previous", "signer", "signed",
                            "decision", "human", "decided_at"),
    "lineage_variants": ("oid", "variant", "signer", "signed", "loop"),
    "lineage_edges": ("oid", "child", "parent"),
    "evals": ("oid", "source", "line", "eval", "dataset", "item", "run", "scorer", "score",
              "threshold", "passed", "signer", "signed", "created_at"),
}  # fmt: skip
COLUMNS.update(_EXPERIMENT_COLUMNS)  # 0.67: experiment manifests and reproduce reports
COLUMNS.update(_RESEARCH_COLUMNS)  # 0.68: sabotage task records and elicitation links
COLUMNS.update(_MERGE_COLUMNS)  # 0.69: history merge records
COLUMNS.update(_CONTAINMENT_COLUMNS)  # 0.69: containment evidence and budget ledgers
COLUMNS.update(_CUSTODY_COLUMNS)  # 0.72: weight custody events and model-organism records
COLUMNS.update(_TRANSCRIPT_COLUMNS)  # 0.74: behaviour flags and transcript clusters
COLUMNS.update(_POLICY_COLUMNS)  # 0.75: signed policy admissions
COLUMNS.update(_UPLIFT_COLUMNS)  # 0.73: uplift suites and records, trend points
COLUMNS.update({**_DATASET_COLUMNS, **_INGEST_COLUMNS})  # 0.75: datasets; 0.77: ingest
#: Columns a row derives from its run (or file), not from the object itself.
CONTEXT = {"run", "seq", "source", "line"}


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    try:
        return float(Decimal(str(value))) if isinstance(value, str) else None
    except (InvalidOperation, ValueError):
        return None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _flag(value: Any) -> int | None:
    return int(value) if isinstance(value, bool) else None


def run_row(oid: str, payload: dict[str, Any]) -> dict[str, Any]:
    events = payload.get("events") if isinstance(payload.get("events"), list) else []
    return {"oid": oid, "status": _text(payload.get("status")),
            "model": _text(payload.get("model")), "created_at": _num(payload.get("created_at")),
            "steps": len(events),
            "source_run_id": _text(payload.get("source_run_id"))}  # fmt: skip


def step_row(oid: str, payload: dict[str, Any], run: str | None = None,
             seq: int | None = None) -> dict[str, Any]:  # fmt: skip
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    tokens_in = usage.get("input_tokens", usage.get("prompt_tokens"))
    tokens_out = usage.get("output_tokens", usage.get("completion_tokens"))
    return {"oid": oid, "run": run, "seq": seq, "kind": _text(payload.get("kind")),
            "model": _text(payload.get("model")), "provider": _text(payload.get("provider")),
            "cost": _num(payload.get("cost")) or 0.0, "duration": _num(payload.get("duration")),
            "time_unix": _num(payload.get("time_unix")), "input_tokens": _int(tokens_in),
            "output_tokens": _int(tokens_out),
            "error": int(bool(payload.get("error")))}  # fmt: skip


def _signed_attestation(payload: dict[str, Any]) -> bool:
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    result = verify_attestation(payload, trust_embedded=True)
    bound = used_key_fingerprint(payload.get("signature")) == payload.get("signer")
    return bool(result.ok and result.algorithm == "ed25519" and bound)


def monitor_row(oid: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    from opentine._monitor_verdict import CONVENTION

    claim = payload.get("claim")
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return None
    monitor = claim.get("monitor") if isinstance(claim.get("monitor"), dict) else {}
    return {"oid": oid, "target": _text(payload.get("target_id")),
            "signer": _text(payload.get("signer")), "signed": int(_signed_attestation(payload)),
            "monitor": _text(monitor.get("id")), "session": _text(claim.get("session")),
            "tool": _text(claim.get("tool")), "action": _text(claim.get("action")),
            "score": _num(claim.get("score")), "threshold": _num(claim.get("threshold")),
            "enforced": _flag(claim.get("enforced")), "mode": _text(claim.get("mode")),
            "decided_by": _text(claim.get("decided_by")),
            "decided_at": _text(claim.get("decided_at"))}  # fmt: skip


def oversight_row(oid: str, repo: Any) -> dict[str, Any] | None:
    from opentine import _oversight

    row = _oversight.read(repo, oid)
    if row is None:
        return None
    human = row.get("human")
    return {"oid": oid, "item": _text(row["item"]), "anchor": _text(row["anchor"]),
            "previous": _text(row["previous"]), "signer": _text(row["signer"]),
            "signed": int(row["signed"]), "decision": _text(row["decision"]),
            "human": human if isinstance(human, str) else json.dumps(human, sort_keys=True),
            "decided_at": _text(row["decided_at"])}  # fmt: skip


def fast_reader(repo: Any) -> Any:
    """Read a payload checked against its oid, without the link and graph checks of ``get``.

    The index build reads every object once; ``--verify`` uses ``repo.get``.
    """
    from opentine.kernel import ObjectEnvelope

    return lambda oid: ObjectEnvelope.decode(repo.raw(oid), oid).payload()


def object_rows(repo: Any, oid: str, read: Any = None) -> dict[str, list[dict[str, Any]]]:
    """``{table: rows}`` one repository object contributes (steps come from runs)."""
    kind = oid.partition(":")[0]
    if kind not in ("run", "attestation", "annotation"):
        return {}
    read = read or (lambda o: repo.get(o).payload())
    payload = read(oid)
    if not isinstance(payload, dict):
        return {}
    if kind == "run":
        out: dict[str, list[dict[str, Any]]] = {"runs": [run_row(oid, payload)], "steps": []}
        for seq, event in enumerate(payload.get("events") or []):
            if isinstance(event, str):
                body = read(event)
                if isinstance(body, dict):
                    out["steps"].append(step_row(event, body, oid, seq))
        return out
    if kind == "attestation":
        row = monitor_row(oid, payload)
        if row:
            return {"monitor_verdicts": [row]}
        from opentine._query_research import sabotage_row

        row = sabotage_row(oid, payload)
        if row:
            return {"sabotage_tasks": [row]}
        from opentine._query_merges import merge_row

        row = merge_row(oid, payload)
        if row:
            return {"history_merges": [row]}
        from opentine._query_containment import attestation_rows
        from opentine._query_custody import attestation_rows as custody_rows
        from opentine._query_datasets import attestation_rows as dataset_rows
        from opentine._query_policy import attestation_rows as policy_rows
        from opentine._query_transcripts import attestation_rows as flag_rows
        from opentine._query_uplift import attestation_rows as uplift_rows

        found = attestation_rows(oid, payload) or custody_rows(oid, payload)
        found = found or flag_rows(oid, payload) or uplift_rows(oid, payload)
        return found or dataset_rows(oid, payload) or policy_rows(oid, payload)
    value = payload.get("value")
    if isinstance(value, dict) and value.get("convention") == "opentine.oversight-decision/1":
        row = oversight_row(oid, repo)
        return {"oversight_decisions": [row]} if row else {}
    from opentine._query_ingest import annotation_rows

    return annotation_rows(oid, payload)


def lineage_rows(files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    from opentine._lineage_claim import folder_rows

    variants, edges = [], []
    for row in folder_rows(files):
        variants.append({k: row[k] for k in COLUMNS["lineage_variants"]})
        edges += [{"oid": row["oid"], "child": row["variant"], "parent": p}
                  for p in row["parents"]]  # fmt: skip
    return {"lineage_variants": variants, "lineage_edges": edges}


def eval_row(oid: str, source: str, line: int, verdict: Any) -> dict[str, Any] | None:
    from opentine import _eval_verdict

    if not isinstance(verdict, dict) or verdict.get("scheme") != _eval_verdict.SCHEME:
        return None
    try:
        _eval_verdict.verify(verdict)
        signed = 1
    except Exception:  # noqa: BLE001 - a malformed or forged verdict is indexed unsigned
        signed = 0
    return {"oid": oid, "source": source, "line": line, "eval": _text(verdict.get("eval")),
            "dataset": _text(verdict.get("dataset")), "item": _text(verdict.get("item")),
            "run": _text(verdict.get("run")), "scorer": _text(verdict.get("scorer")),
            "score": _num(verdict.get("score")), "threshold": _num(verdict.get("threshold")),
            "passed": _flag(verdict.get("passed")), "signer": _text(verdict.get("signer")),
            "signed": signed, "created_at": _text(verdict.get("created_at"))}  # fmt: skip


def verdict_lines(source: str, raw: bytes) -> list[dict[str, Any]]:
    """Eval rows for every verdict line of one ``.jsonl`` file (bad lines are skipped)."""
    out = []
    for number, line in enumerate(raw.split(b"\n"), start=1):
        line = line.rstrip(b"\r")
        if not line.strip():
            continue
        try:
            verdict = _collusion_verdicts.bare(_json_shallow.loads(line))  # 0.83: unwraps
        except ValueError:
            continue
        row = eval_row("sha256:" + hashlib.sha256(line).hexdigest(), source, number, verdict)
        if row is not None:
            out.append(row)
    return out


__all__ = ["COLUMNS", "CONTEXT", "eval_row", "fast_reader", "lineage_rows", "monitor_row",
           "object_rows", "oversight_row", "run_row", "step_row", "verdict_lines"]  # fmt: skip
