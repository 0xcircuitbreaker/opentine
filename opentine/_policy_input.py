"""The fixed input document a policy is evaluated over (0.74).

Assembled for one subject run from signed records only; a record counts when
its Ed25519 signature verifies and its ``signer`` names the key that signed.
Signers are annotated with their roles from the owner-pinned key roles
(:mod:`opentine._key_roles_pin`) and nothing else; a record signed by a pinned
``optimizer`` key is left out. Lists are sorted, so the same records give the
same document and the same input digest::

    {"subject": {"run", "status", "model", "steps"},
     "roles": "pinned" | "unpinned",
     "evals": [{"eval", "dataset", "item", "scorer_name", "score", "threshold",
                "passed", "signer", "roles", "pinned", "holdout"}],
     "holdouts": [NAME],                       # verified --holdout folders
     "monitors": [{"monitor", "action", "score", "threshold", "enforced",
                   "mode", "signer", "roles"}],
     "oversight": {"decisions": [{"item", "decision", "signer", "roles"}],
                   "approvers": [FINGERPRINT]},  # distinct approve, approver role
     "lineage": {"variants": [{"variant", "parents", "loop", "signer", "roles"}]},
     "integrity": {"taints": N, "fail_codes": [CODE]},
     "budget": null | {"subject", "in_force", "decision", "over", "fail_codes"},
     "sandbox": [{"policy_digest", "signer", "roles"}],
     "containment": [{"category", "step", "signer", "roles"}],
     "params": {...}}                         # policy params, then --param values

A number that JSON cannot carry exactly (an integral value beyond 2**53 - 1)
becomes its decimal string.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from opentine._policy_lang import number_ok

MAX_LINEAGE = 1000


def _safe(value: Any) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        if not number_ok(value):
            return None if isinstance(value, float) and value != value else str(int(value))
        return value
    if isinstance(value, list):
        return [_safe(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _safe(v) for k, v in value.items()}
    return str(value)


def _roles(store: Path) -> tuple[str, dict[str, list[str]]]:
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import pinned

    try:
        found = pinned(store)
    except KeyRoleError:
        found = None
    by_key: dict[str, list[str]] = {}
    for role, keys in sorted((found or {}).items()):
        for key in keys or []:
            by_key.setdefault(key, []).append(role)
    return ("pinned" if found is not None else "unpinned"), by_key


def _evals(store: Path, run: str, eval_dirs: list[str], who: Any, holdouts: list[str]) -> list:
    from opentine._query_build import eval_files
    from opentine._query_rows import verdict_lines

    out = []
    dirs = sorted({Path(d).resolve().as_posix() for d in eval_dirs})
    for source, raw in sorted(eval_files(store, dirs).items()):
        for row in verdict_lines(source, raw):
            if row["run"] != run or not row["signed"] or who(row["signer"]) is None:
                continue
            roles = who(row["signer"])
            out.append({"eval": row["eval"], "dataset": row["dataset"], "item": row["item"],
                        "scorer_name": row["scorer"], "score": row["score"],
                        "threshold": row["threshold"], "passed": bool(row["passed"]),
                        "signer": row["signer"], "roles": roles,
                        "pinned": bool({"scorer", "eval"} & set(roles)),
                        "holdout": row["dataset"] in holdouts})  # fmt: skip
    return out


def _holdouts(folders: list[str], by_key: dict[str, list[str]]) -> list[str]:
    from opentine._holdout import load

    names = set()
    for folder in folders:
        try:
            found = load(Path(folder))
        except Exception:  # noqa: BLE001 - an unverifiable holdout is not a holdout
            continue
        roles = by_key.get(found["signer"], [])
        if "dataset" in roles and "optimizer" not in roles:
            names.add(found["claim"].get("holdout"))
    return sorted(n for n in names if isinstance(n, str))


def _budget(repo: Any, subject: str | None, now_ms: int) -> dict[str, Any] | None:
    if subject is None:
        return None
    from opentine._budget_status import status

    try:
        body = status(repo, subject, now_ms=now_ms)
    except Exception:  # noqa: BLE001 - an unreadable ledger is no policy in force (fail closed)
        return {"subject": subject, "in_force": False, "decision": "deny", "over": [],
                "fail_codes": ["budget.unreadable"]}  # fmt: skip
    return {"subject": subject, "in_force": body["policy"] is not None,
            "decision": body["decision"], "over": sorted(body["over"]),
            "fail_codes": sorted({f["code"] for f in body["findings"]
                                  if f["level"] == "fail"})}  # fmt: skip


def _integrity(root: Path, run: str) -> dict[str, Any]:
    from opentine._integrity_run import LIST, check_run, taints

    found = taints(root, run)
    codes = {c for t in found for c in t.get("codes", []) if str(c).startswith("fail:")}
    if (root / LIST).is_file():
        codes |= {f["code"] for f in check_run(root, run)["findings"] if f["level"] == "fail"}
    return {"taints": len(found), "fail_codes": sorted(codes)}


def build(repo: Any, root: Path, run: str, *, eval_dirs: list[str] | None = None,
          holdouts: list[str] | None = None, budget: str | None = None,
          params: dict[str, Any] | None = None,
          now_ms: int | None = None) -> dict[str, Any]:  # fmt: skip
    """The input document for *run* (a ``run:`` id)."""
    from opentine._query_rows import fast_reader, object_rows

    store = Path(repo.path)
    status, by_key = _roles(store)

    def who(signer: Any) -> list[str] | None:  # roles; None when the signer is an optimizer
        roles = by_key.get(signer, []) if isinstance(signer, str) else []
        return None if "optimizer" in roles else roles

    read = fast_reader(repo)
    tables: dict[str, list[dict[str, Any]]] = {}
    for oid in sorted(repo.iter_oids()):
        if oid.startswith(("attestation:", "annotation:")) or oid == run:
            try:
                for name, rows in object_rows(repo, oid, read).items():
                    tables.setdefault(name, []).extend(rows)
            except Exception:  # noqa: BLE001 - an unreadable object contributes nothing
                continue
    run_row = (tables.get("runs") or [{}])[0]

    def mine(table: str, field: str, value: str) -> list[dict[str, Any]]:
        return [r for r in tables.get(table, []) if r.get(field) == value and r.get("signed")
                and who(r.get("signer")) is not None]  # fmt: skip

    names = _holdouts(list(holdouts or []), by_key)
    decisions = [r for r in mine("oversight_decisions", "anchor", run)]
    approvers = sorted({r["signer"] for r in decisions if r["decision"] == "approve"
                        and "approver" in (who(r["signer"]) or [])})  # fmt: skip
    from opentine._query_build import _lineage_files
    from opentine._query_rows import lineage_rows

    lin = lineage_rows(_lineage_files(store))
    parents: dict[str, list[str]] = {}
    for edge in lin["lineage_edges"]:
        parents.setdefault(edge["oid"], []).append(edge["parent"])
    variants = [{"variant": v["variant"], "parents": sorted(parents.get(v["oid"], [])),
                 "loop": v["loop"], "signer": v["signer"], "roles": who(v["signer"])}
                for v in lin["lineage_variants"]
                if v["signed"] and who(v["signer"]) is not None][:MAX_LINEAGE]  # fmt: skip
    doc = {
        "subject": {"run": run, "status": run_row.get("status"), "model": run_row.get("model"),
                    "steps": run_row.get("steps", 0)},
        "roles": status,
        "evals": _evals(store, run, list(eval_dirs or []), who, names),
        "holdouts": names,
        "monitors": [{k: r[k] for k in ("monitor", "action", "score", "threshold", "mode",
                                        "signer")} | {"enforced": bool(r["enforced"]),
                                                      "roles": who(r["signer"])}
                     for r in mine("monitor_verdicts", "target", run)],
        "oversight": {"decisions": [{"item": r["item"], "decision": r["decision"],
                                     "signer": r["signer"], "roles": who(r["signer"])}
                                    for r in decisions], "approvers": approvers},
        "lineage": {"variants": variants},
        "integrity": _integrity(root, run),
        "budget": _budget(repo, budget, time.time_ns() // 1_000_000 if now_ms is None
                          else now_ms),
        "sandbox": [{"policy_digest": r["policy_digest"], "signer": r["signer"],
                     "roles": who(r["signer"])} for r in mine("sandbox_policies", "target", run)],
        "containment": [{"category": r["category"], "step": r["step"], "signer": r["signer"],
                         "roles": who(r["signer"])}
                        for r in mine("containment_findings", "target", run)],
        "params": dict(params or {}),
    }  # fmt: skip
    return _safe(doc)


__all__ = ["build"]
