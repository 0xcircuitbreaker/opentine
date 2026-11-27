"""The work behind ``tine budget`` (0.69); see :mod:`opentine._cli_budget`."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from opentine import _budget_ledger, _budget_policy, _budget_status

MAX_POLICY_BYTES = 64 * 1024


def _public(status: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in status.items() if k not in ("unflagged", "flags")}


def _lines(status: dict[str, Any]) -> list[str]:
    policy = status["policy"]
    head = (f"{status['subject']}: {status['decision']}"
            + (f" (over: {', '.join(status['over'])})" if status["over"] else ""))  # fmt: skip
    lines = [head, f"  policy: {policy['sha256']} serial {policy['serial']}" if policy
             else "  policy: none in force", f"  roles: {status['roles']}"]  # fmt: skip
    for name, used in status["totals"].items():
        if name in _budget_policy.LIMITS:
            cap = (policy or {}).get("limits", {}).get(name)
            lines.append(f"  {name}: {used}" + (f" of {cap}" if cap is not None else ""))
    rules = (policy or {}).get("model_path")
    if rules:
        allow = "any" if rules["allow"] is None else ", ".join(rules["allow"]) or "none"
        lines.append(f"  models: {allow}")
        for unit in ("tokens", "money_usd"):
            cap = rules["judge"].get(unit)
            used = status["totals"]["judge_" + unit]
            lines.append(f"  judge_{unit}: {used}" + (f" of {cap}" if cap is not None else ""))
    lines += [f"  {f['code']}: {f['message']}" for f in status["findings"]]
    return lines


def _model_path(args: argparse.Namespace) -> dict[str, Any] | None:
    """The ``model_path`` section the sign-policy flags ask for (0.87), or ``None``."""
    aliases = {}
    for item in getattr(args, "model_alias", None) or []:
        alias, sep, name = item.partition("=")
        if not sep:
            raise ValueError(f"--model-alias wants ALIAS=NAME, not {item!r}")
        aliases[alias] = name
    judge = {"tokens": getattr(args, "judge_tokens", None),
             "money_usd": getattr(args, "judge_money_usd", None)}  # fmt: skip
    section: dict[str, Any] = {"allow": getattr(args, "allow_model", None), "aliases": aliases,
                               "judge": judge}  # fmt: skip
    if getattr(args, "max_output_tokens", None) is not None:
        section["max_output_tokens"] = args.max_output_tokens
    if section["allow"] is None and not aliases and set(judge.values()) == {None} and (
            "max_output_tokens" not in section):  # fmt: skip
        return None
    return section


def _sign(args: argparse.Namespace, now_ms: int) -> tuple[dict[str, Any], list[str], int]:
    from opentine._key_hygiene import ed25519_private

    limits = {n: getattr(args, n) for n in _budget_policy.LIMITS}
    limits = {n: (int(v) if v is not None and n in _budget_policy.INTEGER else v)
              for n, v in limits.items()}  # fmt: skip
    doc = _budget_policy.build(args.subject, limits, serial=args.serial,
                               on_limit=args.on_limit, issued_at=_budget_ledger.rfc3339(now_ms),
                               model_path=_model_path(args))  # fmt: skip
    signed = _budget_policy.sign(doc, ed25519_private(args.key))
    path = Path(args.out)
    path.write_bytes((json.dumps(signed, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    out = {"policy": {"subject": signed["subject"], "serial": signed["serial"],
                      "sha256": _budget_policy.digest(signed),
                      "signer": _budget_policy.signer(signed)}}  # fmt: skip
    return out, [f"signed {path.as_posix()} ({out['policy']['sha256']})"], 0


def _apply(args: argparse.Namespace, repo: Any, key: Any, now_ms: int):
    raw = Path(args.policy).read_bytes()
    if len(raw) > MAX_POLICY_BYTES:
        raise ValueError(f"{args.policy} exceeds {MAX_POLICY_BYTES} bytes")
    doc = json.loads(raw)
    subject = _budget_policy.body(doc)["subject"]
    oid = _budget_ledger.append(repo, subject, "policy", {"policy": doc}, key, at_ms=now_ms)
    status = _budget_status.check(repo, subject, now_ms=now_ms, key=key)
    accepted = (status["policy"] or {}).get("entry") == oid
    refused = [f for f in status["findings"] if f["entry"] == oid]
    out = {"entry": oid, "accepted": accepted, "flags": status["flags"],
           "status": _public(status)}  # fmt: skip
    word = "in force" if accepted else "refused: " + ", ".join(f["code"] for f in refused)
    return out, [f"policy entry {oid}: {word}", *_lines(status)], 0 if accepted else 1


def _record(args: argparse.Namespace, repo: Any, key: Any, now_ms: int):
    from opentine._cli_execute import _loaded_run
    from opentine._cost_export import aggregate

    _budget_policy.subject(args.subject)
    if args.gpu_hours < 0 or args.egress_bytes < 0:
        raise ValueError("--gpu-hours and --egress-bytes are not negative")
    entries = []
    for ref in args.runs:
        _, run = _loaded_run(ref)
        fields = {"run": str(run.id), "cost": aggregate(run), "gpu_hours": args.gpu_hours,
                  "egress_bytes": args.egress_bytes}  # fmt: skip
        entries.append(_budget_ledger.append(repo, args.subject, "spend", fields, key,
                                             at_ms=now_ms))  # fmt: skip
    status = _budget_status.status(repo, args.subject, now_ms=now_ms)
    out = {"entries": entries, "status": _public(status)}
    return out, [*(f"spend {e}" for e in entries), *_lines(status)], 0


def _ledger(repo: Any, subject: str, now_ms: int) -> tuple[dict[str, Any], list[str], int]:
    status = _budget_status.status(repo, subject, now_ms=now_ms)
    rows = []
    for row in _budget_ledger.entries(repo, subject):
        value = row["value"]
        item = {
            "id": row["id"],
            "previous": row["previous"],
            "signer": row["signer"],
            "signed": row["signed"],
            "entry": value.get("entry"),
            "at": value.get("at"),
        }
        if value.get("entry") == "spend":
            cost = value.get("cost") if isinstance(value.get("cost"), dict) else {}
            item.update(run=value.get("run"), money_usd=cost.get("total_cost"),
                        tokens=cost.get("total_tokens"))  # fmt: skip
        elif value.get("entry") in ("flag", "deny"):
            item.update(code=value.get("code"), about=value.get("about"))
        rows.append(item)
    lines = [f"{r['entry']:6} {r['id']} {r.get('run') or r.get('code') or ''}".rstrip()
             for r in rows]  # fmt: skip
    return {"entries": rows, "totals": status["totals"]}, [*lines, *_lines(status)[3:]], 0


def body(args: argparse.Namespace, now_ms: int) -> tuple[dict[str, Any], list[str], int]:
    from opentine._key_hygiene import ed25519_private
    from opentine.repo import Repo

    verb = args.budget_command
    if verb == "sign-policy":
        return _sign(args, now_ms)
    repo = Repo.open(args.repo)
    key = ed25519_private(args.key) if args.key else None
    if verb == "apply":
        return _apply(args, repo, key, now_ms)
    if verb == "record":
        return _record(args, repo, key, now_ms)
    if verb == "ledger":
        return _ledger(repo, args.subject, now_ms)
    status = _budget_status.check(repo, args.subject, now_ms=now_ms, key=key)
    out = {"status": _public(status), "flags": status["flags"]}
    code = 1 if verb == "check" and status["decision"] != "allow" else 0
    return out, _lines(status), code


__all__ = ["body"]
