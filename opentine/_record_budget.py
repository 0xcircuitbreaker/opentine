"""The model allowlist and budget inside the ``tine record`` proxy (0.87).

``tine record --budget SUBJECT --budget-key KEY --repo PATH -- CMD`` puts a
:class:`RecordBudget` in front of every model call the child makes. The
subject's ledger and policy are the ones ``tine budget`` and the hook / MCP
gates use (:mod:`opentine._budget_status`); the proxy adds what only a model
path can see:

* the requested model, canonicalised (:func:`opentine._model_path.canonical`),
  must match the policy's ``model_path.allow``;
* a pessimistic estimate (request bytes as input tokens, the request's output
  limit or ``max_output_tokens`` times its fan-out, priced from the catalog) is
  *reserved* on the ledger before the call is forwarded, under one lock
  (:mod:`opentine._budget_lock`), so concurrent calls cannot race past a cap;
* the call is *settled* from the usage the provider returned, or at the
  estimate when the reply carries no usage;
* calls tagged ``X-Opentine-Call-Role: judge`` (or ``scorer``) also count toward
  ``model_path.judge`` caps.

Every refusal is a signed, held ``deny`` ledger entry. Anything that cannot be
decided refuses (fail closed): an unreachable or unreadable ledger, no policy in
force, a request whose model or cost cannot be read, or a money cap with a model
the catalog cannot price. Without ``--budget`` the proxy is unchanged.
"""

from __future__ import annotations

import itertools
import json
import threading
from collections.abc import Callable
from typing import Any

from opentine import _model_path

UNGATED = ("GET", "HEAD", "OPTIONS", "DELETE")


def clock_ms() -> int:
    from opentine._budget_gate import clock_ms as now

    return now()


def role_of(values: list[str]) -> str:
    """``judge`` / ``scorer`` when every role header names one of them, else ``agent``."""
    names = {v.strip().casefold() for v in values}
    return names.pop() if len(names) == 1 and names <= set(_model_path.ROLES) else "agent"


def _parse(raw: bytes) -> Any:
    from opentine._json_shallow import loads, unique_pairs

    try:
        return loads(raw, object_pairs_hook=unique_pairs) if raw else None
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None


class RecordBudget:
    def __init__(self, repo: Any, subject: str, key: Any, *, run: str, catalog: Any = None,
                 now: Callable[[], int] = clock_ms) -> None:  # fmt: skip
        self.repo, self.subject, self.key, self.run, self.now = repo, subject, key, run, now
        self.catalog = catalog
        self._calls = itertools.count(1)
        self._lock = threading.Lock()
        self.denied = 0

    def _price(self, provider: str, model: str, usage: dict[str, int]) -> float | None:
        from opentine.billing import Usage, bill, load_catalogs

        if self.catalog is None:
            self.catalog = load_catalogs()
        result = bill(provider, model, Usage(**usage), catalog=self.catalog)
        return None if result.amount_usd is None else float(result.amount_usd)

    def _deny(self, code: str, detail: str, info: dict[str, Any], status: int = 403):
        from opentine._budget_ledger import append

        with self._lock:
            self.denied += 1
        entry = None
        try:
            entry = append(self.repo, self.subject, "deny", {
                "code": code, "detail": detail, **info}, self.key, at_ms=self.now())  # fmt: skip
        except Exception:  # noqa: BLE001 - the call is refused whether or not it is recorded
            status = 503
        return {"ok": False, "status": status, "code": code, "message": detail, "entry": entry}

    def admit(self, provider: str, dialect: str, method: str, path: str, raw: bytes,
              role: str) -> dict[str, Any]:  # fmt: skip
        """``{"ok": True, "ticket"}`` to forward, else ``{"ok": False, "status", "code", ...}``."""
        if method.upper() in UNGATED:
            return {"ok": True, "ticket": None}
        call = next(self._calls)
        info = {"run": self.run, "call": call, "role": role, "model": "",
                "path": path.split("?", 1)[0][:512], "about": None}  # fmt: skip
        try:
            from opentine._budget_lock import locked

            with locked(self.repo):
                return self._admit(provider, dialect, method, path, raw, role, info)
        except Exception as exc:  # noqa: BLE001 - fail closed
            return self._deny("budget.ledger-unreachable",
                              f"the budget could not be checked: {type(exc).__name__}", info,
                              503)  # fmt: skip

    def _admit(self, provider, dialect, method, path, raw, role, info) -> dict[str, Any]:
        from opentine._budget_ledger import append
        from opentine._budget_status import check

        body = check(self.repo, self.subject, now_ms=self.now(), key=self.key)
        policy = body["policy"]
        if policy is None:
            return self._deny("budget.no-policy", f"no budget policy in force for "
                              f"{self.subject}", info)  # fmt: skip
        info["about"] = policy["entry"]
        if body["decision"] != "allow":
            return self._deny("budget.limit-reached", "budget reached: "
                              + (", ".join(body["over"]) or "ledger forked"), info)  # fmt: skip
        rules = policy.get("model_path") or _model_path.section({})
        seen = _model_path.probe(dialect, method, path, raw, _parse(raw),
                                 rules["max_output_tokens"])  # fmt: skip
        names = [_model_path.canonical(m, rules["aliases"]) for m in seen["models"]]
        info["model"] = (names[0] if names else "") or str((seen["models"] or [""])[0])[:128]
        if seen["problem"]:
            return self._deny("budget.call-unverifiable", seen["problem"], info)
        refused = [m for m, n in zip(seen["models"], names) if not _model_path.allowed(
            n, rules["allow"])]  # fmt: skip
        if refused:
            return self._deny("budget.model-not-allowed",
                              f"model {str(refused[0])[:128]!r} is not allowed", info)  # fmt: skip
        if rules["allow"] is not None and not names and not seen["free"]:
            return self._deny("budget.model-unidentified", "the call names no model", info)
        if seen["free"]:
            return {"ok": True, "ticket": None}
        usage = {"input": seen["input"], "output": seen["output"]}
        judge = role in _model_path.ROLES
        caps = {"tokens": policy["limits"]["tokens"], "money_usd": policy["limits"]["money_usd"]}
        jcaps = rules["judge"] if judge else {}
        money = None
        if caps["money_usd"] is not None or jcaps.get("money_usd") is not None:
            prices = [self._price(provider, n or "", usage) for n in (names or [""])]
            if any(p is None for p in prices):
                return self._deny("budget.model-unpriced", "a money cap is set and the "
                                  "catalog has no price for this model", info)  # fmt: skip
            money = max(prices)
        estimate = {"tokens": usage["input"] + usage["output"], "money_usd": money or 0.0}
        totals = body["totals"]
        for unit, cap in caps.items():
            if cap is not None and totals[unit] + estimate[unit] > cap:
                return self._deny("budget.would-exceed", f"the call could exceed {unit}", info)
        for unit, cap in jcaps.items():
            if cap is not None and totals["judge_" + unit] + estimate[unit] > cap:
                return self._deny("budget.judge-would-exceed",
                                  f"the call could exceed the judge {unit} cap", info)  # fmt: skip
        ticket = {**info, "provider": provider, "estimate": usage, "money": money,
                  "priced": money is not None}  # fmt: skip
        append(self.repo, self.subject, "spend", self._spend(ticket, usage, money, "reserve"),
               self.key, at_ms=self.now())  # fmt: skip
        return {"ok": True, "ticket": ticket}

    def _spend(self, ticket: dict[str, Any], usage: dict[str, int], money: float | None,
               phase: str) -> dict[str, Any]:  # fmt: skip
        cost = {"total_tokens": usage["input"] + usage["output"], "input_tokens": usage["input"],
                "output_tokens": usage["output"], "total_cost": money or 0.0}  # fmt: skip
        return {"run": self.run, "call": ticket["call"], "phase": phase, "role": ticket["role"],
                "model": ticket["model"], "source": "record-proxy", "cost": cost,
                "gpu_hours": 0.0, "egress_bytes": 0}  # fmt: skip

    def settle(self, ticket: dict[str, Any] | None, record: dict[str, Any]) -> None:
        """Replace *ticket*'s reservation with the reported usage (or keep the estimate)."""
        if ticket is None:
            return
        from opentine._budget_ledger import append
        from opentine._record_parse import step_args

        usage, money = dict(ticket["estimate"]), ticket["money"]
        if "status" not in record:  # never reached the provider: nothing was spent
            usage, money = {"input": 0, "output": 0}, 0.0
        else:
            reported = step_args(record).get("usage")
            if isinstance(reported, dict) and reported and _complete(record):
                usage = _reported(reported)
                if ticket["priced"]:
                    price = self._price(ticket["provider"], ticket["model"], usage)
                    money = money if price is None else price
        try:
            append(self.repo, self.subject, "spend", self._spend(ticket, usage, money, "settle"),
                   self.key, at_ms=self.now())  # fmt: skip
        except Exception:  # noqa: BLE001 - the reservation stays and counts (pessimistic)
            pass


def _reported(reported: dict[str, Any]) -> dict[str, int]:
    ins = ("input", "cache_read", "cache_write_5m", "cache_write_1h")
    return {
        "input": sum(int(reported.get(k, 0)) for k in ins),
        "output": int(reported.get("output", 0)) + int(reported.get("reasoning", 0)),
    }


#: The last event of a finished stream, per dialect; a cut stream settles at the estimate.
_ENDS = (b"[DONE]", b"message_stop", b'"finishReason"', b"response.completed")


def _complete(record: dict[str, Any]) -> bool:
    from opentine._record_proxy import MAX_CAPTURE

    raw = record.get("response") or b""
    if record.get("error") or len(raw) >= MAX_CAPTURE:
        return False
    if "event-stream" not in str(record.get("content_type") or ""):
        return True
    return any(end in raw[-65536:] for end in _ENDS)


def refusal(decision: dict[str, Any]) -> bytes:
    """The JSON error body the child gets for a refused call."""
    error = {"type": "opentine_budget", "code": decision["code"],
             "message": f"refused by budget: {decision['message']}",
             "entry": decision.get("entry")}  # fmt: skip
    return json.dumps({"error": error}, sort_keys=True).encode()


__all__ = ["RecordBudget", "refusal", "role_of"]
