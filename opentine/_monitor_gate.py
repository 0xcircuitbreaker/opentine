"""The inline gate (0.63): ask a monitor about one action, decide, record a verdict.

:meth:`Gate.decide` takes an action (an MCP ``method`` and its ``params``)
and returns ``{"outcome": "forward"|"replace"|"block", "verdict", "claim",
"replacement", "reason"}``:

* a stop token covering the agent or session (:mod:`opentine._monitor_stop`)
  blocks in either mode;
* **advisory** mode (the default, owner decision D12) always forwards: the
  verdict is recorded and nothing is blocked;
* **gate** mode, which the operator turns on, waits for the monitor up to
  ``deadline_ms``. A missed deadline or a monitor error blocks when
  ``fail_closed`` is set and forwards otherwise. ``block`` blocks;
  ``resample`` and ``defer`` ask the configured alternate (the untrusted
  policy again, or the trusted one) for a replacement action and record both
  trajectories; a resample is scored again and blocked if it still crosses the
  threshold; with no alternate the action is blocked.

Every verdict that is not ``allow``, and every enforced one, is signed and held
(:mod:`opentine._monitor_verdict`). Gate mode refuses to start without a
repository and a key, so every blocked action has a verdict record. The clock,
the wall clock and the deadline runner are injectable so the deadline and the
fail-closed paths are tested without waiting.

0.69: with a repository and a key, every action is also run through the
advisory containment detectors (:mod:`opentine._containment_detect`) and each
finding is signed and held; this never changes the outcome (owner decision D12).
"""

from __future__ import annotations

import hashlib
import secrets
import subprocess
import threading
import time
from collections.abc import Callable
from typing import Any

from opentine import _containment_detect, _monitor_stop, _monitor_verdict
from opentine._monitor_verdict import CONVENTION, input_digest, text_digest
from opentine._monitor_verdict import valid_reply as _valid
from opentine._monitors import MonitorError
from opentine._utc import rfc3339_utc


def run_with_deadline(fn: Callable[[], Any], seconds: float) -> tuple[bool, Any, Any]:
    """``(finished, value, error)``: *fn* on a daemon thread, waited on for *seconds*."""
    box: dict[str, Any] = {}

    def work() -> None:
        try:
            box["value"] = fn()
        except Exception as exc:  # noqa: BLE001 - reported as a monitor error
            box["error"] = exc

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        return False, None, None
    return True, box.get("value"), box.get("error")


def command_alternate(argv: list[str], timeout: float = 60.0) -> Callable[..., Any]:
    """An alternate that runs *argv*: request JSON on stdin, ``{"params": {...}}`` out."""
    import json

    def alternate(role: str, request: dict[str, Any]) -> dict[str, Any] | None:
        body = json.dumps({**request, "role": role}, sort_keys=True).encode("utf-8")
        done = subprocess.run(argv, input=body, capture_output=True, timeout=timeout,
                              check=False)  # fmt: skip
        reply = json.loads(done.stdout.decode("utf-8")) if done.returncode == 0 else {}
        params = reply.get("params") if isinstance(reply, dict) else None
        return params if isinstance(params, dict) else None

    return alternate


def _activations(request: dict[str, Any], params: dict[str, Any]) -> None:
    """Copy ``_meta["opentine/activations"]`` (checkpoint digest, activations) to *request*."""
    meta = params.get("_meta")
    found = meta.get(ACTIVATIONS) if isinstance(meta, dict) else None
    if isinstance(found, dict):
        request["checkpoint_digest"] = found.get("checkpoint_digest")
        request["activations"] = found.get("activations")


ACTIVATIONS = "opentine/activations"


class Gate:
    def __init__(
        self, config: dict[str, Any], *, repo: Any = None, key: Any = None,
        session: str = "mcp", agent: str | None = None,
        clock: Callable[[], float] = time.monotonic, wall: Callable[[], float] = time.time,
        runner: Callable[..., tuple[bool, Any, Any]] = run_with_deadline,
        alternate: Callable[..., Any] | None = None,
    ) -> None:  # fmt: skip
        if config["mode"] == "gate" and (repo is None or key is None):
            raise MonitorError("gate mode records every blocked action: give a repository "
                               "and a monitor key")  # fmt: skip
        self.config, self.monitor = config, config["monitor"]
        getattr(self.monitor, "bind", lambda _repo: None)(repo)  # 0.83: probe vs calibration
        self.repo, self.key, self.session, self.agent = repo, key, session, agent
        self.clock, self.wall, self.runner = clock, wall, runner
        if alternate is None and config.get("alternate"):
            alternate = command_alternate(config["alternate"])
        self.alternate = alternate
        self.counts = {"forward": 0, "replace": 0, "block": 0, "recorded": 0, "observed": 0}
        self.allowlist: list[str] | None = None  # 0.69: hosts the containment scan allows
        self._lock, self._target = threading.Lock(), None

    def _score(self, request: dict[str, Any]) -> tuple[str, dict[str, Any] | None, int]:
        """``(decided_by, reply or None, latency_ms)`` with the deadline applied."""
        deadline = self.config["deadline_ms"]
        start = self.clock()
        finished, value, error = self.runner(lambda: self.monitor.score(request), deadline / 1e3)
        latency = max(0, int(round((self.clock() - start) * 1000)))
        if not finished or latency > deadline:
            return "deadline", None, latency
        if error is not None or not _valid(value):
            return "error", None, latency
        return "monitor", value, latency

    def _over(self, reply: dict[str, Any]) -> bool:
        return float(reply["score"]) >= float(self.config["threshold"])

    def decide(self, method: str, params: Any, *, reasoning: str | None = None) -> dict[str, Any]:
        from opentine.redaction import redact_text

        params = params if isinstance(params, dict) else {}
        tool = str(params.get("name") or params.get("uri") or method)
        seen, state = reasoning, "unavailable" if reasoning is None else "captured"
        if reasoning is not None and self.config["reasoning"] == "redacted":
            seen, state = redact_text(reasoning), "redacted"
        request = {"tool": tool, "method": method, "arguments": params.get("arguments"),
                   "reasoning": seen}  # fmt: skip
        _activations(request, params)  # 0.83: what a probe monitor reads
        original = input_digest(method, params)
        claim: dict[str, Any] = {
            "convention": CONVENTION, "monitor": self.monitor.identity,
            "input_digest": original, "tool": redact_text(tool), "session": self.session,
            "reasoning": {"state": state, "digest": None if seen is None else text_digest(seen)},
            "score": None, "threshold": float(self.config["threshold"]),
            "mode": self.config["mode"], "deadline_ms": self.config["deadline_ms"],
            "fail_closed": self.config["fail_closed"], "latency_ms": 0, "stop": None,
            "trajectories": [{"role": "original", "digest": original}], "chosen": "original",
            "decided_at": rfc3339_utc(self.wall()),
        }  # fmt: skip
        stopped = _monitor_stop.active(self.repo, _monitor_stop.scopes(
            self.agent, self.session)) if self.repo is not None else None  # fmt: skip
        if stopped is not None:
            claim.update(action="block", decided_by="stop-token", stop=stopped["token"])
            return self._finish(claim, "block", None, f"stopped ({stopped['scope']})")
        self._observe(tool, params.get("arguments"), claim["decided_at"])
        decided_by, reply, claim["latency_ms"] = self._score(request)
        claim["decided_by"] = decided_by
        if reply is None:
            claim["action"] = "block" if self.config["fail_closed"] else "allow"
        else:
            claim["score"] = float(reply["score"])
            over = self._over(reply)
            claim["action"] = reply.get("action", self.config["action"]) if over else "allow"
            claim.update({k: reply[k] for k in ("category", "severity") if over and reply.get(k)})
        gate = self.config["mode"] == "gate"
        action = claim["action"]
        if not gate or action in ("allow", "flag"):
            return self._finish(claim, "forward", None, action)
        if action == "block":
            return self._finish(claim, "block", None, f"{decided_by}: block")
        return self._swap(claim, request, method)

    def _swap(self, claim: dict[str, Any], request: dict[str, Any], method: str) -> dict[str, Any]:
        role = "resample" if claim["action"] == "resample" else "trusted"
        try:
            replacement = self.alternate(role, request) if self.alternate else None
        except (OSError, ValueError, subprocess.SubprocessError):
            replacement = None
        if replacement is None:
            claim["chosen"] = "none"
            return self._finish(claim, "block", None, f"{claim['action']}: no alternate")
        entry: dict[str, Any] = {"role": role, "digest": input_digest(method, replacement)}
        if role == "resample":
            alt = {**request, "arguments": replacement.get("arguments")}
            decided_by, reply, _ = self._score(alt)
            entry["score"] = None if reply is None else float(reply["score"])
            if reply is None or self._over(reply):
                claim["trajectories"].append(entry)
                claim.update(chosen="none", decided_by="alternate")
                return self._finish(claim, "block", None, "resample still over the threshold")
        claim["trajectories"].append(entry)
        claim["chosen"] = role
        return self._finish(claim, "replace", replacement, f"{claim['action']}: {role}")

    def _finish(self, claim: dict[str, Any], outcome: str, replacement: Any, reason: str):
        claim["enforced"] = outcome != "forward"
        verdict = None
        if (
            self.repo is not None
            and self.key is not None
            and (claim["action"] != "allow" or claim["enforced"])
        ):
            with self._lock:
                verdict = _monitor_verdict.record(self.repo, self._run(), claim, self.key)
                self.counts["recorded"] += 1
        self.counts[outcome] += 1
        if verdict is not None and replacement is not None:
            meta = dict(replacement.get("_meta") or {})
            meta[_monitor_verdict.META_KEY] = {"verdict": verdict}
            replacement = {**replacement, "_meta": meta}
        return {"outcome": outcome, "verdict": verdict, "claim": claim,
                "replacement": replacement, "reason": reason}  # fmt: skip

    def _observe(self, tool: str, arguments: Any, at: str) -> None:
        """Sign and hold advisory containment findings on this action (never blocks)."""
        if self.repo is None or self.key is None:
            return
        text = _containment_detect.text_of(tool, arguments)
        evidence = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        for hit in _containment_detect.scan_text(text, self.allowlist):
            finding = {**hit, "step": self.counts["observed"], "evidence_digest": evidence}
            with self._lock:
                _containment_detect.record(self.repo, self._run(), finding, self.key, at)
        self.counts["observed"] += 1

    def _run(self) -> str:
        if self._target is None:
            from opentine.graph import Run, StepKind
            from opentine.policies import PolicySet

            run = Run(id=f"monitor-{secrets.token_hex(8)}", model_info="opentine/monitor",
                      user_prompt=f"monitor session {self.session}",
                      policies=PolicySet().to_dict())  # fmt: skip
            run.add_step(StepKind.done, {"text": f"monitor {self.monitor.identity['id']}"})
            self._target = self.repo.put_run(run).run_id
        return self._target


__all__ = ["Gate", "command_alternate", "run_with_deadline"]
