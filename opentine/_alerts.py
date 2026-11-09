"""Alert rules evaluated on ``tine-event/1`` events (0.49).

A rule names a trigger, an optional threshold and its sinks (a signed webhook
URL, an OTLP/HTTP logs endpoint, or both). Rules live in the repository at
``.tine/alerts/rules.json``; the Ed25519 key that signs webhook deliveries is
``.tine/alerts/webhook-ed25519.key`` (created on first use, mode 0600), the
same ``tine-webhook/1`` scheme a remote uses (SPEC 8.13).

Alerts are evaluated on events, never on free-standing claims: ``op.logged``
(a local op log entry, as ``tine watch`` reports it) and ``run.created`` (a
remote's event) announce runs, which are loaded from the repository and
checked; ``log.checkpoint`` events are compared with the previous checkpoint of
the same origin. Triggers:

``verify.failed``         an attestation on an announced run whose signature
                          does not verify (``mismatch``; unsigned and
                          unknown-key attestations are not failures).
``policy.denied``         a ``policy`` step whose outputs carry a deny decision.
``cost.threshold``        a run whose total cost exceeds the rule's threshold (USD).
``witness.disagreement``  a checkpoint that rolls back (smaller size) or forks
                          (same size, different root) against the last one seen.

No new object kind or wire format: a delivery is a ``tine-webhook/1`` body
whose ``event`` is the triggering event, plus an ``alert`` member (the envelope
is open), or an OTLP log record (:mod:`opentine._alerts_deliver`).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

TRIGGERS = ("verify.failed", "policy.denied", "cost.threshold", "witness.disagreement")
RULES_FILE = "rules.json"
MAX_RULES = 64
MAX_RUNS = 100
NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
DENY = frozenset({"deny", "denied", "block", "blocked", "reject", "rejected"})


def state_dir(repo_path: Path) -> Path:
    from opentine.repository._paths import internal_path

    path = internal_path(Path(repo_path), "alerts")
    path.mkdir(exist_ok=True)
    return path


def load_rules(repo_path: Path) -> list[dict[str, Any]]:
    try:
        raw = (state_dir(repo_path) / RULES_FILE).read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    rules = json.loads(raw).get("rules")
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        raise ValueError(f"{RULES_FILE}: 'rules' must be a list of objects")
    return rules


def save_rules(repo_path: Path, rules: list[dict[str, Any]]) -> None:
    from opentine._codec_io import atomic_write_bytes

    body = json.dumps({"rules": rules}, indent=2, sort_keys=True) + "\n"
    atomic_write_bytes(state_dir(repo_path) / RULES_FILE, body.encode("utf-8"))


def make_rule(name: str, on: str, *, threshold: float | None = None, webhook: str | None = None,
              otlp: str | None = None, allow_private: bool = False) -> dict[str, Any]:  # fmt: skip
    """A checked rule; ``ValueError`` names what is wrong with it."""
    from opentine.remote._webhooks import check_url

    if not NAME.fullmatch(name):
        raise ValueError("alert name must match [a-z0-9][a-z0-9._-]{0,63}")
    if on not in TRIGGERS:
        raise ValueError(f"--on must be one of {', '.join(TRIGGERS)}")
    if (on == "cost.threshold") != (threshold is not None):
        raise ValueError("--threshold is required by cost.threshold and taken by nothing else")
    if threshold is not None and not threshold >= 0:
        raise ValueError("--threshold must be a non-negative number of USD")
    if not webhook and not otlp:
        raise ValueError("an alert needs a sink: --webhook URL and/or --otlp ENDPOINT")
    if webhook:
        check_url(webhook, allow_private)
    if otlp and not re.match(r"^https?://", otlp):
        raise ValueError("--otlp must be an http(s):// OTLP/HTTP endpoint")
    return {"name": name, "on": on, "threshold": threshold, "webhook": webhook or None,
            "otlp": otlp or None, "allow_private": bool(allow_private)}  # fmt: skip


def add_rule(repo_path: Path, rule: dict[str, Any], *, replace: bool = False) -> list[dict]:
    rules = [r for r in load_rules(repo_path) if r.get("name") != rule["name"] or not replace]
    if any(r.get("name") == rule["name"] for r in rules):
        raise ValueError(f"alert {rule['name']} exists (pass --replace)")
    if len(rules) >= MAX_RULES:
        raise ValueError(f"at most {MAX_RULES} alert rules")
    rules.append(rule)
    save_rules(repo_path, rules)
    return rules


def remove_rule(repo_path: Path, name: str) -> list[dict]:
    rules = load_rules(repo_path)
    kept = [r for r in rules if r.get("name") != name]
    if len(kept) == len(rules):
        raise KeyError(f"no alert {name}")
    save_rules(repo_path, kept)
    return kept


def announced_runs(event: dict[str, Any]) -> list[str]:
    """The run oids an ``op.logged`` or ``run.created`` event announces."""
    data = event.get("data") if isinstance(event.get("data"), dict) else {}
    if event.get("kind") == "run.created":
        found = [r for r in data.get("runs") or [] if isinstance(r, str)]
    elif event.get("kind") == "op.logged":
        rows = [r for r in data.get("refs") or [] if isinstance(r, dict)]
        found = [r["new"] for r in rows if isinstance(r.get("new"), str)]
    else:
        return []
    return list(dict.fromkeys(r for r in found if r.startswith("run:")))[:MAX_RUNS]


def run_findings(repo: Any, oid: str) -> list[dict[str, Any]]:
    """Every finding one run gives: verify failures, policy denials and its cost."""
    found: list[dict[str, Any]] = []
    for attestation in repo.attestations_for(oid):
        result = repo.verify_attestation(attestation, trust_embedded=True)
        if result.state == "mismatch":
            found.append({"on": "verify.failed", "subject": oid,
                          "detail": f"attestation {attestation}: {result.reason}"})  # fmt: skip
    run = repo.load_run(oid)
    for step in run.steps:
        outputs = step.outputs if isinstance(step.outputs, dict) else {}
        verdict = outputs.get("decision") or outputs.get("verdict") or outputs.get("action")
        if step.kind == "policy" and str(verdict).lower() in DENY:
            reason = str(outputs.get("reason") or outputs.get("rule") or verdict)[:512]
            found.append({"on": "policy.denied", "subject": oid,
                          "detail": f"step {step.id}: {reason}"})  # fmt: skip
    found.append({"on": "cost.threshold", "subject": oid, "value": float(run.total_cost),
                  "detail": f"run cost ${run.total_cost:.4f}"})  # fmt: skip
    return found


class Engine:
    """Rule evaluation over a stream of events; remembers checkpoints it has seen."""

    def __init__(self, rules: list[dict[str, Any]], repo: Any = None):
        self.rules, self.repo = rules, repo
        self.checkpoints: dict[str, tuple[int, str]] = {}

    def findings(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        if event.get("kind") == "log.checkpoint":
            return self._checkpoint(event.get("data") or {})
        found: list[dict[str, Any]] = []
        for oid in announced_runs(event) if self.repo is not None else []:
            try:
                found.extend(run_findings(self.repo, oid))
            except (KeyError, LookupError, OSError, ValueError):
                continue  # a run this repository does not hold is not evaluated
        return found

    def _checkpoint(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        origin, size, root = str(data.get("origin")), data.get("size"), str(data.get("root"))
        if not isinstance(size, int):
            return []
        last, self.checkpoints[origin] = self.checkpoints.get(origin), (size, root)
        if last is None or (size > last[0]) or (size, root) == last:
            return []
        what = "rollback" if size < last[0] else "fork"
        return [
            {
                "on": "witness.disagreement",
                "subject": origin,
                "detail": f"{what}: size {size} root {root} after size {last[0]} root {last[1]}",
            }
        ]

    def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """``[{rule, finding}]`` for every rule a finding of *event* trips."""
        hits = []
        for finding in self.findings(event):
            for rule in self.rules:
                if rule.get("on") != finding["on"]:
                    continue
                if finding["on"] == "cost.threshold" and not (
                    finding["value"] > float(rule.get("threshold") or 0)
                ):
                    continue
                hits.append({"rule": rule, "finding": finding})
        return hits


__all__ = [
    "TRIGGERS",
    "Engine",
    "add_rule",
    "announced_runs",
    "load_rules",
    "make_rule",
    "remove_rule",
    "run_findings",
    "state_dir",
]
