"""Pluggable inline monitors (0.63): rule, local model command, remote API.

A monitor scores one proposed action. :meth:`Monitor.score` receives::

    {"tool": NAME, "method": "tools/call", "arguments": {...},
     "reasoning": TEXT or None}

and returns ``{"score": 0.0..1.0}`` (``"action"`` may name one of
``flag|resample|defer|block`` to override the configured one). ``identity``
is what each verdict records: ``{"id", "kind", "model_digest"}``.

* ``rule``: ``[[monitor.rules]]`` rows of ``tool`` (an ``fnmatch`` pattern on
  the tool name), ``pattern`` (a regular expression searched in the canonical
  JSON of the arguments) and ``score``; the highest matching score wins. Its
  ``model_digest`` is the digest of the rules, so it is deterministic.
* ``command``: a local model run as ``command = [ARGV...]``; the request is
  JSON on stdin, the reply JSON on stdout. ``model_digest`` is declared.
* ``http``: a remote API; the request is POSTed as JSON to ``url``.

The configuration file (``--monitor FILE``, TOML) is documented in
docs/MONITORS.md; :func:`load` reads it.
"""

from __future__ import annotations

import fnmatch
import json
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any, Protocol

from opentine._monitor_verdict import ACTIONS, KINDS, MODES, digest
from opentine.kernel import canonical_json

MAX_RULES = 1024
MAX_REPLY = 1024 * 1024
_KEYS = {"version", "mode", "deadline_ms", "fail_closed", "reasoning", "monitor", "alternate"}


class MonitorError(ValueError):
    """A monitor configuration that cannot be used, or a reply that is not a score."""


class Monitor(Protocol):
    identity: dict[str, Any]

    def score(self, request: dict[str, Any]) -> dict[str, Any]: ...


def _reply(data: bytes) -> dict[str, Any]:
    try:
        reply = json.loads(data[:MAX_REPLY].decode("utf-8"))
        score = float(reply["score"])
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        raise MonitorError(f"the monitor reply is not {{'score': NUMBER}}: {exc}") from exc
    if not 0.0 <= score <= 1.0:
        raise MonitorError("a monitor score is between 0 and 1")
    action = reply.get("action")
    if action is not None and action not in ACTIONS[1:]:
        raise MonitorError(f"a monitor action is one of {', '.join(ACTIONS[1:])}")
    return {"score": score, **({"action": action} if action else {})}


class RuleMonitor:
    def __init__(self, ident: str, rules: list[dict[str, Any]]) -> None:
        if not isinstance(rules, list) or len(rules) > MAX_RULES:
            raise MonitorError(f"monitor.rules is a list of at most {MAX_RULES} rules")
        self._rules = []
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) - {"tool", "pattern", "score", "action"}:
                raise MonitorError("a rule has tool, pattern, score and optionally action")
            try:
                compiled = re.compile(str(rule.get("pattern", "")))
                score = float(rule.get("score", 1.0))
            except (re.error, TypeError, ValueError) as exc:
                raise MonitorError(f"bad rule {rule!r}: {exc}") from exc
            if not 0.0 <= score <= 1.0 or rule.get("action", "block") not in ACTIONS[1:]:
                raise MonitorError(f"bad rule {rule!r}: score 0..1, action flag..block")
            self._rules.append((str(rule.get("tool", "*")), compiled, score, rule.get("action")))
        self.identity = {"id": ident, "kind": "rule", "model_digest": digest(rules)}

    def score(self, request: dict[str, Any]) -> dict[str, Any]:
        text = canonical_json(request.get("arguments")).decode("utf-8")
        best: dict[str, Any] = {"score": 0.0}
        for tool, pattern, score, action in self._rules:
            if fnmatch.fnmatchcase(str(request.get("tool", "")), tool) and pattern.search(text):
                if score > best["score"]:
                    best = {"score": score, **({"action": action} if action else {})}
        return best


class CommandMonitor:
    def __init__(self, ident: str, command: list[str], model: str | None, timeout: float) -> None:
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(p, str) for p in command)
        ):
            raise MonitorError("monitor.command is a non-empty list of strings")
        self.command, self.timeout = command, timeout
        self.identity = {"id": ident, "kind": "command", "model_digest": model}

    def score(self, request: dict[str, Any]) -> dict[str, Any]:
        done = subprocess.run(self.command, input=canonical_json(request), capture_output=True,
                              timeout=self.timeout, check=False)  # fmt: skip
        if done.returncode != 0:
            raise MonitorError(f"the monitor command exited {done.returncode}")
        return _reply(done.stdout)


class HttpMonitor:
    def __init__(self, ident: str, url: str, model: str | None, timeout: float) -> None:
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise MonitorError("monitor.url is an http(s) URL")
        self.url, self.timeout = url, timeout
        self.identity = {"id": ident, "kind": "http", "model_digest": model}

    def score(self, request: dict[str, Any]) -> dict[str, Any]:
        import urllib.request

        call = urllib.request.Request(self.url, data=canonical_json(request), method="POST",
                                      headers={"Content-Type": "application/json"})  # fmt: skip
        with urllib.request.urlopen(call, timeout=self.timeout) as reply:  # noqa: S310
            return _reply(reply.read(MAX_REPLY + 1))


def build(section: dict[str, Any], timeout: float = 60.0) -> Monitor:
    """A monitor from the ``[monitor]`` table."""
    kind, ident = section.get("kind"), section.get("id")
    if kind not in KINDS or not isinstance(ident, str) or not ident:
        raise MonitorError(f"[monitor] needs id and kind ({', '.join(KINDS)})")
    model = section.get("model_digest")
    if model is not None and not isinstance(model, str):
        raise MonitorError("monitor.model_digest is a string")
    if kind == "rule":
        return RuleMonitor(ident, section.get("rules", []))
    if kind == "command":
        return CommandMonitor(ident, section.get("command"), model, timeout)
    return HttpMonitor(ident, section.get("url"), model, timeout)


def parse(document: Any) -> dict[str, Any]:
    """The checked configuration: mode, deadline, fail mode, reasoning, threshold, action."""
    if not isinstance(document, dict) or set(document) - _KEYS or document.get("version") != 1:
        raise MonitorError(f"a monitor config has version = 1 and only {sorted(_KEYS)}")
    section = document.get("monitor")
    if not isinstance(section, dict):
        raise MonitorError("a monitor config needs a [monitor] table")
    config = {
        "mode": document.get("mode", "advisory"),
        "deadline_ms": document.get("deadline_ms", 250),
        "fail_closed": document.get("fail_closed", False),
        "reasoning": document.get("reasoning", "captured"),
        "threshold": section.get("threshold", 0.5),
        "action": section.get("action", "block"),
        "alternate": (document.get("alternate") or {}).get("command"),
    }
    if config["mode"] not in MODES or config["reasoning"] not in ("captured", "redacted"):
        raise MonitorError("mode is advisory or gate; reasoning is captured or redacted")
    if type(config["deadline_ms"]) is not int or not 1 <= config["deadline_ms"] <= 600_000:
        raise MonitorError("deadline_ms is an integer from 1 to 600000")
    if not isinstance(config["fail_closed"], bool) or config["action"] not in ACTIONS[1:]:
        raise MonitorError("fail_closed is a boolean; action is flag, resample, defer or block")
    if not isinstance(config["threshold"], (int, float)) or not 0 <= config["threshold"] <= 1:
        raise MonitorError("monitor.threshold is between 0 and 1")
    config["monitor"] = build(section)
    return config


def load(path: str | Path) -> dict[str, Any]:
    try:
        document = tomllib.loads(Path(path).read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise MonitorError(f"cannot read monitor config {path}: {exc}") from exc
    return parse(document)


__all__ = ["CommandMonitor", "HttpMonitor", "Monitor", "MonitorError", "RuleMonitor", "build",
           "load", "parse"]  # fmt: skip
