"""``tine alert add|list|remove|test`` (0.49): webhook and OTLP alerts.

``add NAME --on TRIGGER [--threshold USD] [--webhook URL] [--otlp ENDPOINT]``
stores a rule (:mod:`opentine._alerts`); ``list`` prints the rules and the
Ed25519 key that signs their webhook deliveries (pin its ``kid`` and
``public_key`` in the receiver, as for a remote's ``caps.webhooks.keys``);
``remove NAME`` drops one. ``test [NAME] [--event FILE] [--always] [--dry-run]``
evaluates the rules on one event -- FILE holds a ``tine-event/1`` object or a
``tine watch --json`` line; without it, the newest entry of the repository's op
log -- and delivers what trips (:mod:`opentine._alerts_deliver`). ``--always``
also sends a ``test: true`` alert for each rule the event does not trip.
``tine watch --alerts`` evaluates the rules on every event it reports.
``--json`` output follows ``tine-cli-alert-1``; ``test`` exits 1 when a
delivery fails.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from opentine._cli_errors import fail
from opentine._cli_json import emit


def add_alert_parser(sub: Any) -> None:
    from opentine._alerts import TRIGGERS

    alert = sub.add_parser("alert", help="Webhook and OTLP alerts on events")
    actions = alert.add_subparsers(dest="alert_action", required=True)
    add = actions.add_parser("add", help="Add an alert rule")
    add.add_argument("name", help="[a-z0-9][a-z0-9._-]{0,63}")
    add.add_argument("--on", required=True, choices=TRIGGERS, help="The trigger")
    add.add_argument("--threshold", type=float, metavar="USD", help="cost.threshold: run cost")
    add.add_argument("--webhook", metavar="URL", help="Signed tine-webhook/1 POST target")
    add.add_argument("--otlp", metavar="ENDPOINT", help="OTLP/HTTP endpoint (adds /v1/logs)")
    add.add_argument("--allow-private", action="store_true",
                     help="Allow http:// and private addresses for --webhook")  # fmt: skip
    add.add_argument("--replace", action="store_true", help="Replace a rule of the same name")
    actions.add_parser("list", help="The rules and the webhook signing key")
    remove = actions.add_parser("remove", help="Remove an alert rule")
    remove.add_argument("name")
    test = actions.add_parser("test", help="Evaluate the rules on one event and deliver")
    test.add_argument("name", nargs="?", help="Only this rule")
    test.add_argument("--event", metavar="FILE", help="A tine-event/1 JSON (default: newest op)")
    test.add_argument("--always", action="store_true", help="Also alert rules it does not trip")
    test.add_argument("--dry-run", action="store_true", help="Evaluate; deliver nothing")
    for parser in actions.choices.values():
        parser.add_argument("--repo", default=".")
        parser.add_argument("--json", action="store_true")


def newest_event(repo_path: Path) -> dict[str, Any]:
    from opentine._cli_watch import _op_event
    from opentine.repository._oplog import read_ops

    ops = read_ops(repo_path)
    if not ops:
        raise ValueError("the op log is empty; pass --event FILE")
    return _op_event(ops[-1])


def read_event(path: str) -> dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(document, dict) and document.get("command") == "watch":
        document = document.get("event")
    if not isinstance(document, dict) or document.get("format") != "tine-event/1":
        raise ValueError(f"{path} is not a tine-event/1 event")
    return document


def run_test(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], bool]:
    from opentine import _alerts, _alerts_deliver

    rules = _alerts.load_rules(repo.path)
    if args.name:
        rules = [rule for rule in rules if rule.get("name") == args.name]
        if not rules:
            raise KeyError(f"no alert {args.name}")
    event = read_event(args.event) if args.event else newest_event(repo.path)
    hits = _alerts.Engine(rules, repo).evaluate(event)
    tripped = {hit["rule"]["name"] for hit in hits}
    results = _alerts_deliver.deliver(hits, event, _alerts.state_dir(repo.path),
                                      dry_run=args.dry_run)  # fmt: skip
    if args.always:
        spare = [{"rule": rule, "finding": {"on": rule["on"], "subject": event.get("id"),
                                            "detail": "test alert"}}
                 for rule in rules if rule["name"] not in tripped]  # fmt: skip
        results += _alerts_deliver.deliver(spare, event, _alerts.state_dir(repo.path),
                                           test=True, dry_run=args.dry_run)  # fmt: skip
    ok = all(row["outcome"] != "failed" for item in results for row in item["deliveries"])
    body = {"event": {"id": event.get("id"), "kind": event.get("kind")}, "alerts": results}
    return body, ok


def _act(args: argparse.Namespace) -> tuple[dict[str, Any], str, bool]:
    from opentine import _alerts, _alerts_deliver
    from opentine._cli_du import _repo

    repo = _repo(args.repo)
    action = args.alert_action
    if action == "add":
        rule = _alerts.make_rule(args.name, args.on, threshold=args.threshold,
                                 webhook=args.webhook, otlp=args.otlp,
                                 allow_private=args.allow_private)  # fmt: skip
        _alerts.add_rule(repo.path, rule, replace=args.replace)
        return {"rule": rule}, f"alert {rule['name']}: {rule['on']}", True
    if action == "remove":
        rules = _alerts.remove_rule(repo.path, args.name)
        return {"rules": rules}, f"removed alert {args.name}", True
    if action == "list":
        rules = _alerts.load_rules(repo.path)
        key = _alerts_deliver.public_key(_alerts_deliver.signing_key(_alerts.state_dir(repo.path)))
        lines = [f"{r['name']}\t{r['on']}\t{r.get('webhook') or '-'}\t{r.get('otlp') or '-'}"
                 for r in rules]  # fmt: skip
        lines.append(f"webhook key {key['kid']} {key['public_key']}")
        return {"rules": rules, "webhook_key": key}, "\n".join(lines), True
    body, ok = run_test(args, repo)
    lines = [f"event {body['event']['kind']} {body['event']['id']}"]
    for item in body["alerts"]:
        outcomes = ", ".join(f"{r['sink']} {r['outcome']}" for r in item["deliveries"])
        lines.append(f"{item['rule']}\t{item['on']}\t{item['detail']}\t{outcomes}")
    if not body["alerts"]:
        lines.append("no rule tripped")
    return body, "\n".join(lines), ok


def cmd_alert(args: argparse.Namespace) -> None:
    try:
        body, text, ok = _act(args)
    except (KeyError, LookupError, OSError, ValueError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(str(message), prefix="tine alert: ")
    if args.json:
        emit({"command": "alert", "action": args.alert_action, "ok": ok, **body})
    else:
        print(text)
    if not ok:
        raise SystemExit(1)


__all__ = ["add_alert_parser", "cmd_alert", "read_event", "run_test"]
