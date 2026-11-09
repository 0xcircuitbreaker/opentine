"""Deliver alerts: signed ``tine-webhook/1`` POSTs and OTLP/HTTP log records (0.49).

A webhook delivery is the 0.45.1 envelope (SPEC 8.13) with ``webhook`` set to
``alert:<rule name>`` and ``event`` the triggering ``tine-event/1`` event; the
alert itself rides in the envelope's ``alert`` member (``rule``, ``on``,
``subject``, ``detail``, ``value``, ``threshold``, ``test``). It is signed with
the repository's alert key (``tine alert list`` prints it for receivers to pin)
and sent like a remote's delivery: https only and global addresses only unless
the rule allows private targets, redirects never followed, 408/429/5xx and
connection errors retried (``ATTEMPTS`` in all, 1 s then 2 s apart).

An OTLP delivery POSTs one OTLP/JSON ``ExportLogsServiceRequest`` to
``<endpoint>/v1/logs``: one log record per alert, severity ``ERROR`` for
``verify.failed`` and ``witness.disagreement``, ``WARN`` otherwise, the
summary as the body and ``opentine.alert.*`` attributes.
"""

from __future__ import annotations

import http.client
import json
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from opentine import _webhook_sig

ATTEMPTS = 3
LOGS_PATH = "/v1/logs"
_ERROR = {"verify.failed", "witness.disagreement"}


def signing_key(state: Path) -> Any:
    from opentine.remote._webhooks import load_key

    return load_key(state)


def public_key(key: Any) -> dict[str, str]:
    raw = key.public_key().public_bytes_raw()
    return {"kid": _webhook_sig.key_id(raw), "alg": "ed25519",
            "public_key": _webhook_sig.b64url(raw)}  # fmt: skip


def alert_body(rule: dict[str, Any], finding: dict[str, Any], test: bool) -> dict[str, Any]:
    return {"rule": rule["name"], "on": finding["on"], "subject": finding.get("subject"),
            "detail": finding.get("detail", ""), "value": finding.get("value"),
            "threshold": rule.get("threshold"), "test": test}  # fmt: skip


def webhook_payload(event: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
    return {"alert": alert, "delivery": str(uuid.uuid4()), "event": event,
            "format": _webhook_sig.FORMAT, "webhook": f"alert:{alert['rule']}"}  # fmt: skip


def logs_url(endpoint: str) -> str:
    parts = urlsplit(endpoint)
    path = parts.path.rstrip("/")
    if not path.endswith(LOGS_PATH):
        path += LOGS_PATH
    return urlunsplit(parts._replace(path=path, fragment=""))


def _attr(key: str, value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, (int, float)):
        return {"key": key, "value": {"doubleValue": float(value)}}
    return {"key": key, "value": {"stringValue": str(value)}}


def otlp_logs(event: dict[str, Any], alerts: list[dict[str, Any]], now_ns: int) -> dict:
    records = []
    for alert in alerts:
        error = alert["on"] in _ERROR
        attrs = [_attr(f"opentine.alert.{k}", alert[k]) for k in sorted(alert)
                 if alert[k] is not None]  # fmt: skip
        attrs += [_attr("opentine.event.id", event.get("id")),
                  _attr("opentine.event.kind", event.get("kind"))]  # fmt: skip
        records.append({"timeUnixNano": str(now_ns), "observedTimeUnixNano": str(now_ns),
                        "severityNumber": 17 if error else 13,
                        "severityText": "ERROR" if error else "WARN",
                        "body": {"stringValue": f"{alert['on']} ({alert['rule']}): "
                                                f"{alert['detail']}"},
                        "attributes": attrs})  # fmt: skip
    resource = {"attributes": [_attr("service.name", "opentine")]}
    scope = {"name": "opentine.alerts"}
    return {"resourceLogs": [{"resource": resource,
                              "scopeLogs": [{"scope": scope, "logRecords": records}]}]}  # fmt: skip


def send_webhook(url: str, payload: dict[str, Any], key: Any, allow_private: bool,
                 *, sender: Any = None, base_delay: float = 1.0) -> dict[str, Any]:  # fmt: skip
    from opentine.remote._webhook_delivery import RETRY, post

    sender = sender or post
    body = _webhook_sig.canonical_body(payload)
    status: int | str = "not-sent"
    for attempt in range(1, ATTEMPTS + 1):
        headers = {"Content-Type": "application/json", "User-Agent": "opentine-webhook/1",
                   _webhook_sig.HEADER: _webhook_sig.sign(key, body),
                   _webhook_sig.DELIVERY_HEADER: payload["delivery"]}  # fmt: skip
        try:
            status = sender(url, body, headers, allow_private)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            status = type(exc).__name__
        if isinstance(status, int) and 200 <= status < 300:
            return {"sink": "webhook", "target": url, "status": status, "outcome": "delivered",
                    "attempts": attempt, "delivery": payload["delivery"]}  # fmt: skip
        if isinstance(status, int) and status not in RETRY and status < 500:
            break
        if attempt < ATTEMPTS:
            time.sleep(base_delay * 2 ** (attempt - 1))
    return {"sink": "webhook", "target": url, "status": status, "outcome": "failed",
            "attempts": attempt, "delivery": payload["delivery"]}  # fmt: skip


def send_otlp(endpoint: str, document: dict[str, Any], *, sender: Any = None,
              allow_private: bool = False) -> dict:  # fmt: skip
    from opentine._alerts import check_otlp
    from opentine.remote._webhooks import resolve
    from opentine.trace._otlp_push import post

    url = logs_url(endpoint)
    try:
        if sender is None:  # every address the host resolves to is checked first
            resolve(*check_otlp(endpoint, allow_private), allow_private)
        status, detail = (sender or post)(url, json.dumps(document).encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - httpx errors, deadline: one failed delivery
        status, detail = type(exc).__name__, ""
    ok = isinstance(status, int) and 200 <= status < 300
    row = {"sink": "otlp", "target": url, "status": status,
           "outcome": "delivered" if ok else "failed", "attempts": 1}  # fmt: skip
    if detail:
        row["detail"] = detail
    return row


def deliver(
    hits: list[dict[str, Any]],
    event: dict[str, Any],
    state: Path,
    *,
    test: bool = False,
    dry_run: bool = False,
    senders: dict[str, Any] | None = None,
) -> list[dict]:
    """Send every hit to its rule's sinks; one result row per alert, with its deliveries."""
    senders = senders or {}
    key = (
        signing_key(state) if not dry_run and any(h["rule"].get("webhook") for h in hits) else None
    )
    out = []
    for hit in hits:
        rule = hit["rule"]
        alert = alert_body(rule, hit["finding"], test)
        rows: list[dict[str, Any]] = []
        if rule.get("webhook"):
            if dry_run:
                rows.append({"sink": "webhook", "target": rule["webhook"], "outcome": "dry-run"})
            else:
                rows.append(send_webhook(rule["webhook"], webhook_payload(event, alert), key,
                                         bool(rule.get("allow_private")),
                                         sender=senders.get("webhook")))  # fmt: skip
        if rule.get("otlp"):
            if dry_run:
                rows.append(
                    {"sink": "otlp", "target": logs_url(rule["otlp"]), "outcome": "dry-run"}
                )
            else:
                document = otlp_logs(event, [alert], time.time_ns())
                rows.append(send_otlp(rule["otlp"], document, sender=senders.get("otlp"),
                                      allow_private=bool(rule.get("allow_private"))))  # fmt: skip
        out.append({**alert, "deliveries": rows})
    return out


__all__ = ["ATTEMPTS", "deliver", "logs_url", "otlp_logs", "public_key", "signing_key"]
