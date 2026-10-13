"""What ``GET /audit/verify`` tells a tenant admin about the server's audit chain.

The chain is one log for the whole server. The endpoint used to return its head,
which changes on every request any tenant makes, so a tenant admin polling it
could watch other tenants' activity; and each call walked every row on the
server. The report now carries only the status (``verified``, ``invalid``,
``legacy-unverified``) and warnings, and a store that can verify at bounded cost
(``audit_status_bounded``) does so.
"""

from __future__ import annotations

from typing import Any


def audit_report(audit: Any) -> dict[str, Any]:
    bounded = getattr(audit, "audit_status_bounded", None)
    verify = getattr(audit, "verify_audit_chain", None)
    status_method = getattr(audit, "audit_status", None)
    head = getattr(audit, "audit_head", None)
    warnings = getattr(audit, "audit_warnings", None)
    if callable(bounded) and callable(warnings):
        status = bounded()
    elif not all(callable(item) for item in (verify, head, warnings)):
        raise RuntimeError("configured AuditSink does not expose chain verification")
    elif callable(status_method):
        # Head read first and passed in on purpose: the status is bound to that
        # head, so a concurrent append yields "invalid" rather than a stale
        # assurance -- a false alarm, the safe direction here.
        status = status_method(expected_head=head())
    else:
        before = head()
        valid = bool(verify()) and head() == before
        status = ("legacy-unverified" if warnings() else "verified") if valid else "invalid"
    warning_list = warnings() if status == "legacy-unverified" else []
    return {"ok": status == "verified", "status": status, "warnings": warning_list}
