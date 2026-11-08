"""Version 2 redaction reports: ``tine redact check --pii`` (0.46, SPEC 4.13.1).

A version 1 report (:func:`opentine._push_gate.run_report`) says which objects
the credential ruleset would still change. Version 2 re-scans the same objects
under ``opentine-redaction/3``: credentials (detector ``secret``) plus the PII
detectors of :mod:`opentine._pii` and the local classifier layer. Each finding
lists the detectors that fired, never the matched text, and the report records
the classifier by name. It is signed like version 1 but under the
``opentine.redaction-report.v2:`` domain, so a version 1 signature cannot be
replayed onto a version 2 body or the reverse.
"""

from __future__ import annotations

from typing import Any

from opentine._pii import PII_RULESET, detectors_in
from opentine._pii_classify import name_of
from opentine._push_gate import REPORT_KIND
from opentine.redaction import redact_blob
from opentine.repository.pack import reachable

REPORT_VERSION_PII = 2
#: The scan reads at most this much of one object; larger objects are scanned on a prefix.
MAX_SCAN_BYTES = 4 * 1024 * 1024


def _detectors(repo: Any, oid: str, classifier: Any) -> list[str]:
    try:
        body = repo.get(oid).body
    except Exception:  # noqa: BLE001 - unreadable: fail closed, as version 1 does
        return ["unreadable"]
    found = {"secret"} if redact_blob(body) != body else set()
    found |= detectors_in(body[:MAX_SCAN_BYTES], classifier)
    return sorted(found)


def scan(repo: Any, oids: Any, classifier: Any = None) -> list[dict[str, Any]]:
    """``{oid, kind, detectors}`` for each object a ``/3`` detector fires on."""
    hits = []
    for oid in sorted(oids):
        detectors = _detectors(repo, oid, classifier)
        if detectors:
            hits.append({"oid": oid, "kind": oid.split(":", 1)[0], "detectors": detectors})
    return hits


def run_report(repo: Any, run: str, classifier: Any = None) -> dict[str, Any]:
    """The version 2 report of one run: every reachable object, credentials and PII."""
    oids = set(reachable(repo, [run], include_associated=True))
    hits = scan(repo, oids, classifier)
    return {
        "kind": REPORT_KIND,
        "report_version": REPORT_VERSION_PII,
        "ruleset": PII_RULESET,
        "classifier": name_of(classifier),
        "run": run,
        "objects": len(oids),
        "findings": hits,
        "clean": not hits,
    }


__all__ = ["MAX_SCAN_BYTES", "REPORT_VERSION_PII", "run_report", "scan"]
