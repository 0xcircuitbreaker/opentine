"""JSON Schemas for compliance profiles and ``tine compliance`` (0.48).

``opentine-compliance-profile-1`` is a ``docs/compliance/*.yaml`` profile
(SPEC 12.5); ``tine-cli-compliance-check-1`` and ``tine-cli-compliance-list-1``
are the ``--json`` outputs. No new object kind: a compliance report is a CLI
output, never stored or signed.
"""

from __future__ import annotations

from typing import Any

from opentine._compliance import NOTICE, STATUSES
from opentine._compliance_facts import FACTS
from opentine._schema_defs import INT, STR, closed, doc

_NOTICE = {"const": NOTICE}
_REVIEW = {"enum": ["outstanding", "recorded"]}
_FACT = {"enum": list(FACTS)}
_SOURCE = closed(["id", "title", "url"], {"id": STR, "title": STR, "url": STR})
_FACT_STATE = closed(["status", "detail"], {"status": {"enum": ["evidenced", "missing"]},
                                            "detail": STR})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-compliance-profile-1": doc("opentine-compliance-profile-1",
        "opentine compliance profile (profile_version 1)",
        "A `docs/compliance/NAME.yaml` profile (SPEC 12.5): YAML in its JSON-compatible flow "
        "style. Each requirement cites the article or rule it paraphrases; an in-scope "
        "requirement lists the evidence facts that show it, an out-of-scope one lists none.",
        closed(["profile", "profile_version", "title", "jurisdiction", "notice",
                "counsel_review", "sources", "requirements"], {
            "profile": STR, "profile_version": INT, "title": STR, "jurisdiction": STR,
            "notice": _NOTICE, "counsel_review": _REVIEW,
            "sources": {"type": "array", "minItems": 1, "items": _SOURCE},
            "requirements": {"type": "array", "minItems": 1, "items": closed(
                ["id", "cite", "text", "scope", "evidence"], {
                    "id": STR, "cite": {"type": "string", "minLength": 1}, "text": STR,
                    "scope": {"enum": ["in", "out"]},
                    "evidence": {"type": "array", "items": _FACT}, "note": STR})}})),
    "tine-cli-compliance-check-1": doc("tine-cli-compliance-check-1",
        "tine compliance check --json",
        "Each requirement of a profile as evidenced, missing or out-of-scope for one run, with "
        "the facts behind it. Draft: not legal advice, pending counsel review.",
        closed(["command", "run", "kind", "report_version", "notice", "counsel_review",
                "profile", "profile_version", "title", "sources", "summary", "requirements",
                "facts"], {
            "command": {"const": "compliance-check"}, "run": STR,
            "kind": {"const": "opentine.compliance-report"}, "report_version": {"const": 1},
            "notice": _NOTICE, "counsel_review": _REVIEW, "profile": STR,
            "profile_version": INT, "title": STR,
            "sources": {"type": "array", "items": _SOURCE},
            "summary": closed(list(STATUSES), {s: INT for s in STATUSES}),
            "requirements": {"type": "array", "items": closed(
                ["id", "cite", "text", "status", "evidence"], {
                    "id": STR, "cite": STR, "text": STR, "status": {"enum": list(STATUSES)},
                    "note": STR, "evidence": {"type": "array", "items": closed(
                        ["fact", "status", "detail"], {
                            "fact": _FACT, "status": {"enum": ["evidenced", "missing"]},
                            "detail": STR})}})},
            "facts": closed([], {f: _FACT_STATE for f in FACTS})})),
    "tine-cli-compliance-list-1": doc("tine-cli-compliance-list-1",
        "tine compliance list --json", "The compliance profiles this opentine ships.",
        closed(["command", "notice", "profiles"], {
            "command": {"const": "compliance-list"}, "notice": _NOTICE,
            "profiles": {"type": "array", "items": closed(
                ["name", "title", "profile_version", "requirements", "counsel_review"], {
                    "name": STR, "title": STR, "profile_version": INT, "requirements": INT,
                    "counsel_review": _REVIEW})}})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {
    "compliance-check": "tine-cli-compliance-check-1",
    "compliance-list": "tine-cli-compliance-list-1",
}

__all__ = ["COMMAND_SCHEMAS", "SCHEMAS"]
