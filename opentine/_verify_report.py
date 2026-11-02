"""The ``tine-verify-report/1`` document ``tine verify RUN --offline`` produces.

A report is an ordered list of checks. Each check has a ``name``, an
``outcome`` (one of :data:`OUTCOMES`), a dotted ``reason`` code, human
``detail``, and a ``trust_basis``: what the outcome rests on, for example
``internal consistency only``, ``pinned key sha256:…`` or
``trusted_root.json sha256 …``. A pass is only as strong as its basis.

The verdict is ``fail`` when any check failed and, under ``--strict``, also
when a *required* check could not run offline (``unavailable-offline``).
Otherwise it is ``pass``. ``authorship`` names the key basis that establishes
who signed, and is ``null`` whenever only internal consistency was shown (no
signature, an unchecked one, or a trust-on-first-use key the file carries).

Reason codes are dotted ``area.detail`` strings. Where a check refuses for a
rule ``docs/conformance/REASON_CODES.md`` already names (an unparseable
artifact is ``artifact.malformed-json``), that code is reused.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCHEMA = "tine-verify-report/1"
OUTCOMES = ("pass", "fail", "unavailable-offline", "not-applicable")
INTERNAL_ONLY = "internal consistency only"

_CHECK_KEYS = ("name", "outcome", "reason", "detail", "trust_basis", "required")
_STRING = {"type": "string"}

#: JSON Schema (2020-12) of the document :meth:`Report.as_json` returns.
JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://opentine.dev/schemas/tine-verify-report-1.json",
    "title": SCHEMA,
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema",
        "command",
        "offline",
        "path",
        "strict",
        "verdict",
        "ok",
        "authorship",
        "checks",
        "unavailable_required",
    ],
    "properties": {
        "schema": {"const": SCHEMA},
        "command": {"const": "verify"},
        "offline": {"const": True},
        "path": _STRING,
        "strict": {"type": "boolean"},
        "verdict": {"enum": ["pass", "fail"]},
        "ok": {"type": "boolean"},
        "authorship": {"type": ["string", "null"]},
        "unavailable_required": {"type": "array", "items": _STRING},
        "location": {"type": "object"},
        "checks": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": list(_CHECK_KEYS),
                "properties": {
                    "name": _STRING,
                    "outcome": {"enum": list(OUTCOMES)},
                    "reason": {"type": "string", "pattern": r"^[a-z0-9-]+(\.[a-z0-9-]+)+$"},
                    "detail": _STRING,
                    "trust_basis": _STRING,
                    "required": {"type": "boolean"},
                },
            },
        },
    },
}


@dataclass(frozen=True)
class Check:
    name: str
    outcome: str
    reason: str
    detail: str
    trust_basis: str = INTERNAL_ONLY
    required: bool = False
    #: True when a pass shows *who* signed (a supplied, pinned or HMAC key).
    authenticates: bool = False

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome {self.outcome!r}")

    def as_json(self) -> dict[str, Any]:
        return {key: getattr(self, key) for key in _CHECK_KEYS}


@dataclass
class Report:
    path: str
    strict: bool = False
    checks: list[Check] = field(default_factory=list)
    #: ``--locate`` only: the ``_verify_locate.locate`` object.
    location: dict[str, Any] | None = None

    def add(self, check: Check) -> None:
        self.checks.append(check)

    @property
    def unavailable_required(self) -> list[str]:
        return [c.name for c in self.checks if c.required and c.outcome == "unavailable-offline"]

    @property
    def ok(self) -> bool:
        if any(check.outcome == "fail" for check in self.checks):
            return False
        return not (self.strict and self.unavailable_required)

    @property
    def authorship(self) -> str | None:
        """The basis that shows who signed, or ``None``: consistency is not authorship."""
        for check in self.checks:
            if check.outcome == "pass" and check.authenticates:
                return check.trust_basis
        return None

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "command": "verify",
            "offline": True,
            "path": self.path,
            "strict": self.strict,
            "verdict": "pass" if self.ok else "fail",
            "ok": self.ok,
            "authorship": None if not self.ok else self.authorship,
            "checks": [check.as_json() for check in self.checks],
            "unavailable_required": self.unavailable_required,
            **({"location": self.location} if self.location is not None else {}),
        }


_STYLE = {
    "pass": "green",
    "fail": "red",
    "unavailable-offline": "yellow",
    "not-applicable": "dim",
}


def render(report: Report) -> list[str]:
    """Rich-markup lines for the human rendering (the caller escapes nothing more)."""
    from rich.markup import escape

    lines = [f"[bold]offline verification[/] {escape(report.path)}"]
    for check in report.checks:
        style = _STYLE[check.outcome]
        need = " (required)" if check.required else ""
        lines.append(
            f"  [{style}]{check.outcome:<19}[/] {escape(check.name)}{need}: "
            f"{escape(check.detail)} [dim]{escape('[' + check.reason + ']')}[/]"
        )
        lines.append(f"  {'':<19} [dim]trust basis:[/] {escape(check.trust_basis)}")
    basis = report.authorship if report.ok else None
    who = escape(basis) if basis else f"NOT established ({INTERNAL_ONLY})"
    lines.append(f"[dim]authorship:[/] {who}")
    if report.strict and report.unavailable_required:
        missing = ", ".join(report.unavailable_required)
        lines.append(f"[red]--strict: required check(s) unavailable offline: {escape(missing)}[/]")
    if report.location is not None:
        where = report.location
        spot = where["field_path"] or "-"
        lines.append(
            f"[dim]location:[/] {escape(where['region'] or 'not localised')} at {escape(spot)}: "
            f"{escape(where['detail'])} {escape('[' + where['reason'] + ']')}"
        )
    verdict = "[green]VERIFIED (offline)[/]" if report.ok else "[red]FAILED (offline)[/]"
    lines.append(verdict)
    return lines


__all__ = ["INTERNAL_ONLY", "JSON_SCHEMA", "OUTCOMES", "SCHEMA", "Check", "Report", "render"]
