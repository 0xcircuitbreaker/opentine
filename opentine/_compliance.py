"""Compliance profiles: data that maps legal requirements to OpenTine evidence (0.48).

A profile is a ``docs/compliance/NAME.yaml`` file (shipped in the wheel as
``opentine/data/compliance``) written in YAML's JSON-compatible flow style, so
the standard library reads it with no YAML dependency: leading ``#`` comment
lines, then one JSON object (``opentine-compliance-profile/1``, SPEC 12.5).

Each requirement cites the article or rule it paraphrases and lists the facts
(:mod:`opentine._compliance_facts`) that evidence it. Evaluation is pure: a
requirement is ``out-of-scope`` when the profile says so (organisational or
qualified-trust-service duties no log can show), ``evidenced`` when every
listed fact is, and ``missing`` otherwise. Every report carries the profile's
notice: these are drafts, not legal advice, pending counsel review.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentine._compliance_facts import FACTS

NOTICE = "draft — not legal advice, pending counsel review"
PROFILE_SCHEMA = "opentine-compliance-profile/1"
STATUSES = ("evidenced", "missing", "out-of-scope")
_PACKAGED = Path(__file__).resolve().parent / "data" / "compliance"
_SOURCE = Path(__file__).resolve().parents[1] / "docs" / "compliance"
_TOP = {"profile", "profile_version", "title", "jurisdiction", "notice", "counsel_review",
        "sources", "requirements"}  # fmt: skip
_REQ = {"id", "cite", "text", "scope", "evidence", "note"}


class ProfileError(ValueError):
    """A profile file that is missing, unparseable or not a valid profile."""


def profile_dirs() -> list[Path]:
    """Where named profiles live: the wheel's copy, else the source tree's docs."""
    return [d for d in (_PACKAGED, _SOURCE) if d.is_dir()]


def available() -> dict[str, Path]:
    found: dict[str, Path] = {}
    for directory in reversed(profile_dirs()):  # the packaged copy wins
        for path in sorted(directory.glob("*.yaml")):
            found[path.stem] = path
    return dict(sorted(found.items()))


def parse(text: str, source: str = "<profile>") -> dict[str, Any]:
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise ProfileError(f"{source}: not a JSON-compatible YAML profile: {exc}") from exc
    validate(data, source)
    return data


def validate(data: Any, source: str = "<profile>") -> None:
    def bad(why: str) -> ProfileError:
        return ProfileError(f"{source}: {why}")

    if not isinstance(data, dict) or set(data) != _TOP:
        raise bad(f"a profile has exactly the keys {sorted(_TOP)}")
    if data["notice"] != NOTICE:
        raise bad(f"notice must be {NOTICE!r}")
    if data["counsel_review"] not in ("outstanding", "recorded"):
        raise bad("counsel_review must be 'outstanding' or 'recorded'")
    if not isinstance(data["profile_version"], int) or isinstance(data["profile_version"], bool):
        raise bad("profile_version must be an integer")
    seen: set[str] = set()
    for req in data["requirements"] if isinstance(data["requirements"], list) else [None]:
        if (
            not isinstance(req, dict)
            or not {"id", "cite", "text", "scope", "evidence"} <= set(req)
            or not set(req) <= _REQ
        ):
            raise bad(f"each requirement has the keys {sorted(_REQ)} ('note' optional)")
        if req["id"] in seen or not isinstance(req["cite"], str) or not req["cite"].strip():
            raise bad(f"requirement {req['id']!r}: duplicate id or empty cite")
        seen.add(req["id"])
        if req["scope"] not in ("in", "out"):
            raise bad(f"requirement {req['id']!r}: scope is 'in' or 'out'")
        unknown = [f for f in req["evidence"] if f not in FACTS]
        if unknown or (req["scope"] == "in") != bool(req["evidence"]):
            raise bad(f"requirement {req['id']!r}: in-scope needs known facts {list(FACTS)}")


def load(name_or_path: str) -> dict[str, Any]:
    named = available()
    path = named.get(name_or_path) or Path(name_or_path)
    if name_or_path not in named and not path.is_file():
        raise ProfileError(f"no compliance profile {name_or_path!r}; known: {', '.join(named)}")
    try:
        return parse(path.read_text(encoding="utf-8"), path.name)
    except OSError as exc:
        raise ProfileError(f"{path.name}: {exc}") from exc


def evaluate(profile: dict[str, Any], facts: dict[str, dict[str, str]]) -> dict[str, Any]:
    """The report body for *profile* against *facts* (pure: no I/O, no clock)."""
    rows = []
    for req in profile["requirements"]:
        evidence = [{"fact": f, **facts[f]} for f in req["evidence"]]
        if req["scope"] == "out":
            status = "out-of-scope"
        else:
            status = "evidenced" if all(e["status"] == "evidenced" for e in evidence) else "missing"
        row = {"id": req["id"], "cite": req["cite"], "text": req["text"], "status": status,
               "evidence": evidence}  # fmt: skip
        if req.get("note"):
            row["note"] = req["note"]
        rows.append(row)
    summary = {s: sum(r["status"] == s for r in rows) for s in STATUSES}
    return {
        "kind": "opentine.compliance-report",
        "report_version": 1,
        "notice": NOTICE,
        "counsel_review": profile["counsel_review"],
        "profile": profile["profile"],
        "profile_version": profile["profile_version"],
        "title": profile["title"],
        "sources": profile["sources"],
        "summary": summary,
        "requirements": rows,
        "facts": {name: facts[name] for name in FACTS if name in facts},
    }


__all__ = [
    "NOTICE",
    "PROFILE_SCHEMA",
    "STATUSES",
    "ProfileError",
    "available",
    "evaluate",
    "load",
    "parse",
    "profile_dirs",
    "validate",
]
