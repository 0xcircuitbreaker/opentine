"""``tine review run``: multi-agent review through the fleet (0.48, SPEC 4.25).

The reviewers are a ``fleet.toml`` (:mod:`opentine.fleet._manifest`): inert
until its exact bytes are trusted, its members run on the fleet executor with
the allowlisted environment only. Each member also gets

* ``OPENTINE_REVIEW_ID``: the Review being run;
* ``OPENTINE_REVIEW_CONTEXT``: a file holding the change under review (``git
  diff`` of ``--base``, or the ``--diff-file`` given), already redacted;
* ``OPENTINE_REVIEW_FINDINGS``: the file it writes its findings to, one JSON
  object per line: ``{"severity", "message", "path"?, "line"?}``.

Every well-formed finding becomes one signed ``opentine.review-finding``
(:mod:`opentine._review_finding`), its message redacted first, stored under
``.tine/review-findings/<review_id>.json``; then one new Review version lists
them all as open findings (row id ``rf-<12 hex of the finding's digest>``), so
the Review's gates block on a critical one. A malformed line is skipped and
counted, never guessed at.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from opentine import _review, _review_finding
from opentine._canon import atomic_write_text
from opentine._review_rules import SEVERITIES
from opentine._signed_record import RUN_OID, RecordError
from opentine.repository._paths import internal_path

MAX_CONTEXT = 4 << 20
MAX_FINDINGS = 256  # per member
STORE = "review-findings"


def context(root: Path, base: str | None, diff_file: str | None) -> str:
    """The change under review, redacted: a diff file, or ``git diff BASE``."""
    from opentine.redaction import redact_blob

    if diff_file:
        raw = Path(diff_file).read_bytes()[:MAX_CONTEXT]
    else:
        if base and base.startswith("-"):
            raise ValueError("--base must name a revision, not an option")
        argv = ["git", "-C", root.as_posix(), "diff", "--no-color", "--no-ext-diff"]
        done = subprocess.run([*argv, base or "HEAD"], capture_output=True, check=False)
        if done.returncode != 0:
            raise ValueError(f"git diff failed: {done.stderr.decode('utf-8', 'replace').strip()}")
        raw = done.stdout[:MAX_CONTEXT]
    return redact_blob(raw).decode("utf-8", "replace")


def _clean(text: str) -> str:
    from opentine.redaction import redact_blob

    flat = " ".join(str(text).split())
    out = redact_blob(flat.encode("utf-8")).decode("utf-8", "replace")
    while len(out.encode("utf-8")) > 1024:
        out = out[:-1]
    return out


def parse(raw: str) -> tuple[list[dict[str, Any]], int]:
    """The well-formed findings of one member's file, and how many lines were skipped."""
    found, skipped = [], 0
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            skipped += 1
            continue
        path, at = (row.get("path"), row.get("line")) if isinstance(row, dict) else (None, None)
        ok = (
            isinstance(row, dict)
            and row.get("severity") in SEVERITIES
            and isinstance(row.get("message"), str)
            and bool(_clean(row["message"]).strip())
            and (path is None or _review_finding.path_ok(path))
            and (at is None or (type(at) is int and at >= 1 and path is not None))
        )
        if not ok or len(found) >= MAX_FINDINGS:
            skipped += 1
            continue
        found.append({"severity": row["severity"], "message": _clean(row["message"]),
                      "path": path, "line": at})  # fmt: skip
    return found, skipped


def _store_path(repo: Any, review_id: str) -> Path:
    return internal_path(repo.path, STORE, f"{review_id}.json")


def load(repo: Any, review_id: str) -> list[dict[str, Any]]:
    """The stored signed findings of *review_id* (oldest first)."""
    try:
        found = json.loads(_store_path(repo, review_id).read_text("utf-8"))
    except FileNotFoundError:
        return []
    if not isinstance(found, list):
        raise ValueError(f"the findings store of {review_id} is not a list")
    return found


def save(repo: Any, review_id: str, records: list[dict[str, Any]]) -> None:
    for record in records:
        _review_finding.check(record)
    path = _store_path(repo, review_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(records, indent=1, sort_keys=True) + "\n")


def sign_all(head: dict[str, Any], members: list[dict[str, Any]], read: Any, key: Any,
             key_id: str | None) -> tuple[list[dict[str, Any]], int]:  # fmt: skip
    """Signed findings for every member's file (``read(member) -> text``)."""
    signed, skipped = [], 0
    for member in members:
        rows, bad = parse(read(member))
        skipped += bad
        run = member.get("run")
        run = run if isinstance(run, str) and RUN_OID.fullmatch(run) else None
        for row in rows:
            draft = _review_finding.build(head["review_id"], "rf-pending", row["severity"],
                                          row["message"], reviewer=member["name"],
                                          path=row["path"], line=row["line"], run=run)  # fmt: skip
            draft["finding_id"] = "rf-" + _review_finding.digest(draft)[12:24]
            signed.append(_review_finding.sign(draft, key, key_id=key_id))
    return signed, skipped


def next_version(head: dict[str, Any], signed: list[dict[str, Any]]) -> dict[str, Any]:
    """The Review's next version, every new finding listed as open."""
    known = {row["id"] for row in head["findings"]}
    findings = list(head["findings"])
    for record in signed:
        if record["finding_id"] in known or len(findings) >= 1024:
            continue
        where = f"{record['path']}:{record['line'] or ''}".rstrip(":") if record["path"] else ""
        text = _clean(f"[{record['reviewer']}] {where} {record['message']}")
        findings.append({"id": record["finding_id"], "severity": record["severity"],
                         "subject": None, "message": text, "status": "open"})  # fmt: skip
        known.add(record["finding_id"])
    fields = {name: head[name] for name in ("title", "reviewers", "repos", "subjects",
                                            "monitors", "gates")}  # fmt: skip
    return _review.build(head["review_id"], previous=head, findings=findings, **fields)


def verify_all(records: list[Any], reviewers: list[str], review_id: str) -> list[dict[str, Any]]:
    """Each record checked against *reviewers*; one filed under another Review fails."""
    out = []
    for record in records:
        try:
            row = _review_finding.check(record, reviewers=reviewers)
            if row["review_id"] != review_id:
                other = row["review_id"]
                raise RecordError(f"{_review_finding.CODE}.wrong-review",
                                  f"the review finding belongs to review {other}")  # fmt: skip
            out.append(row)
        except RecordError as exc:
            fid = record.get("finding_id") if isinstance(record, dict) else None
            out.append({"finding_id": fid, "state": "failed",
                        "code": exc.code, "message": str(exc)})  # fmt: skip
    return out


__all__ = ["context", "load", "next_version", "parse", "save", "sign_all", "verify_all"]
