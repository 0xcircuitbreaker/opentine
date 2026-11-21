"""Withdrawing a contributed run, and the tombstones a dataset build honours (0.75).

``tine dataset withdraw RUN --key K --reason CATEGORY`` signs an
**attestation** (an existing object kind) on RUN under the claim convention
``opentine-dataset/withdraw/1``::

    {"convention": "opentine-dataset/withdraw/1", "run": "run:sha256:...",
     "reason": "consent-withdrawn|privacy|licence|quality|other",
     "contributor": "sha256:<fingerprint of the signing Ed25519 key>",
     "withdrawn_at": "YYYY-MM-DDTHH:MM:SSZ"}

and keeps it with a ``tine hold`` row whose target starts ``dataset-withdraw:``,
which ``tine hold release`` refuses: a loop cannot delete a withdrawal. A
withdrawal is ``verified`` only when its Ed25519 signature holds, the
payload ``signer`` and ``contributor`` are the key that signed, and that key is
the run's contributor or a pinned curator (:mod:`opentine._dataset_withdraw_auth`).

A **tombstone** is what a dataset manifest keeps of a withdrawn run: its
digest, the date and the reason category, never content::

    {"format": "opentine-dataset/tombstones/1",
     "tombstones": [{"digest": "sha256:<hex of the run id>", "date": "YYYY-MM-DD",
                     "reason": "privacy"}]}

:func:`honour` drops dataset items whose run is tombstoned; ``tine dataset
add`` refuses such a run and ``tine dataset check`` refuses such a bundle.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from opentine.repository._holds import DATASET_WITHDRAW as HOLD

CONVENTION = "opentine-dataset/withdraw/1"
TOMBSTONES = "opentine-dataset/tombstones/1"
REASONS = ("consent-withdrawn", "privacy", "licence", "quality", "other")
FIELDS = ("convention", "run", "reason", "contributor", "withdrawn_at")
_RUN = re.compile(r"run:sha256:([0-9a-f]{64})")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
MAX_JSON_BYTES = 8 * 1024 * 1024


def _real(value: Any, pattern: re.Pattern[str], fmt: str) -> bool:
    """*value* has the shape and is a real calendar date or time."""
    from datetime import datetime

    if not isinstance(value, str) or not pattern.fullmatch(value):
        return False
    try:
        datetime.strptime(value, fmt)
    except ValueError:
        return False
    return True


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate keys")
    return dict(pairs)


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON number")


def digest(run: str) -> str:
    """The tombstone digest of a run id: its own ``sha256:<hex>``."""
    found = _RUN.fullmatch(run)
    if not found:
        raise ValueError(f"not a run id: {run!r}")
    return f"sha256:{found.group(1)}"


def check_claim(claim: Any) -> list[str]:
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return [f"not an {CONVENTION} claim"]
    if set(claim) != set(FIELDS):
        return ["wrong set of fields"]
    problems = []
    if not isinstance(claim["run"], str) or not _RUN.fullmatch(claim["run"]):
        problems.append("run is a run id")
    if claim["reason"] not in REASONS:
        problems.append(f"reason is one of {', '.join(REASONS)}")
    if not _real(claim["withdrawn_at"], _AT, "%Y-%m-%dT%H:%M:%SZ"):
        problems.append("withdrawn_at is YYYY-MM-DDTHH:MM:SSZ")
    return problems


def withdraw(repo: Any, run: str, key: Any, reason: str, at: str) -> str:
    """Sign and hold one withdrawal of *run*; the attestation id."""
    from opentine import _containment_records as records

    claim = {
        "convention": CONVENTION,
        "run": run,
        "reason": reason,
        "contributor": records.fingerprint(key),
        "withdrawn_at": at,
    }
    problems = check_claim(claim)
    if problems:
        raise ValueError(f"not a valid withdrawal: {problems[0]}")
    if not repo.has(run):
        raise KeyError(f"no run {run} in the repository")
    from opentine._dataset_withdraw_auth import authority

    who, why = authority(repo, run, claim["contributor"], reason)
    if who is None:
        raise PermissionError(f"refusing to withdraw: {why}")
    return records.record(repo, run, claim, key, f"{HOLD}{run}")


def withdrawals(repo: Any) -> list[dict[str, Any]]:
    """Every held withdrawal with its verification state."""
    from opentine import _containment_records as records
    from opentine._dataset_withdraw_auth import authority

    out = []
    for target, row in records.held(repo, HOLD):
        claim = row["claim"]
        if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
            continue
        problems = check_claim(claim)
        if not row["signed"]:
            state = "unverified: the signature does not hold or names another key"
        elif claim.get("contributor") != row["signer"]:
            state = "unverified: the contributor is not the key that signed"
        elif row["target"] != claim.get("run"):
            state = "unverified: the record is on another object"
        elif problems:
            state = f"unverified: {problems[0]}"
        else:
            who, why = authority(repo, claim["run"], row["signer"], claim["reason"], signed=True)
            state = "verified" if who else f"unverified: {why}"
        out.append(
            {
                "record": row["oid"],
                "hold": target,
                "run": claim.get("run"),
                "reason": claim.get("reason"),
                "contributor": claim.get("contributor"),
                "withdrawn_at": claim.get("withdrawn_at"),
                "state": state,
            }
        )
    return out


def tombstone(row: dict[str, Any]) -> dict[str, str]:
    """The tombstone of a withdrawal row: digest, date, reason; no content."""
    return {"digest": digest(row["run"]), "date": row["withdrawn_at"][:10], "reason": row["reason"]}


def load_json(path: str | Path) -> Any:
    """Untrusted JSON from *path*: at most :data:`MAX_JSON_BYTES`, shallow, no
    duplicate keys or ``NaN``; :class:`ValueError` (or ``OSError``) otherwise."""
    from opentine._json_shallow import loads

    with open(path, "rb") as fh:
        data = fh.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ValueError(f"larger than {MAX_JSON_BYTES} bytes")
    return loads(data, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)


def read_tombstones(path: str | Path) -> list[dict[str, str]]:
    """The tombstones of a manifest file; refuses a malformed one (fail closed)."""
    try:
        doc = load_json(path)
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read the tombstones {path}: {exc}") from None
    rows = doc.get("tombstones") if isinstance(doc, dict) else None
    if not isinstance(rows, list) or doc.get("format") != TOMBSTONES:
        raise ValueError(f"{path} is not an {TOMBSTONES} manifest")
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"digest", "date", "reason"}
            or not isinstance(row["digest"], str)
            or not _DIGEST.fullmatch(row["digest"])
            or not _real(row["date"], _DATE, "%Y-%m-%d")
            or row["reason"] not in REASONS
        ):
            raise ValueError(f"{path}: a tombstone is malformed")
    return rows


def write_tombstones(path: str | Path, rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Merge *rows* into the manifest at *path* (created if absent); the merged list."""
    target = Path(path)
    merged = {r["digest"]: r for r in (read_tombstones(target) if target.exists() else [])}
    for row in rows:
        merged.setdefault(row["digest"], row)
    out = sorted(merged.values(), key=lambda r: r["digest"])
    data = json.dumps({"format": TOMBSTONES, "tombstones": out}, indent=2, sort_keys=True)
    target.write_bytes((data + "\n").encode("utf-8"))
    return out


def tombstoned(run: str, rows: list[dict[str, str]]) -> bool:
    found = _RUN.fullmatch(run or "")
    return bool(found) and f"sha256:{found.group(1)}" in {r["digest"] for r in rows}


def honour(items: list[dict[str, Any]], rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    """*items* without those whose ``run`` is tombstoned."""
    return [item for item in items if not tombstoned(str(item.get("run") or ""), rows)]


__all__ = [
    "CONVENTION",
    "HOLD",
    "MAX_JSON_BYTES",
    "REASONS",
    "TOMBSTONES",
    "check_claim",
    "digest",
    "honour",
    "load_json",
    "read_tombstones",
    "tombstone",
    "tombstoned",
    "withdraw",
    "withdrawals",
    "write_tombstones",
]
