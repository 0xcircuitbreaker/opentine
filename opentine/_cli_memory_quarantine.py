"""``tine memory quarantine|served`` and recall's provenance flags (0.61).

``recall --record-to RUN`` records the served notes as a step of RUN while it
is being captured (:mod:`opentine._memory_served`); ``recall --min-assurance
TIER`` keeps notes whose subject run reaches TIER. ``quarantine NOTE --key K
--why TEXT`` signs and holds a quarantine (:mod:`opentine._memory_quarantine`)
and lists every run that was served the note and every lineage variant whose
mutation or eval runs consumed it; ``served NOTE`` lists the same without
quarantining. Both read the derived index (:mod:`opentine._memory_index`).
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

TIERS = ("T0", "T1", "T2", "T3")


def add_provenance_parsers(actions: Any) -> None:
    recall = actions.choices["recall"]
    recall.add_argument("--min-assurance", choices=TIERS, metavar="TIER",
                        help="Only notes whose subject run reaches TIER (T0-T3)")  # fmt: skip
    recall.add_argument("--record-to", metavar="RUN",
                        help="Record the served notes as a step of RUN")  # fmt: skip
    quarantine = actions.add_parser("quarantine", help="Sign and hold a note's quarantine")
    quarantine.add_argument("note", metavar="NOTE", help="The note's digest (blob:sha256:...)")
    quarantine.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
    quarantine.add_argument("--why", required=True, help="Why the note is quarantined")
    quarantine.add_argument("--created-at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ")
    served = actions.add_parser("served", help="Runs and variants that consumed a note")
    served.add_argument("note", metavar="NOTE", help="The note's digest (blob:sha256:...)")
    for parser in (quarantine, served):
        parser.add_argument("--lineage-dir", metavar="DIR",
                            help="Lineage folder (REPO/.tine/lineage)")  # fmt: skip


def _variants(args: argparse.Namespace, runs: set[str]) -> list[dict[str, Any]]:
    from opentine._lineage import FOLDER, read_folder
    from opentine._memory_index import affected_variants

    folder = Path(args.lineage_dir) if args.lineage_dir else Path(args.repo) / FOLDER
    if not folder.is_dir() or not runs:
        return []
    return affected_variants(read_folder(folder), runs)


def consumers(
    args: argparse.Namespace, repo: Any, *, rebuild_first: bool = False
) -> dict[str, Any]:
    from opentine._memory_index import consumers as served_runs
    from opentine._memory_quarantine import quarantined

    rows = served_runs(repo, args.note, rebuild_first=rebuild_first)
    held = quarantined(repo).get(args.note)
    return {"served_note": args.note, "quarantined": held is not None, "runs": rows,
            "variants": _variants(args, {r["run"] for r in rows})}  # fmt: skip


def _quarantine(args: argparse.Namespace, repo: Any) -> dict[str, Any]:
    from opentine._memory_quarantine import quarantine
    from opentine._signing_keys import ed25519_private_from_file

    key = ed25519_private_from_file(args.key)
    made = quarantine(repo, args.note, key, args.why, created_at=args.created_at)
    return {**made, **consumers(args, repo, rebuild_first=True)}


def recall(args: argparse.Namespace, repo: Any, rows: list[dict[str, Any]]) -> dict[str, Any]:
    from opentine._memory_served import at_least, record

    if args.min_assurance is not None:
        rows = at_least(repo, rows, args.min_assurance)
    body: dict[str, Any] = {"notes": rows}
    if args.record_to:
        body["recorded_run"] = record(repo, args.record_to, rows, args.query)
    return body


def act(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], str]:
    if args.memory_action == "quarantine":
        body = _quarantine(args, repo)
        head = f"quarantined {body['note']} ({body['quarantine']})"
    else:
        body = consumers(args, repo)
        state = "quarantined" if body["quarantined"] else "not quarantined"
        head = f"{body['served_note']} ({state})"
    lines = [head, f"served to {len(body['runs'])} run(s)"]
    lines += [f"  {row['run']}" for row in body["runs"]]
    lines += [f"consumed by {len(body['variants'])} variant(s)"]
    lines += [f"  {row['variant']}" for row in body["variants"]]
    return body, "\n".join(lines)


__all__ = ["act", "add_provenance_parsers", "consumers", "recall"]
