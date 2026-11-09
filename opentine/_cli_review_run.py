"""``tine review run`` and ``tine review findings`` (0.48, SPEC 4.25).

``run REVIEW --fleet reviewers.toml [--trust]`` runs the reviewer fleet on the
change (``--base REV`` for ``git diff REV``, default ``HEAD``; or
``--diff-file FILE``), signs every finding the members report as an
``opentine.review-finding`` with ``--ed25519-key-file`` (a reviewer of the
Review), and signs the next Review version listing them
(:mod:`opentine._review_run`). ``findings REVIEW`` lists the stored findings,
each verified against the head version's reviewers.
"""

from __future__ import annotations

import argparse
import io
from pathlib import Path
from typing import Any


def add_run_parsers(actions: Any) -> list[argparse.ArgumentParser]:
    run = actions.add_parser("run", help="Run reviewer harnesses through the fleet")
    run.add_argument("review_id")
    run.add_argument("--fleet", required=True, metavar="TOML", help="The reviewers' fleet.toml")
    run.add_argument("--trust", action="store_true", help="Trust this manifest's exact bytes")
    change = run.add_mutually_exclusive_group()
    change.add_argument("--base", metavar="REV", help="Review `git diff REV` (default HEAD)")
    change.add_argument("--diff-file", metavar="FILE", help="Review this diff instead")
    run.add_argument("--ed25519-key-file", required=True, metavar="PATH",
                     help="A reviewer's Ed25519 key; it signs every finding")  # fmt: skip
    run.add_argument("--key-id", help="Key id recorded in the signatures")
    findings = actions.add_parser("findings", help="List a Review's signed findings")
    findings.add_argument("review_id")
    return [run, findings]


def _run(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], str]:
    from opentine import _review, _review_run
    from opentine._signing_keys import ed25519_private_from_file
    from opentine.fleet import _manifest, _runner
    from opentine.repository import _review_store as store

    current = store.load(repo, args.review_id)
    if current is None:
        raise KeyError(f"no review {args.review_id} here: `tine review create` first")
    head = current["versions"][-1]
    key = ed25519_private_from_file(args.ed25519_key_file)
    me = key.public_key().public_bytes_raw().hex()
    if me not in head["reviewers"]:
        raise ValueError("the signing key is not a reviewer of the head version")
    fleet = _manifest.load(Path(args.fleet), trust_now=args.trust)
    root = Path(repo.worktree)
    text = _review_run.context(root, args.base, args.diff_file)
    state = _runner.create(fleet)
    work = state.directory / state.id
    work.mkdir(parents=True, exist_ok=True)
    (work / "review-context.diff").write_text(text, "utf-8")

    def extra(member: str) -> dict[str, str]:
        return {"OPENTINE_REVIEW_ID": args.review_id,
                "OPENTINE_REVIEW_CONTEXT": str(work / "review-context.diff"),
                "OPENTINE_REVIEW_FINDINGS": str(work / f"{member}.findings.jsonl")}  # fmt: skip

    code = _runner.run(fleet, state, out=io.StringIO(), extra=extra)
    members = [{"key": m["key"], "name": f"{m['vary']['agent']}-{m['key']}", "run": m.get("run"),
                "status": m["status"]} for m in state.data["members"]]  # fmt: skip

    def read(member: dict[str, Any]) -> str:
        path = work / f"{member['key']}.findings.jsonl"
        return path.read_text("utf-8", "replace") if path.is_file() else ""

    signed, skipped = _review_run.sign_all(head, members, read, key, args.key_id)
    stored = _review_run.load(repo, args.review_id)
    have = {r["finding_id"] for r in stored}
    fresh = [r for r in signed if r["finding_id"] not in have]
    _review_run.save(repo, args.review_id, stored + fresh)
    digest = _review.digest(head)
    if signed:
        version = _review.sign(_review_run.next_version(head, signed), key, key_id=args.key_id)
        digest = store.append(repo, version, expected=_review.digest(head))
    rows = _review_run.verify_all(signed, head["reviewers"])
    body = {"review_id": args.review_id, "fleet": fleet.name, "fleet_id": state.id,
            "exit_code": code, "members": members, "findings": rows, "skipped": skipped,
            "head": digest}  # fmt: skip
    text = (f"review {args.review_id}: {len(rows)} signed finding(s) from {len(members)} "
            f"reviewer(s), {skipped} skipped; head {digest}")  # fmt: skip
    return body, text


def _findings(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], str]:
    from opentine import _review_run
    from opentine.repository import _review_store as store

    current = store.load(repo, args.review_id)
    if current is None:
        raise KeyError(f"no review {args.review_id} here")
    reviewers = current["versions"][-1]["reviewers"]
    rows = _review_run.verify_all(_review_run.load(repo, args.review_id), reviewers)
    lines = [f"{r['finding_id']} {r.get('severity', '?')} {r.get('path') or '-'}"
             f":{r.get('line') or ''} {r['state']}" for r in rows]  # fmt: skip
    return {"review_id": args.review_id, "findings": rows}, "\n".join(lines) or "no findings"


def act(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], str]:
    return (_run if args.review_action == "run" else _findings)(args, repo)


__all__ = ["act", "add_run_parsers"]
