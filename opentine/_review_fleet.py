"""Run a reviewer fleet on one change and sign what it finds (0.48, shared in 0.55).

``tine review run`` and the review runner (:mod:`opentine._review_runner`) both
call :func:`run_fleet`: the members run on the fleet executor with the change in
``OPENTINE_REVIEW_CONTEXT``, every well-formed finding is signed by *key* (a
reviewer of the Review's head version) and stored, and the Review's next
version lists them (:mod:`opentine._review_run`).
"""

from __future__ import annotations

import io
from typing import Any


def run_fleet(repo: Any, review_id: str, fleet: Any, key: Any, key_id: str | None, text: str, *,
              extra_env: dict[str, str] | None = None,
              created_at: str | None = None) -> dict[str, Any]:  # fmt: skip
    """``{review_id, fleet, fleet_id, exit_code, members, findings, skipped, head, cost}``."""
    from opentine import _review, _review_run
    from opentine.fleet import _runner
    from opentine.repository import _review_store as store

    current = store.load(repo, review_id)
    if current is None:
        raise KeyError(f"no review {review_id} here: `tine review create` first")
    head = current["versions"][-1]
    if key.public_key().public_bytes_raw().hex() not in head["reviewers"]:
        raise ValueError("the signing key is not a reviewer of the head version")
    state = _runner.create(fleet)
    work = state.directory / state.id
    work.mkdir(parents=True, exist_ok=True)
    (work / "review-context.diff").write_text(text, "utf-8")

    def extra(member: str) -> dict[str, str]:
        return {**(extra_env or {}), "OPENTINE_REVIEW_ID": review_id,
                "OPENTINE_REVIEW_CONTEXT": str(work / "review-context.diff"),
                "OPENTINE_REVIEW_FINDINGS": str(work / f"{member}.findings.jsonl")}  # fmt: skip

    code = _runner.run(fleet, state, out=io.StringIO(), extra=extra)
    members = [{"key": m["key"], "name": f"{m['vary']['agent']}-{m['key']}", "run": m.get("run"),
                "status": m["status"]} for m in state.data["members"]]  # fmt: skip

    def read(member: dict[str, Any]) -> str:
        path = work / f"{member['key']}.findings.jsonl"
        if path.is_symlink() or not path.is_file():
            return ""
        with path.open("rb") as handle:  # a member cannot make the run read without bound
            return handle.read(_review_run.MAX_CONTEXT).decode("utf-8", "replace")

    signed, skipped = _review_run.sign_all(head, members, read, key, key_id, created_at)
    stored = _review_run.load(repo, review_id)
    have = {r["finding_id"] for r in stored}
    _review_run.save(repo, review_id, stored + [r for r in signed if r["finding_id"] not in have])
    digest = _review.digest(head)
    if signed:
        version = _review.sign(_review_run.next_version(head, signed), key, key_id=key_id)
        digest = store.append(repo, version, expected=_review.digest(head))
    total, unknown = _runner.cost(state)
    return {"review_id": review_id, "fleet": fleet.name, "fleet_id": state.id,
            "exit_code": code, "members": members, "signed": signed,
            "findings": _review_run.verify_all(signed, head["reviewers"], review_id),
            "skipped": skipped, "head": digest,
            "cost": {"total": str(total), "unknown_members": unknown}}  # fmt: skip


__all__ = ["run_fleet"]
