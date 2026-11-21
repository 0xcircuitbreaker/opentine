"""A curated dataset version as an eval dataset (0.75).

:func:`materialize` writes the members of one held ``opentine.dataset-version/1``
as JSON Lines eval items (:func:`opentine._eval_dataset.run_item`: the run's
prompt as ``input``, its last answer as ``output``, the run id as ``run``, the
version and member content digest in ``metadata``), the
file ``tine eval``, ``tine dataset seal`` and the canary checks already read.

The gate fails closed: only a version that ``tine dataset versions`` reports
``verified`` is written (its offline check holds, its signer is a pinned
``curator`` key that is not an ``optimizer`` key, and no member has been
tainted since curation). A version the repository does not hold, one that is
unverified, or a member that cannot be loaded refuses and writes nothing. Runs
withdrawn after curation are left out and listed, so a withdrawal applies to
every later use of the version as well as to later versions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def materialize(repo: Any, record: str, out: str | Path) -> dict[str, Any]:
    """Write *record*'s members to *out*; the summary row (raises on refusal)."""
    from opentine._dataset_version import versions, withdrawals
    from opentine._eval_dataset import dataset_digest, run_item, write_jsonl

    row = next((v for v in versions(repo) if v["record"] == record), None)
    if row is None:
        raise KeyError(f"{record} is not a held dataset version")
    if row["verification"] != "verified":
        raise PermissionError(f"refusing to materialize {record}: {row['verification']}")
    claim = repo.get(record).payload()["claim"]
    gone = withdrawals(repo)
    items, withdrawn = [], []
    for member in claim["members"]:
        run_id = member["run"]
        if run_id in gone:
            withdrawn.append(run_id)
            continue
        try:
            run = repo.load_run(run_id)
        except Exception as exc:  # noqa: BLE001 - any unreadable member refuses the whole file
            raise ValueError(f"member {run_id} cannot be loaded: {exc}") from exc
        meta = {"dataset_version": record, "content": member["content"]}
        items.append({**run_item(run, run_id), "metadata": meta})
    path = Path(out)
    write_jsonl(path, items)
    return {"ok": True, "record": record, "name": claim["name"], "version": claim["version"],
            "out": path.as_posix(), "items": len(items), "digest": dataset_digest(items),
            "withdrawn": withdrawn}  # fmt: skip


__all__ = ["materialize"]
