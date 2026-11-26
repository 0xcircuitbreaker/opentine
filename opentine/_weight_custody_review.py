"""Custody gaps and refused tagged loads in the oversight queue (0.72).

:func:`items` lists what ``tine oversight queue`` shows under the ``custody``
source, recomputed from held records on every read (nothing new is trusted):

* ``custody:attestation:sha256:...`` -- a held weight custody event that a
  ``fail:`` finding of ``tine custody check`` names (a gap, a broken chain or an
  unapproved load of a ``model-organism`` artifact);
* ``custody:blob:sha256:...`` -- a refused load of a tagged artifact: an
  ``opentine.weight-custody-refusal/1`` entry the ``tine custody gate`` hook held
  when it denied a call, or an ``opentine.organism-access/1`` entry whose
  ``outcome`` is ``refused``.

A refusal entry is a held blob (hold ``custody:weights-refused:NAME``) that
``tine hold release`` refuses; it is a convention, not an object kind. Approving
a custody item records a reviewer's decision; it never allows a load (the gates
read only custody approvals and organism approvals).
"""

from __future__ import annotations

import json
from typing import Any

from opentine.kernel import canonical_json

REFUSAL = "opentine.weight-custody-refusal/1"
REFUSED_HOLD = "custody:weights-refused:"
SOURCE = "custody"


def log_refusal(repo: Any, artifact: str, reason: str, tool: str | None, at: str) -> str:
    """Store and hold one refused load; its blob id."""
    from opentine.repository._holds import hold_row

    entry = {"convention": REFUSAL, "artifact": artifact, "reason": reason, "tool": tool,
             "at": at}  # fmt: skip
    oid = repo.put("blob", canonical_json(entry), redact=False)
    hold_row(repo, oid, REFUSED_HOLD + artifact)
    return oid


def _blob(repo: Any, oid: str) -> dict[str, Any]:
    try:
        doc = json.loads(bytes(repo.get(oid).body))
    except Exception:  # noqa: BLE001 - an unreadable entry is still listed for review
        return {}
    return doc if isinstance(doc, dict) else {}


def _refusals(repo: Any, rows: list[dict[str, str]]) -> list[str]:
    from opentine._organism import ACCESS, HOLD

    out = []
    for row in rows:
        if row["target"].startswith(REFUSED_HOLD):
            out.append(row["oid"])  # listed even when unreadable: fail toward review
        elif row["target"].startswith(HOLD + "access:"):
            doc = _blob(repo, row["oid"])
            if doc.get("convention") == ACCESS and doc.get("outcome") == "refused":
                out.append(row["oid"])
    return out


def items(repo: Any) -> list[dict[str, Any]]:
    """``[{"item", "source"}]`` for every custody gap record and refused tagged load."""
    from opentine import _weight_custody as wc
    from opentine import _weight_custody_check as check
    from opentine.repository._holds import holds_path, read_holds

    found: set[str] = set()
    for artifact in wc.artifacts(repo):
        for finding in check.check(repo, artifact)["findings"]:
            if finding["code"].startswith("fail:") and finding["record"]:
                found.add(finding["record"])
    found.update(_refusals(repo, read_holds(holds_path(repo))))
    return [{"item": f"{SOURCE}:{oid}", "source": SOURCE} for oid in sorted(found)]


__all__ = ["REFUSAL", "REFUSED_HOLD", "SOURCE", "items", "log_refusal"]
