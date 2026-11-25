"""Held collusion-protocol verdicts and their oversight items (0.83).

``tine monitor protocol-run --key K --record`` stores each signed
``{claim, verdict}`` line (:mod:`opentine._collusion_verdicts`) as a blob and
holds it under ``collusion-verdict:<verdict digest>``, released never, so a
loop cannot delete a run it failed. :func:`items` feeds the ``collusion``
source of the oversight queue (:mod:`opentine._oversight_queue`): every held
overall verdict (item ``collusion``) that did not pass opens
``collusion:<blob>``, and so does every held line that no longer checks (a bad
signature, a claim that does not follow from its counts, or a signer that is
not a pinned ``verdict`` key): the queue fails closed on what it cannot read.
Nothing is indexed: the holds file is the only list. No object kind is added.
"""

from __future__ import annotations

from typing import Any

SOURCE = "collusion"


def record(repo: Any, signed: list[dict[str, Any]]) -> list[str]:
    """Store and hold every signed line; returns the blob ids in order."""
    from opentine._eval_verdict import digest
    from opentine.kernel import canonical_json
    from opentine.repository._holds import COLLUSION_VERDICT, edit_holds, holds_path
    from opentine.repository._link_touch import touch_links

    oids, rows = [], []
    for line in signed:
        oid = repo.put("blob", canonical_json(line), redact=False)
        oids.append(oid)
        rows.append({"oid": oid, "target": COLLUSION_VERDICT + digest(line["verdict"])})
    touch_links(repo, oids)  # a concurrent prune keeps them, or the hold fails
    edit_holds(holds_path(repo), lambda old: [*(r for r in old if r not in rows), *rows])
    return oids


def _fails(repo: Any, oid: str) -> bool:
    from opentine import _collusion_verdicts, _json_shallow

    try:
        line = _json_shallow.loads(repo.get(oid).payload())
        _collusion_verdicts.check(line, repo.path)
    except Exception:  # noqa: BLE001 - a held line that does not check is listed (fail closed)
        return True
    return line["claim"]["item"] == "collusion" and line["verdict"]["passed"] is False


def held(repo: Any) -> list[str]:
    from opentine.repository._holds import COLLUSION_VERDICT, holds_path, read_holds

    rows = read_holds(holds_path(repo))
    return sorted({r["oid"] for r in rows if r["target"].startswith(COLLUSION_VERDICT)})


def items(repo: Any) -> list[dict[str, Any]]:
    """``[{"item", "source"}]`` for every failed or unverifiable held verdict."""
    return [{"item": f"{SOURCE}:{oid}", "source": SOURCE}
            for oid in held(repo) if _fails(repo, oid)]  # fmt: skip


__all__ = ["SOURCE", "held", "items", "record"]
