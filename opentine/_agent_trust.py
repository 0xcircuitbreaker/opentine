"""Per-run trust states and lineage, recomputed from runs and manifests.

``TrustResolver`` is what ``who``, ``touched``, ``audit`` and ``agent show``
ask "is this run's agent verified?". It never trusts the action index: a row's
``agent_ref`` counts only when the run itself, reloaded, has that ref, and a
verdict comes from :func:`opentine._actions_verdict.verify` every time.

A **lineage link** (child -> parent) is trusted only from both sides: the child
is verified, the parent run it names is verified with the ref the child claims,
and the parent's signed manifest records the child's ``spawn_step`` as a
subagent spawn. A child cannot adopt a parent on its own say-so. The edge
itself (child ref, parent ref) is recomputed from the reloaded child run, never
taken from an index row: a row only nominates a run id to check.

Accepted residual: the parent's signed manifest lists spawn *step ids* only, not
which child each spawned, so a second verified run (signed by a trusted key)
that names a real spawn step of a verified parent is accepted as its subagent
too. Binding a spawn to the child instance needs the child's id inside the
parent's signed manifest, a format change left for a later release.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from opentine import _agent_identity as identity
from opentine._actions_verdict import Trust, load_manifest, verify

MAX_LINEAGE_ROUNDS = 10_000


class TrustResolver:
    def __init__(
        self,
        load_run: Callable[[str], Any],
        base: Path | None,
        *,
        hmac_key: bytes | None = None,
        public_key: Any | None = None,
        pins: frozenset[str] = frozenset(),
    ):
        self._load_run, self.base = load_run, base
        self._keys = {"hmac_key": hmac_key, "public_key": public_key, "pins": pins}
        self._runs: dict[str, Any] = {}
        self._trust: dict[str, Trust] = {}

    def run(self, run_id: str) -> Any:
        if run_id not in self._runs:
            try:
                self._runs[run_id] = self._load_run(run_id)
            except Exception:
                self._runs[run_id] = None
        return self._runs[run_id]

    def adopt(self, run: Any) -> None:
        """Use *run*, already loaded by the caller, for its own id."""
        self._runs[run.id] = run

    def trust(self, run_id: str) -> Trust:
        if run_id in self._trust:
            return self._trust[run_id]
        stored = load_manifest(self.base, run_id)
        if stored is None:
            verdict = Trust("unsigned", "no action manifest")
        elif stored is False:
            verdict = Trust("mismatch", "action manifest is unreadable")
        elif (run := self.run(run_id)) is None:
            verdict = Trust("mismatch", "run cannot be loaded")
        else:
            verdict = verify(stored, run, **self._keys)
        self._trust[run_id] = verdict
        return verdict

    def ref_holds(self, run_id: str, ref: str) -> bool:
        """Whether *run_id*, reloaded, really has agent ref *ref* (full length)."""
        run = self.run(run_id)
        return run is not None and identity.same_ref(identity.run_agent_ref(run), ref)

    def lineage_ok(self, run_id: str) -> bool:
        """The run's parent link is verified from both sides."""
        return self.lineage_edge(run_id) is not None

    def lineage_edge(self, run_id: str) -> tuple[str, str] | None:
        """``(child ref, parent ref)`` recomputed from the run, if verified both ways."""
        child = self.run(run_id)
        record = identity.run_identity(child) if child is not None else None
        if not record or not record["parent"] or not record["parent_run"]:
            return None
        if not self.trust(run_id).verified or not self.trust(record["parent_run"]).verified:
            return None
        parent = self.run(record["parent_run"])
        if parent is None or not identity.same_ref(
            identity.run_agent_ref(parent), record["parent"]
        ):
            return None
        stored = load_manifest(self.base, record["parent_run"])
        spawns = stored.get("body", {}).get("spawns", []) if isinstance(stored, dict) else []
        if not isinstance(spawns, list) or record["spawn_step"] not in spawns:
            return None
        return identity.run_agent_ref(child), record["parent"]


def lineage_refs(
    root: str,
    edges: Iterable[tuple[str, str, str]],
    *,
    resolver: TrustResolver | None = None,
) -> set[str]:
    """*root* and every ref descending from it over ``(run_id, ref, parent_ref)`` edges.

    Iterative, so a deep or cyclic claimed chain cannot exhaust the stack. With
    *resolver*, an edge's run id is only a nomination: the ``(ref, parent)`` pair
    followed is the one :meth:`TrustResolver.lineage_edge` recomputes and
    verifies from the run and the signed manifests, never the row's own.
    """
    if resolver is not None:
        nominated = dict.fromkeys(run_id for run_id, _, _ in edges)
        edges = [(run_id, *edge) for run_id in nominated if (edge := resolver.lineage_edge(run_id))]
    pending = [(run_id, ref, parent) for run_id, ref, parent in edges if ref and parent]
    found = {root}
    for _ in range(MAX_LINEAGE_ROUNDS):
        grew = False
        for run_id, ref, parent in pending:
            if ref in found or not any(identity.same_ref(parent, item) for item in found):
                continue
            found.add(ref)
            grew = True
        if not grew:
            break
    return found


__all__ = ["TrustResolver", "lineage_refs"]
