"""Adopting the annotation refs a remote advertises, run by run, after a fetch.

Split from ``_unadopted`` (which records the annotations a pack must not relabel
runs with) to keep each module inside the architecture limit.
"""

from __future__ import annotations

from opentine.kernel import KernelError


class _Chains:
    """Each annotation's ``(previous_id, target_id)``, read at most once per fetch.

    A remote advertising thousands of refs at one long chain made every ref walk
    the whole chain again: quadratic object reads after the transfer. Reads are
    memoized, and a chain's delivered verdict is recorded on every link walked.
    """

    def __init__(self, repo) -> None:
        self.repo = repo
        self.links: dict[str, tuple[str | None, object]] = {}
        self.verdict: dict[str, bool] = {}

    def link(self, oid: str) -> tuple[str | None, object]:
        if oid not in self.links:
            payload = self.repo.get(oid).payload()
            previous = payload.get("previous_id")
            previous = previous if isinstance(previous, str) else None
            self.links[oid] = (previous, payload.get("target_id"))
        return self.links[oid]


def _fast_forward(repo, old: str | None, new: str, chains: _Chains | None = None) -> bool:
    from opentine.repository.pack import MAX_PACK_OBJECTS

    chains = chains or _Chains(repo)
    current: str | None = new
    for _ in range(MAX_PACK_OBJECTS):
        if current == old or old is None:
            return True
        current = chains.link(current)[0]
        if current is None:
            return False
    return False


def runs_held(repo, remote_refs: dict[str, str]) -> frozenset[str]:
    """The advertised annotation refs whose run *repo* holds now (before a fetch)."""
    held = set()
    for name in remote_refs:
        if not name.startswith("annotations/"):
            continue
        try:
            if repo.has("run:sha256:" + name.removeprefix("annotations/")):
                held.add(name)
        except (KeyError, ValueError):
            continue
    return frozenset(held)


def adopt_advertised_annotations(
    repo,
    remote_refs: dict[str, str],
    held_before: frozenset[str] = frozenset(),
    remote_name: str = "origin",
    *,
    adopt_held: bool = False,
) -> None:
    """Fast-forward the annotation refs the remote advertises, for runs it brought.

    A run this fetch delivered takes its tags and metadata from the remote, as a
    clone always has. A run that was already here does not: any writer to a
    shared remote could otherwise push an annotation *and* its ref and relabel a
    local run on the next fetch. Its advertised head is kept as
    ``remotes/<remote>/annotations/<digest>`` instead, for the owner to inspect
    and adopt (``adopt_held``, ``tine fetch --adopt-annotations``). A ref that is
    mis-bound, or whose chain is cut by a shallow boundary, changes nothing.
    """
    from opentine.repository._unadopted import read_unadopted

    path = getattr(repo, "path", None)
    skipped = read_unadopted(path) if path is not None else frozenset()
    chains = _Chains(repo)
    for name, remote in sorted(remote_refs.items()):
        if not name.startswith("annotations/"):
            continue
        try:
            # The cheap binding check first: a ref naming another run's annotation
            # is refused by update_ref anyway, so it must not cost a chain walk.
            run = "run:sha256:" + name.removeprefix("annotations/")
            if not repo.has(remote) or chains.link(remote)[1] != run:
                continue
            target = name
            if name in held_before and not adopt_held:
                target = f"remotes/{remote_name}/{name}"
            elif name not in held_before and (
                not getattr(skipped, "complete", True)
                or not repo.has(run)
                or not _delivered(chains, remote, skipped)
            ):
                # A run still absent (a shallow boundary), or an annotation the
                # install recorded as foreign: a pack may plant one ahead of the
                # run it names, so its ref is never adopted locally.
                continue
            local = repo.read_ref(target)
            if local != remote and _fast_forward(repo, local, remote, chains):
                repo.update_ref(target, remote, expected_old=local)
        except (KeyError, ValueError, KernelError):
            continue


def _delivered(chains: _Chains, remote: str, skipped: frozenset[str]) -> bool:
    """Whether *remote*'s chain is the pack's own: no link recorded as foreign."""
    from opentine.repository.pack import MAX_PACK_OBJECTS

    walked: list[str] = []
    current: str | None = remote
    verdict = False
    for _ in range(MAX_PACK_OBJECTS):
        if current is None:
            verdict = True
            break
        if current in chains.verdict:
            verdict = chains.verdict[current]
            break
        if current in skipped:
            break
        walked.append(current)
        current = chains.link(current)[0]
    chains.verdict.update(dict.fromkeys(walked, verdict))
    return verdict
