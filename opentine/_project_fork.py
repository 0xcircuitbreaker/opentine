"""``tine project claim`` and ``tine project fork`` (0.47, SPEC 4.19).

* :func:`write_claim` writes ``.opentine/project`` (an ``opentine.forge-claim``)
  into a code checkout for the owner to commit on the default branch;
  :func:`check_claim` checks such a file against this repository's project.
* :func:`fork` copies a run repository, never code: every object and ref of the
  source except the ``project/`` namespace and its manifest blobs, then a new
  first manifest whose ``forked_from`` is the source's ``project_id``. The fork
  point (the source's ``{project_id, tenant, genesis, head, seq}``) is kept in
  ``.tine/project-fork.json``, which, like the locator file, is never pushed,
  bundled or served.
* :func:`check_source` is ``tine project verify --source``: the source chain
  verifies, its id is ``forked_from``, the fork is another project, and the
  recorded fork point is still in the source's history.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentine import _forge_claim, _project
from opentine._signed_record import RecordError
from opentine.kernel import canonical_json
from opentine.repository._paths import atomic_bytes, internal_path
from opentine.repository._refs import PROJECT_REF

FORK_FILE = "project-fork.json"


def _history(repo: Any) -> list[dict[str, Any]]:
    from opentine.repository import _project_ref

    versions = _project_ref.history(repo)
    if not versions:
        raise KeyError("no project here: `tine project init` first")
    return versions


def _primary_branch(record: dict[str, Any]) -> str:
    return next(s["default_branch"] for s in record["slots"] if s["role"] == "primary")


def write_claim(repo: Any, code_dir: str | Path) -> dict[str, Any]:
    versions = _history(repo)
    head = versions[-1]
    claim = _forge_claim.build(head["project_id"], head["tenant"], _project.digest(versions[0]))
    path = Path(code_dir) / _forge_claim.PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_bytes(path, _forge_claim.encode(claim))
    return {"claim": claim, "path": _forge_claim.PATH, "branch": _primary_branch(head)}


def check_claim(repo: Any, data: bytes | None, branch: str | None) -> dict[str, Any]:
    versions = _history(repo)
    head = versions[-1]
    project = {"project_id": head["project_id"], "tenant": head["tenant"],
               "genesis": _project.digest(versions[0]),
               "default_branch": _primary_branch(head)}  # fmt: skip
    claim = None if data is None else _forge_claim.parse(data)
    return _forge_claim.check(claim, branch=branch or project["default_branch"], project=project)


def fork(source: Any, dest: str | Path, record: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    """Copy *source* into a new repository at *dest*; return it and the fork point.

    *record* is the fork's signed first manifest; it must name the source's
    ``project_id`` in ``forked_from`` and be another project.
    """
    from opentine.repository import Repo, _project_ref

    versions = _history(source)
    head = versions[-1]
    point = {"project_id": head["project_id"], "tenant": head["tenant"],
             "genesis": _project.digest(versions[0]), "head": _project.digest(head),
             "seq": head["seq"]}  # fmt: skip
    if record.get("forked_from") != head["project_id"]:
        raise ValueError("a fork names its source's project_id in forked_from")
    if (record.get("project_id"), record.get("tenant")) == (head["project_id"], head["tenant"]):
        raise ValueError("a fork is another project: change --project-id or --tenant")
    target = Path(dest)
    if (target / ".tine").exists():
        raise ValueError(f"{target.as_posix()} already holds a repository")
    manifests = {_project.digest(v) for v in versions}
    oids = [oid for oid in source.iter_oids() if oid not in manifests]
    copy = Repo.init(target)
    if oids:
        copy.import_pack(source.pack(oids))
    for name, oid in sorted(source.list_refs().items()):
        if name.removeprefix("refs/") != PROJECT_REF and not name.startswith("project/"):
            copy.update_ref(name, oid, expected_old=None)
    _project_ref.write(copy, record)
    atomic_bytes(internal_path(copy.path, FORK_FILE), canonical_json(point))
    return copy, point


def fork_point(repo: Any) -> dict[str, Any] | None:
    try:
        raw = internal_path(repo.path, FORK_FILE).read_bytes()
    except FileNotFoundError:
        return None
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{FORK_FILE} is malformed")
    return value


def _break(message: str) -> RecordError:
    return RecordError("project.chain-break", f"{message}: it breaks the project chain")


def check_source(repo: Any, source_versions: list[dict[str, Any]]) -> dict[str, Any]:
    """``tine project verify --source``: this fork against its source's history."""
    ours = _history(repo)
    if ours[0].get("forked_from") is None:
        raise ValueError("this project is not a fork (forked_from is null)")
    source = _project.chain(source_versions)
    if source["project_id"] != ours[0]["forked_from"]:
        raise _break(f"forked_from names {ours[0]['forked_from']}, the source is "
                     f"{source['project_id']}")  # fmt: skip
    if (ours[0]["project_id"], ours[0]["tenant"]) == (source["project_id"], source["tenant"]):
        raise _break("a fork cannot be the source project itself")
    point = fork_point(repo)
    digests = [_project.digest(v) for v in source_versions]
    if point is not None and (
        point.get("genesis") != digests[0] or point.get("head") not in digests
    ):
        raise _break("the source's history no longer holds the recorded fork point")
    return {"forked_from": source["project_id"], "source_head": source["head"],
            "source_versions": source["versions"],
            "fork_point": None if point is None else point["head"],
            "state": "fork-verified" if point else "fork-unrecorded"}  # fmt: skip


__all__ = ["FORK_FILE", "check_claim", "check_source", "fork", "fork_point", "write_claim"]
