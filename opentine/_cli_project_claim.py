"""``tine project claim|fork`` and ``verify --source`` (0.47, SPEC 4.23).

``claim [--code DIR]`` writes ``DIR/.opentine/project`` (an
``opentine.forge-claim``) for the owner to commit on the default branch;
``claim --check FILE [--branch B]`` checks one against this repository's
project (``--missing`` checks the absence of one), and never reports a pass:
the best answer is ``claimed by upstream (as mirrored)``.

``fork DEST --project-id ID [--tenant T] --ed25519-key-file K`` copies this run
repository (never code) into DEST under a new project whose ``forked_from`` is
this one. ``verify --source PATH`` on a fork checks ``forked_from`` against the
source repository's project history (:mod:`opentine._project_fork`).
"""

from __future__ import annotations

import argparse
from typing import Any


def add_claim_parsers(actions: Any) -> list[argparse.ArgumentParser]:
    claim = actions.add_parser("claim", help="Write or check .opentine/project (forge claim)")
    claim.add_argument("--code", default=".", metavar="DIR", help="Code checkout to write into")
    claim.add_argument("--check", metavar="FILE", help="Check this claim file instead")
    claim.add_argument("--missing", action="store_true", help="Check: the upstream has none")
    claim.add_argument("--branch", help="Check: the branch the file was found on")
    fork = actions.add_parser("fork", help="Copy this run repository under a new project")
    fork.add_argument("dest", metavar="DEST", help="Directory for the forked repository")
    fork.add_argument("--project-id", required=True)
    fork.add_argument("--tenant", help="The fork's tenant (default: the source's)")
    fork.add_argument("--ed25519-key-file", required=True, metavar="PATH",
                      help="The forker's Ed25519 key; it owns and signs the fork")  # fmt: skip
    fork.add_argument("--key-id", help="Key id recorded in the signature")
    return [claim, fork]


def claim(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    from opentine import _project_fork
    from opentine.repository import Repo

    repo = Repo.open(args.repo)
    if args.check or args.missing:
        data = None
        if args.check:
            with open(args.check, "rb") as handle:
                data = handle.read(1 << 16)
        result = _project_fork.check_claim(repo, data, args.branch)
        return {"result": result}, f"{result['label']}: {result['project_id']}"
    body = _project_fork.write_claim(repo, args.code)
    return body, f"wrote {body['path']}: commit it on {body['branch']}"


def fork(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    from opentine import _project, _project_fork
    from opentine._signing_keys import ed25519_private_from_file
    from opentine.repository import Repo, _project_ref

    source = Repo.open(args.repo)
    head = _project_ref.read(source)
    if head is None:
        raise KeyError("no project here: `tine project init` first")
    key = ed25519_private_from_file(args.ed25519_key_file)
    owner = key.public_key().public_bytes_raw().hex()
    record = _project.build(args.project_id, args.tenant or head["tenant"], owners=[owner],
                            slots=head["slots"], visibility=head["visibility"],
                            forked_from=head["project_id"])  # fmt: skip
    signed = _project.sign(record, key, key_id=args.key_id)
    copy, point = _project_fork.fork(source, args.dest, signed)
    summary = {name: signed[name] for name in ("project_id", "tenant", "seq", "visibility")}
    body = {"project": summary, "digest": _project.digest(signed), "manifest": signed,
            "fork_point": point}  # fmt: skip
    return (
        body,
        f"forked {point['project_id']} into {args.project_id} at {copy.worktree.as_posix()}",
    )


def verify_source(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _project_fork
    from opentine.repository import Repo, _project_ref

    source = _project_ref.history(Repo.open(args.source))
    if not source:
        raise KeyError("the source has no project")
    return _project_fork.check_source(Repo.open(args.repo), source)


__all__ = ["add_claim_parsers", "claim", "fork", "verify_source"]
