"""``tine publish zenodo | hf``: put run bundles where papers and datasets live (0.49).

``zenodo`` deposits a bundle of the named refs (and any ``--attach`` files, such
as a ``tine export --format run-crate`` crate) on Zenodo; ``hf`` uploads one
run's redacted, signed public copy to a Hugging Face Hub dataset. Both refuse
unredacted content with the push gate before any request, read their token
only from an environment variable and never print it, and record what they
published in the op log. ``--dry-run`` needs neither a token nor the network.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine._cli_errors import fail
from opentine._cli_json import emit


def add_publish_parser(sub: Any) -> None:
    publish = sub.add_parser("publish", help="Deposit run bundles on Zenodo or Hugging Face")
    actions = publish.add_subparsers(dest="publish_action", required=True)
    z = actions.add_parser("zenodo", help="Deposit a run bundle (and crates) on Zenodo")
    z.add_argument("refs", nargs="+", help="Refs to bundle (heads/NAME, tags/NAME, ...)")
    z.add_argument(
        "--attach",
        action="append",
        default=[],
        metavar="FILE",
        help="Also deposit FILE, e.g. a run crate (scanned like the bundle)",
    )
    z.add_argument(
        "--creator",
        action="append",
        default=[],
        metavar="NAME",
        help="A creator, 'Family, Given' (repeatable; at least one)",
    )
    z.add_argument("--title")
    z.add_argument("--description")
    z.add_argument("--access-right", choices=("open", "closed"), default="open")
    z.add_argument("--license", default="cc-by-4.0", help="A Zenodo license id")
    z.add_argument(
        "--publish",
        action="store_true",
        help="Publish (mints a DOI; cannot be undone). Default: leave a draft",
    )
    z.add_argument("--sandbox", action="store_true", help="Use sandbox.zenodo.org")
    z.add_argument(
        "--allow-unredacted",
        metavar="REASON",
        help="Deposit even if content fails the redaction scan; REASON is logged",
    )
    h = actions.add_parser("hf", help="Upload a redacted, signed run bundle to a HF dataset")
    h.add_argument("ref", help="The run ref whose redacted copy is published")
    h.add_argument("--dataset", required=True, metavar="OWNER/NAME")
    keys = h.add_mutually_exclusive_group()
    keys.add_argument("--key-file", metavar="PATH", help="Sign the copy's record (HMAC key)")
    keys.add_argument("--ed25519-key-file", metavar="PATH", help="Sign the copy's record")
    h.add_argument("--key-id", help="Key id recorded in the signature")
    h.add_argument("--revision", default="main", help="The dataset branch")
    h.add_argument("--create", action="store_true", help="Create the dataset if it is missing")
    h.add_argument("--private", action="store_true", help="With --create: a private dataset")
    for p in (z, h):
        p.add_argument("--api-url", help="API base URL (default: the public service)")
        p.add_argument("--token-env", metavar="NAME", help="Environment variable with the token")
        p.add_argument("--dry-run", action="store_true", help="Gate and plan only; send nothing")
        p.add_argument("--json", action="store_true")
        p.add_argument("--repo", default=".")


def _zenodo(repo: Any, args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _publish_common as common
    from opentine import _publish_zenodo as zenodo

    data, checked = common.gated_bundle(repo, args.refs, args.allow_unredacted)
    files = [(common.file_name(f"opentine-{checked.digest[7:19]}.tbundle"), data)]
    for path in map(Path, args.attach):
        raw = path.read_bytes()
        common.gated_file(repo, path.name, raw, args.allow_unredacted)
        files.append((common.file_name(path.name), raw))
    meta = zenodo.metadata(args, checked.digest, checked.refs)
    base = common.api_base(args.api_url or (zenodo.SANDBOX if args.sandbox else zenodo.ZENODO))
    body: dict[str, Any] = {
        "api": base,
        "bundle": {"digest": checked.digest, "bytes": len(data), "refs": checked.refs},
        "files": [{"name": name, "bytes": len(raw)} for name, raw in files],
    }
    if args.dry_run:
        return {**body, "plan": zenodo.plan(files, args.publish)}
    token = common.token(args.token_env or zenodo.TOKEN_ENV)
    with common.client() as session:
        done = zenodo.deposit(session, base, token, files, meta, args.publish)
    names = ", ".join(name for name, _raw in files)
    common.record(
        repo,
        f"publish zenodo: deposition {done['deposition']} ({done['state']}"
        f"{', doi ' + done['doi'] if done['doi'] else ''}) at {base}: bundle "
        f"{checked.digest} of {', '.join(sorted(checked.refs))}; files {names}",
    )
    return {**body, "published": done}


def _hf(repo: Any, args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _bundle, _bundle_share
    from opentine import _publish_common as common
    from opentine import _publish_hf as hf
    from opentine._push_gate import scan
    from opentine._redacted_derive import _View, derive

    dataset = hf.dataset_id(args.dataset)
    base = common.api_base(args.api_url or hf.HUB)
    run = repo.read_ref(_ref(args.ref))
    if not run or not run.startswith("run:"):
        raise KeyError(f"no such run ref: {args.ref}")
    _public, objects, boundary, _changed = derive(repo, run)
    hits = scan(_View(objects, boundary), set(objects))
    if hits:
        raise ValueError(
            f"publish refused: {len(hits)} object(s) of the redacted copy fail the redaction "
            "scan; a Hub dataset is public, so there is no override"
        )
    shim = argparse.Namespace(
        refs=[args.ref],
        all=False,
        transparency=False,
        pack_format="TINEPACK3",
        key_file=args.key_file,
        ed25519_key_file=args.ed25519_key_file,
        key_id=args.key_id,
    )
    data = _bundle_share.create_public(repo, shim)
    checked = _bundle.verify(data)
    record = checked.redacted_public or {}
    public = record.get("public_run", "")
    entry = {
        "path": f"runs/{public.split(':', 1)[-1][:16]}.tbundle",
        "public_run": public,
        "digest": checked.digest,
        "algorithm": (record.get("signature") or {}).get("algorithm", "unknown"),
    }
    body: dict[str, Any] = {
        "api": base,
        "dataset": dataset,
        "bundle": {"digest": checked.digest, "bytes": len(data), "refs": checked.refs},
        "files": [{"name": entry["path"], "bytes": len(data)}, {"name": "README.md"}],
        "public_run": public,
    }
    if args.dry_run:
        return {**body, "plan": hf.plan(entry, args.create)}
    token = common.token(args.token_env or hf.TOKEN_ENV)
    with common.client() as session:
        done = hf.upload(
            session,
            base,
            token,
            dataset,
            revision=args.revision,
            entry=entry,
            data=data,
            create=args.create,
            private=args.private,
        )
    common.record(
        repo,
        f"publish hf: dataset {dataset}@{args.revision} commit {done['commit'] or 'unknown'} "
        f"at {base}: redacted copy {public} of {run} as {entry['path']} (bundle {checked.digest})",
    )
    return {**body, "published": done}


def _ref(name: str) -> str:
    from opentine.repository._refs import normalize_ref

    return normalize_ref(name if "/" in name else f"heads/{name}")


def cmd_publish(args: argparse.Namespace) -> None:
    import httpx

    from opentine._bundle import BundleError
    from opentine._publish_common import PublishError
    from opentine._signed_record import RecordError
    from opentine.repo import Repo

    action = args.publish_action
    try:
        repo = Repo.open(args.repo)
        result = (_zenodo if action == "zenodo" else _hf)(repo, args)
    except httpx.HTTPError as exc:
        fail(f"the service could not be reached ({type(exc).__name__})", prefix="tine publish: ")
    except (PublishError, BundleError, RecordError, KeyError, OSError, ValueError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
        fail(str(message), prefix="tine publish: ")
    body = {"command": "publish", "action": action, "ok": True, "dry_run": bool(args.dry_run)}
    body.update(result)
    if args.json:
        emit(body)
        return
    print(f"bundle {result['bundle']['digest']} ({result['bundle']['bytes']} bytes)")
    for row in body.get("plan", []):
        print(f"would {row['method']} {row['path']}")
    done = body.get("published")
    if done:
        where = done.get("doi") or done.get("url") or done.get("commit") or ""
        print(f"published to {action}: {done.get('state', 'committed')} {where}".rstrip())


__all__ = ["add_publish_parser", "cmd_publish"]
