"""``tine ingest --batch FILE`` and ``tine ingest policy|verify|serve|packs`` (0.77).

Batched streaming ingest for large episode streams (docs/INGEST.md):

* ``policy``: sign and hold a stream's sampling policy
  (``opentine.ingest-policy/1``, :mod:`opentine._ingest_policy`);
* ``--batch FILE`` (``-`` for stdin): sample, store, sign and chain one batch
  of JSON Lines events (``opentine.ingest-batch/1``, :mod:`opentine._ingest_batch`);
* ``verify``: the chain, counts and policy (:mod:`opentine._ingest_verify`),
  exit 1 on a ``fail:`` finding (``--strict``: on any finding);
* ``serve``: the loopback endpoint ``POST /v1/ingest`` (:mod:`opentine._ingest_http`);
* ``packs``: re-read every pack of a ``tine serve`` pack store
  (``TINE_REMOTE_PACK_STORE``), exit 1 on a bad pack or object.

``--json`` follows ``tine-cli-ingest-1``.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from typing import Any

from opentine._cli_errors import error

SCHEMA = "tine-cli-ingest/1"


def add_ingest_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("ingest", help="Batched streaming ingest with signed sampling")
    parser.add_argument("--batch", metavar="FILE", help="JSON Lines events to ingest (- = stdin)")
    parser.add_argument("--stream", metavar="NAME", help="The ingest stream")
    parser.add_argument("--key", metavar="KEY", help="Ed25519 private key that signs the batch")
    parser.add_argument("--policy", metavar="ID", help="Policy attestation (default: newest)")
    verbs = parser.add_subparsers(dest="ingest_command", required=False)
    policy = verbs.add_parser("policy", help="Sign and hold a stream's sampling policy")
    policy.add_argument("--stream", required=True, metavar="NAME", help="The ingest stream")
    policy.add_argument("--rate", type=float, default=1.0, help="Share captured, in (0, 1]")
    policy.add_argument("--capture", action="append", default=[], metavar="KIND",
                        help="Event kind to capture (repeatable; default: every kind)")  # fmt: skip
    policy.add_argument("--drop", action="append", default=[], metavar="KIND",
                        help="Event kind always dropped (repeatable)")  # fmt: skip
    policy.add_argument("--seed", metavar="HEX", help="64-hex sampling seed (default: random)")
    policy.add_argument("--no-redact", dest="redact", action="store_false",
                        help="Store captured events without the credential scrubber")  # fmt: skip
    policy.add_argument("--key", required=True, metavar="KEY", help="A pinned policy-role key")
    verify = verbs.add_parser("verify", help="Check a stream's chain, counts and policy")
    verify.add_argument("stream", metavar="STREAM", help="The ingest stream")
    verify.add_argument("--strict", action="store_true", help="Advisory findings block too")
    serve = verbs.add_parser("serve", help="Loopback endpoint: POST /v1/ingest")
    serve.add_argument("--stream", required=True, metavar="NAME", help="The ingest stream")
    serve.add_argument("--key", required=True, metavar="KEY", help="Key that signs batches")
    serve.add_argument("--port", type=int, default=4319, help="Port (127.0.0.1)")
    serve.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024, help="Body limit")
    packs = verbs.add_parser("packs", help="Re-read every pack of a tine serve pack store")
    packs.add_argument("--state", default=".tine-remote", help="tine serve --root")
    packs.add_argument("--tenant", action="append", required=True, help="Tenant (repeatable)")
    for row in (parser, policy, verify, serve):
        row.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        row.add_argument("--at", metavar="TIME", help="YYYY-MM-DDTHH:MM:SSZ (default: now)")
    for row in (parser, policy, verify, packs):
        row.add_argument("--json", action="store_true", help="Print a JSON object")


def _now(args: argparse.Namespace) -> int:
    import time
    from datetime import datetime

    if not getattr(args, "at", None):
        return int(time.time() * 1000)
    try:
        return int(datetime.strptime(args.at, "%Y-%m-%dT%H:%M:%S%z").timestamp() * 1000)
    except ValueError:
        raise ValueError(f"--at {args.at!r} is not YYYY-MM-DDTHH:MM:SSZ") from None


def _batch(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str], int]:
    from opentine._ingest_batch import append
    from opentine._key_hygiene import ed25519_private

    if not args.stream or not args.key:
        raise ValueError("--batch needs --stream and --key")
    from pathlib import Path

    data = sys.stdin.buffer.read() if args.batch == "-" else Path(args.batch).read_bytes()
    row = append(repo, args.stream, data, ed25519_private(args.key), at_ms=_now(args),
                 policy_id=args.policy)  # fmt: skip
    line = (f"batch {row['seq']} of {row['stream']}: {row['captured']} captured, "
            f"{row['dropped']} dropped ({row['id']})")  # fmt: skip
    return {"batch": row}, [line], 0


def _policy(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str], int]:
    from opentine import _ingest_policy
    from opentine._budget_ledger import rfc3339
    from opentine._key_hygiene import ed25519_private

    doc = _ingest_policy.build(args.stream, capture=args.capture, drop=args.drop,
                               rate=args.rate, seed=args.seed, redact=args.redact,
                               issued_at=rfc3339(_now(args)))  # fmt: skip
    oid = _ingest_policy.record(repo, doc, ed25519_private(args.key))
    out = {"policy": {"id": oid, "digest": _ingest_policy.digest(doc), **doc}}
    return out, [f"policy {oid} for {doc['stream']} ({out['policy']['digest']})"], 0


def _verify(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str], int]:
    from opentine._ingest_verify import verify

    report = verify(repo, args.stream)
    blocking = [f for f in report["findings"] if args.strict or f["level"] == "fail"]
    lines = [f"{f['level']}: {f['code']} {f['batch'] or ''} {f['message']}".replace("  ", " ")
             for f in report["findings"]]  # fmt: skip
    lines.append(f"{report['stream']}: {report['batches']} batches, {report['received']} "
                 f"received, {report['captured']} captured, {report['dropped']} dropped: "
                 f"{'ok' if not blocking else 'FAILED'}")  # fmt: skip
    return {"report": report}, lines, 1 if blocking else 0


def _packs(args: argparse.Namespace) -> tuple[dict[str, Any], list[str], int]:
    from pathlib import Path

    from opentine.remote import _worm_config
    from opentine.remote.security import LocalKeyProvider

    store = _worm_config.packed_store_from_env(Path(args.state).resolve(),
                                               LocalKeyProvider.from_env(),
                                               _env())  # fmt: skip
    rows = [store.fsck(tenant) for tenant in args.tenant]
    lines = [f"{r['tenant']}\t{r['packs']} packs\t{r['objects']} objects\t{len(r['bad'])} bad"
             for r in rows]  # fmt: skip
    lines.extend(bad for r in rows for bad in r["bad"])
    return {"packs": rows}, lines, 1 if any(r["bad"] for r in rows) else 0


def _env() -> dict[str, str]:
    import os

    from opentine.remote._worm_config import PACK_ENV

    if not (os.environ.get(PACK_ENV) or "").strip():
        raise ValueError(f"{PACK_ENV} is not set: there is no pack store to read")
    return dict(os.environ)


def _serve(args: argparse.Namespace, repo: Any) -> None:
    from opentine import _ingest_http
    from opentine._key_hygiene import ed25519_private

    server = _ingest_http.start(repo, args.stream, ed25519_private(args.key), port=args.port,
                                max_bytes=args.max_bytes)  # fmt: skip
    print(f"ingest: http://127.0.0.1:{server.server_address[1]}{_ingest_http.ROUTE}", flush=True)
    import threading

    try:
        threading.Event().wait()  # the server runs on its own thread until interrupted
    except KeyboardInterrupt:
        server.stop()


def cmd_ingest(args: argparse.Namespace) -> None:
    from opentine._cli_common import _terminal, console
    from opentine._cli_json import emit
    from opentine._ingest_policy import IngestError

    verb = args.ingest_command
    try:
        if verb == "packs":
            out, lines, code = _packs(args)
        else:
            from opentine.repo import Repo

            repo = Repo.open(args.repo)
            if verb == "serve":
                _serve(args, repo)
                return
            if verb is None and not args.batch:
                raise ValueError("give --batch FILE or one of policy, verify, serve, packs")
            handler = {None: _batch, "policy": _policy, "verify": _verify}[verb]
            out, lines, code = handler(args, repo)
    except (OSError, ValueError, KeyError, IngestError) as exc:
        raise error(exc, prefix="ingest: ") from exc
    if args.json:
        emit({"command": "ingest" + (f" {verb}" if verb else " --batch"), "schema": SCHEMA, **out})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if code:
        raise SystemExit(code)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"ingest": cmd_ingest}

__all__ = ["COMMANDS", "SCHEMA", "add_ingest_parser", "cmd_ingest"]
