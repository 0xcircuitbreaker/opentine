"""``tine interp store|list|export|calibrate|check|score`` (0.83): interpretability custody.

``store FILE --kind K --checkpoint D [--layer N] --key KEY`` stores an attribution
graph, SAE feature dashboard or probe weights as a held blob keyed to a
checkpoint digest (:mod:`opentine._interp_custody`); ``list`` shows the records
and their verification; ``export DIGEST --out PATH [--run RUN]`` writes the bytes
under model-organism custody (a tagged artifact needs an approval bound to the
run; exit 6 on ``custody.denied``). ``calibrate PROBE --threshold T --samples F
--key KEY`` signs calibration evidence; ``check CONFIG`` compares a probe monitor
configuration with its calibration (exit 1 on a finding); ``score CONFIG
--request F`` scores one activation request (exit 4 on ``digest.mismatch``).
See docs/INTERPRETABILITY.md.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console
from opentine._cli_errors import TRUST_REQUIRED, VERIFICATION_FAILED, error

SCHEMA = "tine-cli-interp/1"
MAX_INPUT = 64 * 1024 * 1024


def add_interp_parser(subparsers: argparse._SubParsersAction) -> None:
    from opentine._interp_custody import KINDS, TAGS

    parser = subparsers.add_parser("interp", help="Interpretability artifact custody and probes")
    verbs = parser.add_subparsers(dest="interp_command", required=True)
    store = verbs.add_parser("store", help="Store and sign an interpretability artifact")
    store.add_argument("file", metavar="FILE", help="The artifact bytes")
    store.add_argument("--kind", required=True, choices=KINDS, help="What the artifact is")
    store.add_argument(
        "--checkpoint",
        required=True,
        metavar="DIGEST",
        help="The sha256: digest of the checkpoint it was computed from",
    )
    store.add_argument("--layer", type=int, metavar="N", help="The layer (probe weights)")
    store.add_argument("--name", metavar="NAME", help="A display name")
    store.add_argument("--tag", action="append", default=[], choices=TAGS, help="A custody tag")
    lst = verbs.add_parser("list", help="Interpretability artifacts and their verification")
    lst.add_argument("--checkpoint", metavar="DIGEST", help="Only this checkpoint's artifacts")
    export = verbs.add_parser("export", help="Write an artifact's bytes (custody applies)")
    export.add_argument("artifact", metavar="DIGEST", help="The artifact's sha256: digest")
    export.add_argument("--out", required=True, metavar="PATH", help="Where to write the bytes")
    export.add_argument("--requester-key", metavar="KEY",
                        help="0.91: the requester's key, named by custodian approvals")  # fmt: skip
    cal = verbs.add_parser("calibrate", help="Sign calibration evidence for a probe")
    cal.add_argument("artifact", metavar="DIGEST", help="The probe weights' sha256: digest")
    cal.add_argument("--threshold", required=True, type=float, help="The decision threshold")
    cal.add_argument(
        "--samples",
        required=True,
        metavar="FILE",
        help='JSON list of {"activations": [...], "label": true|false}',
    )
    for verb in (export, cal):
        verb.add_argument("--run", metavar="RUN", help="The run reading it (approval binding)")
    for verb in (store, cal):
        verb.add_argument("--key", required=True, metavar="KEY", help="Ed25519 private key")
    check = verbs.add_parser("check", help="Compare a probe monitor with its calibration")
    score = verbs.add_parser("score", help="Score one activation request with a probe monitor")
    score.add_argument(
        "--request",
        required=True,
        metavar="FILE",
        help='JSON {"checkpoint_digest": D, "activations": [...]}',
    )
    for verb in (check, score):
        verb.add_argument("config", metavar="CONFIG", help="Monitor configuration (TOML)")
    for verb in (store, lst, export, cal, check, score):
        verb.add_argument("--repo", default=".", metavar="PATH", help="Repository")
        verb.add_argument("--json", action="store_true", help="Print a JSON object")


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        data = handle.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ValueError(f"{path} is larger than {MAX_INPUT} bytes")
    return data


def _key(path: str) -> Any:
    from opentine._key_hygiene import ed25519_private

    return ed25519_private(path)


def _store(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _interp_custody as ic

    out = ic.store(repo, _read(args.file), kind=args.kind, checkpoint=args.checkpoint,
                   key=_key(args.key), layer=args.layer, name=args.name, tags=args.tag)  # fmt: skip
    claim = out["claim"]
    body = {"record": out["record"], "digest": claim["digest"], "blob": claim["blob"],
            "kind": claim["kind"], "checkpoint": claim["checkpoint"]}  # fmt: skip
    return body, [f"{claim['kind']} {claim['digest']} ({out['record']})"]


def _list(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _interp_custody as ic

    rows = [{**r, "custody": ic.tagged(repo, r)} for r in ic.artifacts(repo, args.checkpoint)]
    lines = [f"{r['kind']} {r['digest']} checkpoint {r['checkpoint']} {r['verification']}"
             + (" [custody]" if r["custody"] else "") for r in rows]  # fmt: skip
    return {"artifacts": rows}, lines or ["no interpretability artifacts"]


def _export(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _interp_custody as ic

    requester = None
    if args.requester_key:
        from opentine._containment_records import fingerprint
        from opentine._key_hygiene import ed25519_private

        requester = fingerprint(ed25519_private(args.requester_key))
    data, row = ic.export(repo, args.artifact, run=args.run, requester=requester)
    Path(args.out).write_bytes(data)
    return {"digest": row["digest"], "size": len(data), "out": Path(args.out).as_posix()}, [
        f"wrote {len(data)} bytes of {row['digest']} to {args.out}"
    ]


def _calibrate(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _json_shallow
    from opentine import _probe_monitor as pm

    samples = _json_shallow.loads(_read(args.samples))
    out = pm.calibrate(repo, args.artifact, _key(args.key), threshold=args.threshold,
                       samples=samples, run=args.run)  # fmt: skip
    claim = {k: v for k, v in out["claim"].items() if k != "convention"}
    return {"record": out["record"], **claim}, [
        f"calibrated {args.artifact}: tpr {claim['tpr']} fpr {claim['fpr']} ({out['record']})"
    ]


def _monitor(args: argparse.Namespace) -> Any:
    from opentine._monitors import load

    monitor = load(args.config)["monitor"]
    if monitor.identity.get("kind") != "probe":
        raise ValueError("the configuration's monitor is not of kind probe")
    return monitor


def _check(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _probe_monitor as pm

    identity = _monitor(args).identity
    findings = pm.check(repo, identity)
    lines = [f"{f['code']}: {f['message']}" for f in findings]
    return {"ok": not findings, "monitor": identity, "findings": findings}, lines or [
        f"{identity['id']}: probe matches its calibration"
    ]


def _score(args: argparse.Namespace, repo: Any) -> tuple[dict[str, Any], list[str]]:
    from opentine import _json_shallow

    monitor = _monitor(args)
    monitor.bind(repo)
    request = _json_shallow.loads(_read(args.request))
    if not isinstance(request, dict):
        raise ValueError("the request is a JSON object")
    score = monitor.score(request)["score"]
    over = score >= monitor.threshold
    body = {"score": score, "threshold": monitor.threshold, "over": over,
            "monitor": monitor.identity}  # fmt: skip
    return body, [f"score {score:.6f} ({'over' if over else 'under'} {monitor.threshold})"]


HANDLERS = {"store": _store, "list": _list, "export": _export, "calibrate": _calibrate,
            "check": _check, "score": _score}  # fmt: skip


def cmd_interp(args: argparse.Namespace) -> None:
    from opentine import _interp_custody as ic
    from opentine._cli_json import emit
    from opentine._monitors import MonitorError
    from opentine.repo import Repo

    verb = args.interp_command
    try:
        body, lines = HANDLERS[verb](args, Repo.open(args.repo))
    except ic.CustodyDenied as exc:
        raise error(exc, TRUST_REQUIRED, prefix=f"interp {verb}: ",
                    extra={"reason": "custody.denied"}) from exc  # fmt: skip
    except (ic.DigestMismatch, MonitorError, ValueError) as exc:
        code = getattr(exc, "code", None) or getattr(exc.__cause__, "code", None)
        if code == ic.MISMATCH:
            raise error(exc, VERIFICATION_FAILED, prefix=f"interp {verb}: ",
                        extra={"reason": ic.MISMATCH}) from exc  # fmt: skip
        raise error(exc, prefix=f"interp {verb}: ") from exc
    except (OSError, KeyError) as exc:
        raise error(exc, prefix=f"interp {verb}: ") from exc
    if args.json:
        emit({"command": f"interp {verb}", "schema": SCHEMA, **body})
    else:
        for line in lines:
            console.print(_terminal(line), markup=False)
    if verb == "check" and not body["ok"]:
        raise SystemExit(1)


COMMANDS: dict[str, Callable[[argparse.Namespace], None]] = {"interp": cmd_interp}

__all__ = ["COMMANDS", "SCHEMA", "add_interp_parser", "cmd_interp"]
