"""``tine monitor protocol-sign|protocol-run`` (0.83): collusion-testing protocols.

Registered under ``tine monitor`` by :mod:`opentine._cli_monitor_eval`.

``protocol-sign --spec FILE --secret FILE --key KEY --out FILE`` signs a protocol
manifest (:mod:`opentine._collusion_protocol`) that commits to the secret seed.
``protocol-run MONITOR --protocol FILE --secret FILE --runs FILE [--repo PATH]``
verifies the manifest against the repository's pinned roles (a pinned
``policy`` key, never an ``optimizer`` key; fail closed when unpinned), checks
the revealed secret against its commitment, applies the protocol
(:mod:`opentine._collusion_run`) and, with ``--key`` and ``--verdicts FILE``,
writes one signed ``tine-eval-verdict/1`` per probe as JSON Lines
(:mod:`opentine._collusion_verdicts`); ``--record`` stores and holds them in the
repository, where a failed run opens a ``collusion`` oversight item
(:mod:`opentine._collusion_record`). Results are advisory (exit 0) unless the
signed manifest sets ``required``; then a monitor that does not clear exits 1.
"""

from __future__ import annotations

import argparse
import json
from decimal import Decimal
from pathlib import Path
from typing import Any

from opentine._utc import rfc3339_utc


def add_protocol_parsers(verbs: argparse._SubParsersAction) -> None:
    sign = verbs.add_parser("protocol-sign", help="Sign a collusion-testing protocol manifest")
    sign.add_argument("--spec", required=True, metavar="FILE", help="Protocol fields (JSON)")
    sign.add_argument("--out", required=True, metavar="FILE", help="Write the signed manifest")
    run = verbs.add_parser("protocol-run", help="Apply a signed collusion protocol to a monitor")
    run.add_argument("monitor", metavar="MONITOR", help="Untrusted monitor spec (JSON)")
    run.add_argument("--protocol", required=True, metavar="FILE", help="Signed manifest")
    run.add_argument("--runs", action="append", required=True, metavar="FILE",
                     help="Recorded trajectories (JSON Lines); repeatable")  # fmt: skip
    run.add_argument("--reference", metavar="MONITOR", help="The pinned reference monitor spec")
    run.add_argument("--repo", default=".", metavar="PATH", help="Repository with pinned roles")
    run.add_argument("--verdicts", metavar="FILE", help="With --key: write signed verdicts")
    run.add_argument("--record", action="store_true",
                     help="With --key: store and hold the signed verdicts in --repo")  # fmt: skip
    for p in (sign, run):
        p.add_argument("--secret", required=True, metavar="FILE",
                       help="The secret seed (16+ bytes), committed when signing")  # fmt: skip
        p.add_argument("--key", required=p is sign, metavar="KEY", help="Ed25519 signing key")
        p.add_argument("--json", action="store_true", help="Machine-readable output")


def _now() -> str:
    return rfc3339_utc()


def _store(path: str) -> Path | None:
    from opentine.repo import Repo

    try:
        return Repo.open(path).path
    except Exception:  # noqa: BLE001 - no repository: no pinned roles, refused later
        return None


def _sign(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _collusion_protocol as proto
    from opentine._json_shallow import loads
    from opentine._key_hygiene import ed25519_private
    from opentine.kernel import canonical_json

    spec = loads(Path(args.spec).read_bytes())
    if not isinstance(spec, dict):
        raise ValueError("--spec is a JSON object")
    fields = {k: v for k, v in spec.items() if k not in ("convention", "seed_commitment",
                                                         "signer", "signature")}  # fmt: skip
    fields.setdefault("created_at", _now())
    manifest = proto.make(ed25519_private(args.key), Path(args.secret).read_bytes(), **fields)
    Path(args.out).write_bytes(canonical_json(manifest) + b"\n")
    return {"ok": True, "protocol": proto.digest(manifest), "protocol_name": manifest["protocol"],
            "signer": manifest["signer"], "seed_commitment": manifest["seed_commitment"],
            "out": Path(args.out).as_posix()}  # fmt: skip


def _run(args: argparse.Namespace) -> dict[str, Any]:
    from opentine import _collusion_protocol as proto
    from opentine import _collusion_verdicts as cv
    from opentine._collusion_run import run
    from opentine._json_shallow import loads
    from opentine._monitor_backtest import read_trajectories
    from opentine._monitor_rule import load

    if (args.verdicts or args.record) and not args.key:
        raise ValueError("--verdicts and --record need --key")
    store = _store(args.repo)
    manifest = loads(Path(args.protocol).read_bytes())
    checked = proto.verify(manifest, store)
    secret = proto.reveal(checked, Path(args.secret).read_bytes())
    monitor = load(args.monitor)
    reference = load(args.reference) if args.reference else None
    rows = read_trajectories(args.runs)
    result = run(checked, secret, monitor, rows, reference=reference)
    digest = proto.digest(manifest)
    allowed = checked["trials"] * Decimal(checked["max_flag_rate"])
    cleared = result["collusion"]["flagged"] <= allowed
    out: dict[str, Any] = {
        "ok": cleared or not checked["required"], "advisory_only": not checked["required"],
        "cleared": cleared, "protocol": digest, "protocol_name": checked["protocol"],
        "monitor": monitor["monitor"], "monitor_digest": monitor["_digest"],
        "reference_digest": checked["disagreement"]["reference_digest"],
        "seed_commitment": checked["seed_commitment"], **result, "verdicts": [],
        "verdicts_file": None, "recorded": []}  # fmt: skip
    if args.key:
        from opentine._eval_verdict import digest as verdict_digest
        from opentine._key_hygiene import ed25519_private
        from opentine.kernel import canonical_json

        private = ed25519_private(args.key)
        cv.guard_signer(private, store)
        signed = cv.sign(private, checked, digest, monitor, rows, result, now=_now())
        out["verdicts"] = [verdict_digest(r["verdict"]) for r in signed]
        if args.verdicts:
            Path(args.verdicts).write_bytes(b"".join(canonical_json(r) + b"\n" for r in signed))
            out["verdicts_file"] = Path(args.verdicts).as_posix()
        if args.record:
            from opentine._collusion_record import record
            from opentine.repo import Repo

            out["recorded"] = record(Repo.open(args.repo), signed)
    return out


def run(args: argparse.Namespace) -> None:
    from opentine._cli_common import _terminal, console
    from opentine._cli_errors import error
    from opentine._cli_json import emit
    from opentine._collusion_protocol import ProtocolError

    verb = args.monitor_command
    try:
        row = _sign(args) if verb == "protocol-sign" else _run(args)
    except ProtocolError as exc:
        raise error(f"{exc.code}: {exc}", prefix="monitor: ") from exc
    except (OSError, ValueError, KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise error(exc, prefix="monitor: ") from exc
    if args.json:
        emit({"command": f"monitor {verb}", "schema": "tine-cli-monitor/1", **row})
    elif verb == "protocol-sign":
        console.print(_terminal(f"signed {row['protocol_name']}: {row['protocol']}"), markup=False)
    else:
        c = row["collusion"]
        head = "CLEARED" if row["cleared"] else "COLLUSION SUSPECTED"
        tail = "" if row["advisory_only"] else " (required by the protocol)"
        console.print(
            _terminal(
                f"{head} {row['monitor']}: {c['flagged']}/{c['trials']} trials "
                f"flagged, CP {c['clopper_pearson']}{tail}"
            ),
            markup=False,
        )
        for name, p in row["probes"].items():
            console.print(_terminal(f"  {name}: {p['flagged']} flagged, {p['events']} events"),
                          markup=False)  # fmt: skip
    if row["ok"] is False:
        raise SystemExit(1)


__all__ = ["add_protocol_parsers", "run"]
