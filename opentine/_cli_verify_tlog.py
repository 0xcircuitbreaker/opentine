"""``tine verify TARGET --offline --witnesses N-of-M --witness-vkey V... [--log-vkey V...]``.

0.49: ``--witnesses REGISTRY.json`` instead takes the quorum, the witness keys
and the log key from an ``opentine-witness-network/1`` registry
(``_witness_network``), which must meet the network policy (a majority of
three or more independent witnesses, e.g. 2-of-3) before anything is checked.

TARGET is one of (0.44, X33):

* a bundle (``TINEBUNDLE1``): its integrity, then every embedded transparency
  receipt (``_transparency.check``), each checkpoint cosigned by a quorum;
* an ``opentine-tlog-receipt/1`` JSON file (a stored push receipt);
* a bare signed-note checkpoint, which needs ``--log-vkey`` to be meaningful.

Exactly M distinct ``--witness-vkey`` keys must be pinned and at least N must
have cosigned. A split view -- one log showing two checkpoints that cannot both
be honest -- cannot gather N cosignatures from honest witnesses, so it fails
here (exit 4). Everything runs inside the offline guard: nothing is fetched.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def add_tlog_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--witnesses",
        metavar="N-of-M|REGISTRY",
        help="--offline: require N of the M pinned witnesses (or a witness-network registry)",
    )
    parser.add_argument(
        "--witness-vkey", action="append", metavar="VKEY", help="--witnesses: a pinned witness key"
    )
    parser.add_argument(
        "--log-vkey", action="append", metavar="VKEY", help="--witnesses: pin a log's key by origin"
    )


def _check(target: Path, args: argparse.Namespace, quorum: tuple[int, int]) -> dict[str, Any]:
    from opentine import _bundle, _transparency
    from opentine.repository import _tlog_cosign, _tlog_note, _tlog_receipt

    data = target.read_bytes()[: _bundle.MAX_BUNDLE_BYTES + 1]
    witnesses, vkeys = list(args.witness_vkey or ()), list(args.log_vkey or ())
    if data.startswith(_bundle.MAGIC):
        checked = _bundle.verify(data)
        if not checked.transparency:
            raise ValueError("bundle carries no transparency receipts (create --transparency)")
        result = _transparency.check(
            checked.transparency, checked.refs, vkeys=vkeys, witnesses=witnesses, quorum=quorum
        )
        return {**result, "kind": "bundle"}
    if data.lstrip().startswith(b"{"):
        receipt = json.loads(data)
        origin = str(receipt.get("checkpoint", "")).split("\n", 1)[0]
        pinned = {_tlog_note.parse_vkey(v)[0]: v for v in vkeys}
        result = _tlog_receipt.verify(
            receipt, vkey=pinned.get(origin), witnesses=witnesses, quorum=quorum
        )
        return {**result, "kind": "receipt"}
    if len(vkeys) != 1:
        raise ValueError("a bare checkpoint needs exactly one --log-vkey")
    origin, size, _ = _tlog_note.open_checkpoint(data, vkeys[0])
    cosigned = _tlog_cosign.check_quorum(data, witnesses, *quorum)
    return {"cosigned_by": sorted(cosigned), "kind": "checkpoint", "ok": True, "origin": origin,
            "size": size}  # fmt: skip


def _check_registry(target: Path, args: argparse.Namespace) -> dict[str, Any]:
    """Verify against a witness-network registry: its log key, its quorum, any key per witness."""
    from opentine import _bundle, _transparency, _witness_network
    from opentine.repository import _tlog_receipt

    doc = _witness_network.load(Path(args.witnesses))
    log = doc["log"]["vkey"]
    data = target.read_bytes()[: _bundle.MAX_BUNDLE_BYTES + 1]
    if data.startswith(_bundle.MAGIC):
        checked = _bundle.verify(data)
        if not checked.transparency:
            raise ValueError("bundle carries no transparency receipts (create --transparency)")
        result = {**_transparency.check(checked.transparency, checked.refs, vkeys=[log]),
                  "kind": "bundle"}  # fmt: skip
        notes = [str(r["checkpoint"]).encode() for r in checked.transparency]
    elif data.lstrip().startswith(b"{"):
        receipt = json.loads(data)
        result = {**_tlog_receipt.verify(receipt, vkey=log), "kind": "receipt"}
        notes = [str(receipt["checkpoint"]).encode()]
    else:
        from opentine.repository._tlog_note import open_checkpoint

        origin, size, _ = open_checkpoint(data, log)
        result = {"kind": "checkpoint", "ok": True, "origin": origin, "size": size}
        notes = [data]
    for item, note in zip(result.get("receipts", [result]), notes, strict=True):
        if item["origin"] != doc["log"]["origin"]:
            raise ValueError(f"checkpoint origin {item['origin']!r} is not the registry's log")
        item["cosigned_by"] = sorted(_witness_network.check(note, doc))
    need, total = _witness_network.quorum(doc)
    return {**result, "registry": {"log": doc["log"]["origin"], "quorum": f"{need}-of-{total}"}}


def cmd_verify_tlog(args: argparse.Namespace) -> None:
    from opentine._cli_common import BRAND, _terminal, console
    from opentine._cli_errors import USAGE, VERIFICATION_FAILED, fail
    from opentine._offline_guard import no_network
    from opentine._witness_network import looks_like_quorum
    from opentine.repository._tlog_cosign import parse_quorum

    registry = not looks_like_quorum(args.witnesses)
    try:
        quorum = (0, 0) if registry else parse_quorum(args.witnesses)
        if registry and (args.witness_vkey or args.log_vkey):
            raise ValueError("--witnesses REGISTRY takes its keys from the registry, not flags")
    except ValueError as exc:
        fail(exc, USAGE, cause=exc)
    try:
        with no_network():
            target = Path(args.run_id)
            result = _check_registry(target, args) if registry else _check(target, args, quorum)
    except (OSError, ValueError) as exc:
        fail(exc, VERIFICATION_FAILED, prefix="tine verify: ", cause=exc)
    result["witnesses"] = args.witnesses
    if getattr(args, "json", False):
        print(json.dumps(result, sort_keys=True))
        return
    console.print(f"[{BRAND}]# Verified[/] {result['kind']} with {args.witnesses} witnesses")
    for item in result.get("receipts", [result]):
        names = ", ".join(_terminal(n) for n in item.get("cosigned_by", ()))
        console.print(f"  {_terminal(item['origin'])} size {item['size']}: cosigned by {names}")
