"""``tine trust policy set|list|show|rm|default``: manage named trust policies.

The store and its safety rules are in :mod:`opentine._trust_policy`; this module
is the CLI. ``policy`` is a real subcommand of the ``trust`` group (not an argv
rewrite to an older verb), wired by ``_cli_groups.add_group_parsers``.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from opentine._cli_common import _terminal, console
from opentine._trust_policy import FIELDS, PolicyError, check_name, check_policy, load, save

__all__ = ["add_policy_parser", "cmd_trust_policy"]


def add_policy_parser(group_sub: argparse._SubParsersAction) -> None:
    text = "Named trust policies for `tine verify --policy NAME`"
    policy = group_sub.add_parser("policy", help=text, description=text)
    policy.set_defaults(group_handler=cmd_trust_policy)
    sub = policy.add_subparsers(dest="policy_command", metavar="SUBCOMMAND")
    put = sub.add_parser("set", help="Define (replace) a policy")
    put.add_argument("name")
    put.add_argument("--pubkey", metavar="FILE", help="Trusted Ed25519 public key")
    put.add_argument("--pin", action="append", metavar="SHA256", help="Pinned key fingerprint")
    put.add_argument("--rekor-key", metavar="FILE", help="Rekor log key (PEM)")
    put.add_argument("--require-receipt", action="store_true", help="Demand a Rekor receipt")
    put.add_argument("--cert-identity", metavar="SAN", help="Keyless: expected signer identity")
    put.add_argument("--cert-oidc-issuer", metavar="URL", help="Keyless: expected OIDC issuer")
    put.add_argument("--fulcio-root", metavar="FILE", help="Keyless: Fulcio root/intermediates")
    for verb, help_text in (("list", "List policies"), ("show", "Show one policy")):
        child = sub.add_parser(verb, help=help_text)
        if verb == "show":
            child.add_argument("name")
        child.add_argument("--json", action="store_true", help="Emit a JSON object instead")
    sub.add_parser("rm", help="Delete a policy").add_argument("name")
    default = sub.add_parser("default", help="Show, set or --clear the default policy")
    default.add_argument("name", nargs="?")
    default.add_argument("--clear", action="store_true", help="Apply no policy by default")


def _fail(message: str) -> None:
    console.print(f"[red]trust policy: {_terminal(message)}[/]")
    raise SystemExit(1)


def _absolute_file(path: str, flag: str, reader) -> str:
    from opentine._signing_keys import SignatureError

    target = Path(path).expanduser().resolve()
    try:
        reader(target)
    except (OSError, ValueError, SignatureError) as exc:
        _fail(f"{flag} {path}: {exc}")
    return str(target)


def _policy_from(args: argparse.Namespace) -> dict:
    from opentine._fulcio_verify import load_roots
    from opentine._rekor_proof import load_log_key
    from opentine._signing_keys import ed25519_public_from_file

    def pem(load):
        return lambda path: load(path.read_bytes()[: 1 << 20])

    policy: dict = {}
    if args.pubkey:
        policy["pubkey"] = _absolute_file(args.pubkey, "--pubkey", ed25519_public_from_file)
    if args.pin:
        from opentine._signing_pins import normalize_pins

        policy["pin"] = sorted(normalize_pins(args.pin))
    if args.rekor_key:
        policy["rekor_key"] = _absolute_file(args.rekor_key, "--rekor-key", pem(load_log_key))
    if args.require_receipt:
        policy["require_receipt"] = True
    for field in ("cert_identity", "cert_oidc_issuer"):
        if getattr(args, field):
            policy[field] = getattr(args, field)
    if args.fulcio_root:
        policy["fulcio_root"] = _absolute_file(args.fulcio_root, "--fulcio-root", pem(load_roots))
    keyless = [f for f in ("cert_identity", "cert_oidc_issuer", "fulcio_root") if f in policy]
    if keyless and (len(keyless) < 3 or "rekor_key" not in policy):
        _fail("a keyless policy needs --cert-identity, --cert-oidc-issuer, --fulcio-root "
              "and --rekor-key")  # fmt: skip
    if not ({"pubkey", "pin"} & set(policy) or keyless):
        _fail("a policy needs a trust root: --pubkey, --pin, or the keyless flags")
    return policy


def _emit(payload: dict) -> None:
    from opentine._cli_json import emit

    emit({"command": "trust policy", **payload})


def cmd_trust_policy(args: argparse.Namespace) -> None:
    verb = getattr(args, "policy_command", None)
    if verb is None:
        from opentine._cli_groups import cmd_group

        return cmd_group(args)
    try:
        table = load()
        name = check_name(args.name) if getattr(args, "name", None) else None
        if verb == "set":
            table["policies"][name] = check_policy(name, _policy_from(args))
            save(table)
            console.print(f"policy {_terminal(name)} saved", highlight=False)
        elif verb == "list":
            _list(args, table)
        elif verb == "show":
            if name not in table["policies"]:
                _fail(f"unknown policy {name!r}")
            policy = table["policies"][name]
            if args.json:
                _emit({"name": name, "default": table["default"] == name, "policy": policy})
                return
            for field in FIELDS:
                if field in policy:
                    console.print(f"{field}={_terminal(policy[field])}", highlight=False)
        elif verb == "rm":
            if table["policies"].pop(name, None) is None:
                _fail(f"unknown policy {name!r}")
            table["default"] = None if table["default"] == name else table["default"]
            save(table)
            console.print(f"policy {_terminal(name)} removed", highlight=False)
        else:
            _default(args, table, name)
    except (OSError, PolicyError) as exc:
        _fail(str(exc))


def _list(args: argparse.Namespace, table: dict) -> None:
    if args.json:
        _emit({"default": table["default"], "policies": table["policies"]})
        return
    for name in sorted(table["policies"]):
        mark = " (default)" if name == table["default"] else ""
        console.print(f"{_terminal(name)}{mark}", highlight=False)


def _default(args: argparse.Namespace, table: dict, name: str | None) -> None:
    if args.clear and name:
        _fail("give a policy name or --clear, not both")
    if not args.clear and not name:
        if table["default"]:
            console.print(_terminal(table["default"]), highlight=False)
        return
    if name and name not in table["policies"]:
        _fail(f"unknown policy {name!r}")
    table["default"] = name
    save(table)
    console.print(f"default policy: {_terminal(name or '(none)')}", highlight=False)
