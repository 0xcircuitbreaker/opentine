"""``tine agent id | show | trust | keys``: opentine-agent/1 identities.

* ``id`` computes the ``agt_`` ref an agent would record (harness, model,
  definition files -- hashed, never stored -- and an optional signing key).
* ``show RUN`` prints a run's identity record, its trust state, and whether
  its parent link is verified from both sides; ``show agt_...`` lists the runs
  that claim that ref, each with its own trust state.
* ``trust`` trusts the repository's ``.tine/agents.toml`` as it is now.
* ``keys`` lists this user's agent keys (``tine keygen --agent NAME``).

Every recorded string is untrusted and reaches the terminal through
``_terminal``; a name that is not plain ASCII is flagged as a possible look-alike.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opentine import _agent_identity as identity
from opentine import _cli_who_trust as who_trust
from opentine._agent_definition import DefinitionError, definition_digest, harness_files
from opentine._agent_keys import key_dir, key_paths, local_fingerprints, trust
from opentine._cli_common import _terminal, console
from opentine._signing_pins import key_fingerprint, normalize_pin


def _fail(message: str) -> None:
    console.print(f"[red]{_terminal(message)}[/]")
    raise SystemExit(2)


def _out(args: argparse.Namespace, payload: dict[str, Any], lines: list[str]) -> None:
    if getattr(args, "json", False):
        from opentine._cli_json import emit

        emit({"command": "agent", **payload})
        return
    for line in lines:
        console.print(line)


def _name(value: str) -> str:
    flag = " [yellow](!look-alike)[/]" if identity.lookalike(value) else ""
    return _terminal(value or "-") + flag


def _key_fpr(args: argparse.Namespace) -> str:
    if args.agent:
        raw = key_paths(args.agent)[1].read_text(encoding="ascii").strip()
        return key_fingerprint(bytes.fromhex(raw))
    return normalize_pin(args.key_fpr) if args.key_fpr else ""


def _id(args: argparse.Namespace) -> None:
    try:
        files = args.definition or harness_files(args.harness, args.root)
        record = identity.build(
            harness=args.harness,
            model=args.model or "",
            provider=args.provider or "",
            definition_digest=definition_digest(files, args.root),
            key_fpr=_key_fpr(args),
        )
    except (DefinitionError, OSError, ValueError) as exc:
        _fail(str(exc))
        return
    ref = identity.agent_ref(record)
    lines = [ref, f"harness {_name(record['harness'])}  model {_name(record['model'])}"]
    lines += [f"definition {record['definition_digest'] or '-'} ({len(files)} file(s))"]
    _out(args, {"agent_ref": ref, "identity": record, "files": files}, lines)


def _show_ref(args: argparse.Namespace, ref: str) -> None:
    from opentine._cli_who import _open

    index, _report = _open(args)
    with index:
        resolver = who_trust.resolver(args, index)
        runs = sorted({run for run, held, _ in index.edges() if identity.same_ref(held, ref)})
        rows = [
            {"run_id": run, "trust": resolver.trust(run).state}
            for run in runs
            if resolver.ref_holds(run, ref)
        ]
    lines = [f"{_terminal(ref)}: {len(rows)} run(s)"]
    lines += [f"  {_terminal(row['run_id'][:64])}  {row['trust']}" for row in rows]
    _out(args, {"agent_ref": ref, "runs": rows}, lines)


def _load_target(args: argparse.Namespace) -> Any:
    """The operator's own argument may be a path, unlike an id read from a run."""
    from opentine._cli_who import _load_run

    args.run_id = args.target
    try:
        return _load_run(args)
    except (KeyError, OSError, SystemExit, ValueError):
        return None


def _show(args: argparse.Namespace) -> None:
    target = args.target
    if target.startswith(("agt_", identity.LEGACY_PREFIX)):
        try:
            _show_ref(args, identity.check_query_ref(target))
        except identity.IdentityError as exc:
            _fail(str(exc))
        return
    resolver = who_trust.resolver(args)
    run = resolver.run(target) or _load_target(args)
    if run is None:
        _fail(f"Run not found: {target}")
        return
    resolver.adopt(run)
    record, verdict = identity.run_identity(run), resolver.trust(run.id)
    ref = identity.run_agent_ref(run)
    lineage = bool(record and record["parent"]) and resolver.lineage_ok(run.id)
    lines = [f"{_terminal(ref)}  trust: {verdict.state} ({_terminal(verdict.reason)})"]
    for key, value in (record or {}).items():
        if key != "scheme" and value:
            lines.append(f"  {key}: {_name(value)}")
    if record and record["parent"]:
        lines.append(f"  lineage: {'verified' if lineage else 'claimed (unverified)'}")
    payload = {"run_id": run.id, "agent_ref": ref, "identity": record}
    payload |= {"trust": verdict.state, "reason": verdict.reason, "lineage_verified": lineage}
    _out(args, payload, lines)


def _trust(args: argparse.Namespace) -> None:
    _, _, agents = who_trust.scope_paths(args)
    try:
        digest = trust(agents if agents is not None else Path(".tine"))
    except (OSError, ValueError) as exc:
        _fail(str(exc))
        return
    console.print(f"Trusted agents.toml ({digest[:16]}).")


def _keys(args: argparse.Namespace) -> None:
    pins = sorted(local_fingerprints())
    _out(args, {"keys": pins, "dir": str(key_dir())}, pins or ["No agent keys."])


def cmd_agent(args: argparse.Namespace) -> None:
    handler = {"id": _id, "show": _show, "trust": _trust, "keys": _keys}.get(args.agent_command)
    if handler is None:
        _fail("usage: tine agent {id,show,trust,keys}")
        return
    handler(args)


def add_agent_parser(sub: Any) -> None:
    agent = sub.add_parser("agent", help="Agent identities: refs, lineage, signing keys")
    verbs = agent.add_subparsers(dest="agent_command")
    ident = verbs.add_parser("id", help="Compute an agent's agt_ ref")
    ident.add_argument("--harness", required=True)
    ident.add_argument("--model")
    ident.add_argument("--provider")
    ident.add_argument("--definition", action="append", metavar="PATH", help="Definition file")
    ident.add_argument("--root", default=".", help="Directory definition paths are under")
    ident.add_argument("--agent", metavar="NAME", help="Bind the key from keygen --agent NAME")
    ident.add_argument("--key-fpr", metavar="FINGERPRINT", help="Bind this signing key")
    show = verbs.add_parser("show", help="A run's identity and trust, or a ref's runs")
    show.add_argument("target", help="Run id, agt_ ref or legacy:LABEL")
    who_trust.add_trust_args(show, filters=False)
    verbs.add_parser("trust", help="Trust .tine/agents.toml as it is now")
    verbs.add_parser("keys", help="List this user's agent signing keys")
    for parser in verbs.choices.values():
        if not any(a.dest == "json" for a in parser._actions):
            parser.add_argument("--json", action="store_true", help="Emit JSON")
        if not any(a.dest == "repo" for a in parser._actions):
            parser.add_argument("--repo", metavar="PATH", help="Read a v3 repository instead")


__all__ = ["add_agent_parser", "cmd_agent"]
