"""The three v3 operator write verbs: ``attest``, ``evaluate``, and ``promote``.

These are the mutating half of the repository surface — the half MCP deliberately
withholds (``promote_run`` is registered only under ``allow_promotion=True``).
Nothing here re-implements an engine: each verb resolves its argument and then
makes exactly one call, ``Repo.attest`` or ``Repo.promote``, so a CLI-written
object is byte-identical to the object the corresponding MCP tool writes.

Three rules hold across all three verbs.

**Resolve first.** ``Repo.attest`` passes ``target_id`` straight into
``Repo.put``, whose kernel link check requires an object that already exists, and
``Repo.promote`` passes its run argument into ``update_ref``, which rejects a ref
name. Both therefore need an oid, not a ref, so every verb runs
``ops.resolve_target`` before touching the engine. That is what makes
``tine attest heads/main`` attest the run ``heads/main`` points at.

**One evaluation claim shape.** ``evaluate`` is ``attest`` with the claim fixed to
``{"kind": "evaluation", "scores": {...}}`` and ``signer`` taken from
``--evaluator`` — exactly the claim the MCP ``evaluate_run`` tool builds. The
score scan in ``repository/search.py`` and the reverse lookup in
``repository/_associations.py`` both read that shape back, so a second shape
would be scores no reader can see. ``attest`` refuses a claim that is not a JSON
object for the same reason: ``_associations.evaluations`` raises on one.

**Signing is opt-in, and unsigned says so.** Given a key
(``--key-env`` / ``--key-file`` / ``--ed25519-key-file``, plus an optional
``--key-id``, exactly as ``tine sign``) both attesting verbs bind the signer
label to that key at ``tine-attest/1``, and ``tine repo-verify`` checks it.
Given no key they write the byte-identical unsigned object every release since
0.3.0 wrote, and the receipt keeps saying ``unsigned``: the label is then
self-asserted, and claiming otherwise would be the exact lie signing exists to
remove. MCP's ``attest_run`` deliberately has no key options — a model acting on
run content it just read must not be able to sign as an operator.

And ``promote`` has no override flag: a promotion ref is a release gate, so
``expected_old=None`` means *expect no existing ref* and moving a promotion
always requires the operator to name the value being replaced with
``--expected-old``.
"""

from __future__ import annotations

import argparse
from typing import Any

from opentine._cli_common import _terminal
from opentine._cli_json import emit
from opentine._repo_cli_claim import parse_claim, parse_scores
from opentine._repo_cli_keys import signing_key
from opentine._repo_cli_render import _short_oid
from opentine.kernel import KernelError, parse_oid
from opentine.repo import Repo
from opentine.repository.ops import resolve_target


def _run_oid(repo: Repo, value: str) -> str:
    """Resolve *value* to a run oid that exists, or refuse by name.

    Both engines below would refuse a missing target on their own, but with a
    kernel-level message about links or ref types. The operator typed a ref, so
    the refusal names the ref.
    """
    try:
        oid = resolve_target(repo, value)
    except KeyError:
        raise KeyError(f"cannot resolve {value}: no such ref or object in {repo.path}") from None
    if parse_oid(oid)[0] != "run":
        raise ValueError(f"{value} resolves to {oid}, which is not a run object")
    if not repo.has(oid):
        raise KeyError(f"cannot resolve {value}: no such ref or object in {repo.path}")
    return oid


def _attest(
    repo: Repo, args: argparse.Namespace, target: str, claim: dict[str, Any], signer: str
) -> tuple[str, str, dict[str, Any] | None]:
    """Resolve, sign if a key was given, then make the one shared ``Repo.attest`` call."""
    run_id = _run_oid(repo, target)
    key, algorithm = signing_key(args)
    attestation = repo.attest(
        run_id,
        claim,
        signer=signer,
        evidence_ids=list(getattr(args, "evidence", None) or []),
        key=key,
        algorithm=algorithm,
        key_id=getattr(args, "key_id", None),
    )
    # Read back rather than kept from the signer: the receipt then reports the
    # block as *stored*, which is the thing repo-verify will check.
    block = repo.get(attestation).payload().get("signature") if key is not None else None
    return run_id, attestation, block


def _receipt(console, headline: str, oid: str) -> None:
    """Print the headline, then the new oid unwrapped and unhighlighted.

    The headline shortens ids the way every read verb does, but the receipt line
    does not: this oid is the value an operator pastes back into ``--expected-old``
    or ``tine object``, so it is printed whole, unhighlighted, and with
    ``soft_wrap`` so an 80-column terminal cannot fold it mid-digest.
    """
    console.print(headline)
    console.print(f"  {_terminal(oid)}", highlight=False, soft_wrap=True)


def _signature_line(console, block: dict[str, Any] | None, label: str) -> None:
    """One line saying whether the label is cryptographically bound, or not."""
    if not block:
        console.print(
            f"  [yellow]unsigned[/]: the {label} label is self-asserted, "
            "not cryptographically bound"
        )
        return
    console.print(
        f"  [green]signed[/] {_terminal(block.get('scheme'))} "
        f"alg={_terminal(block.get('alg'))} key_id={_terminal(block.get('key_id') or '-')}"
    )


def cmd_attest(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    claim = parse_claim(args)
    run_id, attestation, block = _attest(repo, args, args.target, claim, args.signer)
    if getattr(args, "json", False):
        emit(
            {
                "command": "attest",
                "repo": str(repo.path),
                "target": args.target,
                "run_id": run_id,
                "attestation_id": attestation,
                "signer": args.signer,
                "claim": claim,
                "evidence_ids": list(getattr(args, "evidence", None) or []),
                "signed": block is not None,
                "signature": block,
            }
        )
        return
    _receipt(console, f"Attested {_short_oid(run_id)} as {_terminal(args.signer)}", attestation)
    _signature_line(console, block, "signer")


def cmd_evaluate(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    # The one evaluation claim shape, byte-identical to the MCP evaluate_run tool.
    scores = parse_scores(args.score)
    run_id, attestation, block = _attest(
        repo, args, args.target, {"kind": "evaluation", "scores": scores}, args.evaluator
    )
    if getattr(args, "json", False):
        emit(
            {
                "command": "evaluate",
                "repo": str(repo.path),
                "target": args.target,
                "run_id": run_id,
                "attestation_id": attestation,
                "evaluator": args.evaluator,
                "scores": scores,
                "signed": block is not None,
                "signature": block,
            }
        )
        return
    rendered = ", ".join(f"{_terminal(name)}={value}" for name, value in sorted(scores.items()))
    _receipt(
        console,
        f"Evaluated {_short_oid(run_id)} as {_terminal(args.evaluator)}: {rendered}",
        attestation,
    )
    _signature_line(console, block, "evaluator")


def _cas_refusal(repo: Repo, ref: str, expected_old: str | None) -> ValueError:
    """Turn the store's compare-and-swap refusal into an operator remediation.

    ``commit_ref`` reports the mismatch it saw; what the operator needs is the
    flag that resolves it, so every branch here names ``--expected-old``. The
    re-read is best effort: an unreadable ref still yields a refusal.
    """
    try:
        current = repo.read_ref(ref)
    except (KernelError, OSError, ValueError):
        current = None
    if expected_old is None and current:
        return ValueError(
            f"{ref} already points at {current}; moving an existing promotion requires "
            f"--expected-old {current} (or promote under a different --name)"
        )
    if current is None:
        return ValueError(f"{ref} does not exist; omit --expected-old to create it")
    return ValueError(
        f"{ref} points at {current}, not the --expected-old you gave; re-read it and retry"
    )


def cmd_promote(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    run_id = _run_oid(repo, args.target)
    ref = f"promotions/{args.name}"
    # expected_old=None is *expect absent*, not "overwrite": Repo.promote always
    # passes the value through, so the store compare-and-swaps against it.
    try:
        repo.promote(run_id, args.name, expected_old=args.expected_old)
    except ValueError as exc:
        if not str(exc).startswith("concurrent ref update"):
            raise
        raise _cas_refusal(repo, ref, args.expected_old) from None
    if getattr(args, "json", False):
        emit(
            {
                "command": "promote",
                "repo": str(repo.path),
                "target": args.target,
                "run_id": run_id,
                "name": args.name,
                "ref": ref,
                "expected_old": args.expected_old,
                "created": args.expected_old is None,
            }
        )
        return
    verb = "Created" if args.expected_old is None else "Moved"
    _receipt(console, f"{verb} {_terminal(ref)} ->", run_id)
