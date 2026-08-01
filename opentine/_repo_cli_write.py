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

**No signing, and no ``--force``.** v3 has no attestation signing helper, so a
``signer`` label is self-asserted and the human output says so; signing is 0.7.0
Trust work. And a promotion ref is a release gate: ``expected_old=None`` means
*expect no existing ref*, so moving a promotion always requires the operator to
name the value being replaced with ``--expected-old``. There is no override flag.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal
from opentine._cli_json import emit
from opentine._repo_cli_render import _short_oid
from opentine.kernel import KernelError, parse_oid
from opentine.repo import Repo
from opentine.repository.ops import resolve_target

#: A claim is operator-authored, but it is still read off disk or off a shell
#: argument, and it is stored verbatim inside a content-addressed object.
MAX_CLAIM_BYTES = 1 << 20


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


def _claim(args: argparse.Namespace) -> dict[str, Any]:
    """Parse ``--claim`` / ``--claim-file`` into a JSON object, or refuse."""
    source = "--claim"
    if getattr(args, "claim_file", None):
        source = "--claim-file"
        text = Path(args.claim_file).read_text(encoding="utf-8")
    else:
        text = args.claim or ""
    if len(text.encode("utf-8", "replace")) > MAX_CLAIM_BYTES:
        raise ValueError(f"{source} exceeds the {MAX_CLAIM_BYTES}-byte claim limit")
    try:
        parsed = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"{source} must be valid JSON: {exc}") from None
    if not isinstance(parsed, dict):
        # An attestation claim is read back as a mapping by _associations and by
        # search; a bare list, number, or string would store fine and then raise
        # on every reader, so it is refused at the door instead.
        raise ValueError(f"{source} must be a JSON object, got {type(parsed).__name__}")
    return parsed


def _scores(pairs: list[str] | None) -> dict[str, float]:
    """Parse repeated ``--score NAME=VALUE`` into the evaluation claim's mapping."""
    scores: dict[str, float] = {}
    for pair in pairs or []:
        name, separator, raw = pair.partition("=")
        if not separator or not name:
            raise ValueError(f"--score must be NAME=VALUE, got {pair!r}")
        try:
            value = float(raw)
        except ValueError:
            raise ValueError(f"--score {name} must be a number, got {raw!r}") from None
        if not math.isfinite(value):
            # search averages scores; a nan or inf would poison every average it
            # reaches, and _finite drops it silently on the way back out.
            raise ValueError(f"--score {name} must be finite, got {raw!r}")
        if name in scores:
            raise ValueError(f"--score {name} was given twice")
        scores[name] = value
    if not scores:
        raise ValueError("evaluate requires at least one --score NAME=VALUE")
    return scores


def _attest(
    repo: Repo, args: argparse.Namespace, target: str, claim: dict[str, Any], signer: str
) -> tuple[str, str]:
    """Resolve, then make the single ``Repo.attest`` call both verbs share."""
    run_id = _run_oid(repo, target)
    return run_id, repo.attest(
        run_id,
        claim,
        signer=signer,
        evidence_ids=list(getattr(args, "evidence", None) or []),
    )


def _receipt(console, headline: str, oid: str) -> None:
    """Print the headline, then the new oid unwrapped and unhighlighted.

    The headline shortens ids the way every read verb does, but the receipt line
    does not: this oid is the value an operator pastes back into ``--expected-old``
    or ``tine object``, so it is printed whole, unhighlighted, and with
    ``soft_wrap`` so an 80-column terminal cannot fold it mid-digest.
    """
    console.print(headline)
    console.print(f"  {_terminal(oid)}", highlight=False, soft_wrap=True)


def cmd_attest(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    claim = _claim(args)
    run_id, attestation = _attest(repo, args, args.target, claim, args.signer)
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
                "signed": False,
            }
        )
        return
    _receipt(console, f"Attested {_short_oid(run_id)} as {_terminal(args.signer)}", attestation)
    console.print(
        "  [yellow]unsigned[/]: the signer label is self-asserted, not cryptographically bound"
    )


def cmd_evaluate(args: argparse.Namespace, console) -> None:
    repo = Repo.open(args.repo)
    # The one evaluation claim shape, byte-identical to the MCP evaluate_run tool.
    scores = _scores(args.score)
    run_id, attestation = _attest(
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
                "signed": False,
            }
        )
        return
    rendered = ", ".join(f"{_terminal(name)}={value}" for name, value in sorted(scores.items()))
    _receipt(
        console,
        f"Evaluated {_short_oid(run_id)} as {_terminal(args.evaluator)}: {rendered}",
        attestation,
    )
    console.print(
        "  [yellow]unsigned[/]: the evaluator label is self-asserted, not cryptographically bound"
    )


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
