"""``tine run --model provider[:model] --prompt ...`` — a first run with no code.

The other two run modes both need something written first: a Python script that
builds its own Run, or an agent CLI installed and logged in for ``--harness``.
This third mode drives a bundled adapter straight from the command line, so a
new user's first captured run costs one command.  It is exclusive with the other
two — three modes competing for one Run would leave two of them silently
dropped — and everything downstream of the model call (default save location,
``--save``, the receipt) is the script mode's behaviour, unchanged: literally
so, since all three modes end in ``_cli_render._save_run_receipt``.
"""

from __future__ import annotations

import argparse

from opentine._cli_common import BRAND, _terminal, console
from opentine._cli_flags import (
    AUTOSAVE_FLAGS,
    HARNESS_CONFIG_FLAGS,
    refuse_conflict,
    refuse_unhonoured,
)
from opentine._cli_render import _save_run_receipt


def cmd_run_model(args: argparse.Namespace) -> None:
    _refuse_competing_modes(args)
    # Imported here, not at module scope: `tine ls` should not pay for the
    # adapter package, and no provider SDK may be touched before a provider is
    # named (the adapters lazy-import theirs inside _get_client).
    from opentine.models import UnknownProvider, resolve_model
    from opentine.runtime import Agent

    try:
        model = resolve_model(args.model)
    except UnknownProvider as exc:
        console.print(f"[red]{_terminal(exc)}[/]")
        raise SystemExit(1) from exc
    console.print(f"[{BRAND}]# Running {_terminal(model.name)}...[/]\n")
    try:
        run = Agent(model=model).run_sync(args.prompt)
    except ImportError as exc:
        # The adapter's own guidance, e.g. "pip install opentine[anthropic]".
        console.print(f"[red]Missing dependency:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    except Exception as exc:
        # A missing key, a refusal, a rate limit: the provider's own rejection,
        # reported as one line rather than as a traceback.
        console.print(f"[red]Model run failed:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
    # args.force, like args.save, because this mode's tail *is* the script
    # mode's tail: the third `tine run` mode may not be the one that overwrites.
    _save_run_receipt(run, args.save, args.force)


def _refuse_competing_modes(args: argparse.Namespace) -> None:
    """Exit 1 for a command line where --model is not the whole story."""
    if args.script:
        console.print(
            f"[red]{_terminal(args.script)} and --model cannot be combined: only one takes "
            "effect. A script builds its own Run; --model builds one from a bundled adapter.[/]"
        )
        raise SystemExit(1)
    refuse_conflict(
        args,
        ("harness", "model"),
        hint="--harness records an agent CLI; --model calls a bundled model adapter.",
    )
    if not args.prompt:
        console.print("[red]--prompt is required when running --model.[/]")
        raise SystemExit(1)
    refuse_unhonoured(
        args,
        (*AUTOSAVE_FLAGS, *HARNESS_CONFIG_FLAGS),
        mode="with --model",
        hint=(
            "A --model run is one model call with no subprocess to configure or "
            "checkpoint; use --save PATH to choose where that run is written."
        ),
    )
