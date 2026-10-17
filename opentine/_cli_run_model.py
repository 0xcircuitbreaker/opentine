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
    from opentine.models import UnknownProvider
    from opentine.runtime import Agent

    try:
        model = build_model(
            args.model, getattr(args, "base_url", None), getattr(args, "api_key_env", None)
        )
    except (UnknownProvider, ValueError) as exc:
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


def add_model_args(run: argparse.ArgumentParser) -> None:
    """``tine run --model`` and the two flags that configure its adapter."""
    run.add_argument(
        "--model",
        metavar="PROVIDER[:MODEL]",
        help="Run a bundled model adapter with --prompt, e.g. anthropic or openai:gpt-6.1-sol",
    )
    run.add_argument(
        "--base-url",
        metavar="URL",
        help="Point the --model adapter at this endpoint (a server on another port or host)",
    )
    run.add_argument(
        "--api-key-env",
        metavar="NAME",
        help="Read the --model adapter's API key from environment variable NAME",
    )


#: ``tine run`` flags only a ``--model`` run honours.
MODEL_FLAGS = ("base_url", "api_key_env")


def refuse_model_flags(args: argparse.Namespace, mode: str) -> None:
    """Exit 1 when --base-url/--api-key-env reach a run mode that ignores them."""
    refuse_unhonoured(
        args,
        MODEL_FLAGS,
        mode=mode,
        hint="--base-url and --api-key-env configure the adapter of a --model run.",
    )


def build_model(spec: str, base_url: str | None, api_key_env: str | None):
    """``resolve_model(spec)`` pointed at *base_url* with the key in *api_key_env*.

    A local server on another port or machine, or one that requires a key (Jan,
    TabbyAPI, LM Studio with auth), used to be reachable only from Python.
    """
    import os

    from opentine.models import model_class, resolve_model
    from opentine.models._endpoint_security import require_key_transport

    if base_url is None and api_key_env is None:
        return resolve_model(spec)
    provider, _, model = spec.partition(":")
    key = None
    if api_key_env is not None:
        key = os.environ.get(api_key_env)
        if not key:
            raise ValueError(f"--api-key-env {api_key_env}: that variable is not set")
    cls = model_class(provider)
    options: dict = {} if not model else {"model": model}
    name = provider.strip().casefold()
    if name == "google":
        if base_url is not None:
            raise ValueError("google: set GOOGLE_GEMINI_BASE_URL instead of --base-url")
        return cls(api_key=key, **options)
    if name == "ollama":
        return cls(host=base_url, api_key=key, **options)
    if name == "anthropic" and base_url is not None:
        options.update(compatible_anthropic(base_url))
    if name in ("anthropic", "openai") or hasattr(cls, "default_host"):
        if key is not None:
            options["api_key"] = key
        return cls(base_url=base_url, **options) if base_url else cls(**options)
    # A hosted OpenAI-compatible preset: its endpoint is fixed, and its own key
    # (GROQ_API_KEY, ...) belongs to that vendor -- never sent to another host.
    if base_url is not None and key is None:
        raise ValueError(
            f"{provider}: --base-url needs --api-key-env (its own key is never sent elsewhere)"
        )
    if key is not None:
        options["api_key"] = key
    if base_url is None:
        return cls(**options)
    # Built against the real endpoint, so host-derived billing (Fireworks' us.
    # tier, GLM's China provider) is never computed for the default one.
    adapter = cls(base_url=base_url.rstrip("/"), **options)
    require_key_transport(base_url, adapter._api_key)
    return adapter


def compatible_anthropic(base_url: str) -> dict:
    """Provider identity for ``--model anthropic --base-url``: never first-party
    prices for another server's tokens."""
    from urllib.parse import urlsplit

    from opentine.models._anthropic_client import third_party
    from opentine.models._endpoint_security import _loopback

    if not third_party(base_url):
        return {}
    if _loopback(urlsplit(base_url.strip()).hostname):
        return {"provider": "local-anthropic-compatible", "unmetered": True}
    return {"provider": "anthropic-compatible"}
