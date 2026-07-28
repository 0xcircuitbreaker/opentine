"""Implementation of the explicit ``tine pricing`` lifecycle commands."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import httpx
from rich.console import Console
from rich.table import Table

from opentine._cli_common import _terminal
from opentine.billing import BUNDLED_CATALOG, PricingCatalog, install_catalog, load_catalogs
from opentine.billing.catalog import MAX_CATALOG_BYTES, CatalogError, user_catalog_path


def add_pricing_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("pricing", help="Inspect and update signed pricing catalogs")
    actions = parser.add_subparsers(dest="pricing_command", required=True)

    listing = actions.add_parser("list", help="List effective rate cards")
    listing.add_argument("--provider")
    listing.add_argument("--model")
    listing.add_argument("--at", help="Effective date (YYYY-MM-DD)")

    show = actions.add_parser("show", help="Show the selected exact rate card")
    show.add_argument("provider")
    show.add_argument("model")
    show.add_argument("--at", help="Effective date (YYYY-MM-DD)")
    show.add_argument("--json", action="store_true")

    check = actions.add_parser("check", help="Verify catalog hash and signature")
    check.add_argument("path", nargs="?", default=str(BUNDLED_CATALOG))
    check.add_argument("--allow-unsigned", action="store_true")

    update = actions.add_parser("update", help="Install a signed catalog from file or URL")
    update.add_argument("source", help="HTTPS URL or local JSON file")
    # Must match where load_catalogs() actually reads the user overlay from, or the
    # install silently has no effect under a non-default XDG_CONFIG_HOME.
    update.add_argument("--dest", default=str(user_catalog_path()))


def _cmd_list(args: argparse.Namespace, console: Console) -> None:
    catalog = load_catalogs()
    cards = sorted(catalog.cards, key=lambda card: (card.provider, card.model, card.effective_from))
    table = Table(title=f"Pricing catalog {catalog.id[:19]}…")
    for column in ("Provider", "Model", "Effective", "Input", "Cache", "Output", "Card"):
        table.add_column(column)
    for card in cards:
        if args.provider and card.provider.casefold() != args.provider.casefold():
            continue
        if args.model and args.model.casefold() not in card.model.casefold():
            continue
        if args.at and not card.active(card.effective_from.fromisoformat(args.at)):
            continue
        table.add_row(
            _terminal(card.provider),
            _terminal(card.model),
            card.effective_from.isoformat(),
            str(card.rates.get("input", "?")),
            str(card.rates.get("cache_read", "-")),
            str(card.rates.get("output", "?")),
            _terminal(card.id),
        )
    console.print(table)


def _cmd_show(args: argparse.Namespace, console: Console) -> None:
    catalog = load_catalogs()
    card = catalog.lookup(args.provider, args.model, effective_at=args.at)
    if card is None:
        raise SystemExit(f"No exact rate card for {args.provider}/{args.model}")
    data = card.to_dict()
    data["catalog_id"] = catalog.id
    data["catalog_hash"] = catalog.hash
    if args.json:
        console.print_json(json.dumps(data))
        return
    console.print(
        f"[bold]{_terminal(card.provider)}/{_terminal(card.model)}[/]  {_terminal(card.id)}"
    )
    console.print(f"effective: {card.effective_from} through {card.effective_until or 'open'}")
    console.print(f"rates / MTok ({card.currency}): {data['rates']}")
    if card.context_thresholds:
        console.print(f"context rules: {list(card.context_thresholds)}")
    console.print(f"verified: {card.verified_at or '-'}")
    for source in card.source_urls:
        console.print(f"source: {_terminal(source)}")


def _cmd_check(args: argparse.Namespace, console: Console) -> None:
    catalog = PricingCatalog.load(args.path, require_signature=not args.allow_unsigned)
    state = "signed" if catalog.signed else "unsigned local overlay"
    console.print(
        f"[green]OK[/] {_terminal(args.path)} {_terminal(catalog.id)} "
        f"({state}, {len(catalog.cards)} cards)"
    )


def _cmd_update(args: argparse.Namespace, console: Console) -> None:
    if args.source.startswith("http://"):
        raise ValueError("remote catalog updates require HTTPS")
    if args.source.startswith("https://"):
        with httpx.stream("GET", args.source, timeout=30, follow_redirects=False) as response:
            response.raise_for_status()
            if response.is_redirect:
                raise ValueError("catalog update redirects are not followed")
            declared = int(response.headers.get("content-length", "0"))
            if declared > MAX_CATALOG_BYTES:
                raise ValueError("pricing catalog exceeds maximum size")
            downloaded = bytearray()
            started = time.monotonic()
            for chunk in response.iter_bytes():
                if time.monotonic() - started > 30:
                    raise ValueError("pricing catalog download exceeded total deadline")
                downloaded.extend(chunk)
                if len(downloaded) > MAX_CATALOG_BYTES:
                    raise ValueError("pricing catalog exceeds maximum size")
            raw = bytes(downloaded)
    else:
        with Path(args.source).open("rb") as handle:
            raw = handle.read(MAX_CATALOG_BYTES + 1)
    catalog = install_catalog(raw, args.dest)
    console.print(f"[green]Installed[/] {_terminal(catalog.id)} -> {_terminal(args.dest)}")


def cmd_pricing(args: argparse.Namespace, console: Console) -> None:
    commands = {
        "list": _cmd_list,
        "show": _cmd_show,
        "check": _cmd_check,
        "update": _cmd_update,
    }
    try:
        commands[args.pricing_command](args, console)
    except (CatalogError, OSError, httpx.HTTPError, ValueError) as exc:
        console.print(f"[red]Pricing error:[/] {_terminal(exc)}")
        raise SystemExit(1) from exc
