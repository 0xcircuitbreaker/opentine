"""Implementation of the explicit ``tine pricing`` lifecycle commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import httpx
from rich.console import Console
from rich.table import Table

from opentine.billing import BUNDLED_CATALOG, PricingCatalog, install_catalog, load_catalogs
from opentine.billing.catalog import CatalogError


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
    update.add_argument(
        "--dest",
        default=str(Path.home() / ".config" / "opentine" / "pricing.json"),
    )


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
            card.provider,
            card.model,
            card.effective_from.isoformat(),
            str(card.rates.get("input", "?")),
            str(card.rates.get("cache_read", "-")),
            str(card.rates.get("output", "?")),
            card.id,
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
    console.print(f"[bold]{card.provider}/{card.model}[/]  {card.id}")
    console.print(f"effective: {card.effective_from} through {card.effective_until or 'open'}")
    console.print(f"rates / MTok ({card.currency}): {data['rates']}")
    if card.context_thresholds:
        console.print(f"context rules: {list(card.context_thresholds)}")
    console.print(f"verified: {card.verified_at or '-'}")
    for source in card.source_urls:
        console.print(f"source: {source}")


def _cmd_check(args: argparse.Namespace, console: Console) -> None:
    catalog = PricingCatalog.load(args.path, require_signature=not args.allow_unsigned)
    state = "signed" if catalog.signed else "unsigned local overlay"
    console.print(f"[green]OK[/] {args.path} {catalog.id} ({state}, {len(catalog.cards)} cards)")


def _cmd_update(args: argparse.Namespace, console: Console) -> None:
    if args.source.startswith("http://"):
        raise ValueError("remote catalog updates require HTTPS")
    if args.source.startswith("https://"):
        response = httpx.get(args.source, timeout=30, follow_redirects=True)
        response.raise_for_status()
        if response.url.scheme != "https":
            raise ValueError("catalog update redirected away from HTTPS")
        raw = response.content
    else:
        raw = Path(args.source).read_bytes()
    catalog = install_catalog(raw, args.dest)
    console.print(f"[green]Installed[/] {catalog.id} -> {args.dest}")


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
        console.print(f"[red]Pricing error:[/] {exc}")
        raise SystemExit(1) from exc
