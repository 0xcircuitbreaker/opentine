"""Stable machine-readable JSON for the ``tine pricing`` lifecycle commands.

All four subcommands take ``--json``, and each writes exactly one object to
stdout through :func:`opentine._cli_json.emit` — the CLI's single JSON writer,
so a rate card sorts and escapes here exactly as a run does under ``tine show
--json``. The rich rendering stays the default; ``--json`` only replaces it.

A catalog that will not load — a bad hash, a missing signature, an unreadable
file, an ``http://`` update URL — is a failure that stops the command producing
a result, so it stays human text on stderr-ish output and exits 1 rather than
becoming an object with ``ok: false``. The same rule the rest of the CLI's
``--json`` surfaces follow.

Every payload names the catalog it answered from (``catalog_id`` and
``catalog_hash``), because a rate is only meaningful against the catalog it was
read out of, and a script comparing two machines needs to see when they differ.

``tine pricing list --json``
    ``command``       ``"pricing-list"``
    ``catalog_id``    str — the effective (possibly overlaid) catalog
    ``catalog_hash``  str
    ``count``         int — number of entries in ``cards`` after filtering
    ``cards``         array — one rate card per entry, in the table's order and
                      after the same ``--provider``/``--model``/``--at``
                      filters; each is the full ``RateCard.to_dict()`` shape
                      (``id``, ``provider``, ``model``, ``rates``,
                      ``effective_from``, ``effective_until``, …), which is
                      also what ``show`` flattens

``tine pricing show PROVIDER MODEL --json``
    ``command``       ``"pricing-show"``
    ``catalog_id``    str
    ``catalog_hash``  str
    plus every key of the selected rate card, flattened at the top level — those
    card keys are exactly what ``show --json`` has emitted since 0.3.0

``tine pricing check PATH --json``
    ``command``       ``"pricing-check"``
    ``path``          str — the catalog file that was checked
    ``ok``            ``true`` — a failed check exits 1 as human text
    ``catalog_id``    str
    ``catalog_hash``  str
    ``signed``        bool
    ``state``         str — ``"signed"`` or ``"unsigned local overlay"``
    ``cards``         int — how many rate cards it carries

``tine pricing update SOURCE --json``
    ``command``       ``"pricing-update"``
    ``source``        str — the URL or file the catalog came from
    ``dest``          str — where it was installed
    ``catalog_id``    str
    ``catalog_hash``  str
    ``signed``        bool
    ``cards``         int

``tine price RUN --json``
    The post-hoc pass (:mod:`opentine._pricing_pass`), which recomputes a run's
    cost from its recorded ``(provider, model, usage)`` instead of summing what
    capture recorded — so it lives here, beside the catalog surfaces it reads,
    rather than with ``tine cost`` in :mod:`opentine._cli_json`.

    ``command``          ``"price"``
    ``run_id``           str
    ``short_id``         str
    ``catalog_id``       str — the catalog the run was priced against
    ``catalog_hash``     str
    ``effective_at``     str — ISO date the rates were selected for (``--at``)
    ``total_cost``       float — sum of the *known* subtotals only
    ``priced_steps``     int — steps a rate card answered for
    ``unknown_steps``    int — steps no rate card covers; unpriced, not free
    ``unknown_models``   array of str — the models behind ``unknown_steps``
    ``by_model``         object — model id -> cost, priced steps only
    ``by_provider``      object — provider -> cost, priced steps only
    ``status_counts``    object — billing status -> number of steps
    ``steps``            array — one object per model step, in recorded order:
                         ``step_id``, ``provider``, ``model``, ``status``,
                         ``amount_usd`` (null unless ``status`` is
                         ``complete``), ``known_subtotal_usd``, ``rate_card_id``
"""

from __future__ import annotations

from typing import Any

from opentine._cli_json import emit
from opentine.core import short_id


def emit_list(catalog: Any, cards: list[Any]) -> None:
    emit(
        {
            "command": "pricing-list",
            "catalog_id": catalog.id,
            "catalog_hash": catalog.hash,
            "count": len(cards),
            "cards": [card.to_dict() for card in cards],
        }
    )


def emit_show(catalog: Any, card: Any) -> None:
    emit({"command": "pricing-show", **_catalog_of(card.to_dict(), catalog)})


def emit_check(catalog: Any, path: str, state: str) -> None:
    emit(
        {
            "command": "pricing-check",
            "path": path,
            "ok": True,
            "state": state,
            **_catalog_of({"signed": bool(catalog.signed), "cards": len(catalog.cards)}, catalog),
        }
    )


def emit_update(catalog: Any, source: str, dest: str) -> None:
    emit(
        {
            "command": "pricing-update",
            "source": source,
            "dest": dest,
            **_catalog_of({"signed": bool(catalog.signed), "cards": len(catalog.cards)}, catalog),
        }
    )


def emit_price(run: Any, pricing: Any) -> None:
    """Emit the post-hoc pricing rollup for one run."""
    emit({"command": "price", "run_id": run.id, "short_id": short_id(run.id), **pricing.to_dict()})


def _catalog_of(payload: dict[str, Any], catalog: Any) -> dict[str, Any]:
    """Stamp the catalog a payload was read out of onto it."""
    return {**payload, "catalog_id": catalog.id, "catalog_hash": catalog.hash}
