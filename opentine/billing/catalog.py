"""Effective-dated catalogs, signature verification, and lookup precedence."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from opentine._canon import atomic_write_text
from opentine.billing._catalog_json import parse_catalog_json
from opentine.billing._catalog_verify import SUPPORTED_SCHEMAS as SUPPORTED_SCHEMAS
from opentine.billing._catalog_verify import TRUSTED_KEYS as TRUSTED_KEYS
from opentine.billing._catalog_verify import CatalogError as CatalogError
from opentine.billing._catalog_verify import catalog_hash as catalog_hash
from opentine.billing._catalog_verify import verify_catalog as verify_catalog
from opentine.billing._immutable import freeze
from opentine.billing.types import RateCard, as_date

BUNDLED_CATALOG = Path(__file__).parent.parent / "data" / "pricing_catalog.json"
MAX_CATALOG_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class PricingCatalog:
    id: str
    cards: tuple[RateCard, ...]
    hash: str
    source: str = ""
    signed: bool = False
    priorities: tuple[int, ...] = ()
    provenance: tuple[dict[str, Any], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "cards", tuple(self.cards))
        object.__setattr__(self, "priorities", tuple(self.priorities))
        object.__setattr__(self, "provenance", tuple(freeze(self.provenance)))

    def lookup(
        self,
        provider: str,
        model: str,
        *,
        effective_at: date | datetime | str | None = None,
        service_tier: str | None = None,
    ) -> RateCard | None:
        del service_tier  # card modifiers are applied by the billing engine
        when = as_date(effective_at)
        priorities = self.priorities or (0,) * len(self.cards)
        matches = [
            (priorities[index], index, card)
            for index, card in enumerate(self.cards)
            if card.matches(provider, model) and card.active(when)
        ]
        if not matches:
            return None
        return max(matches, key=lambda item: (item[0], item[2].effective_from, item[1]))[2]

    def overlay(self, other: PricingCatalog) -> PricingCatalog:
        # A later layer wins for any matching provider/model. Effective dates
        # remain deterministic within each layer.
        other_ids = {card.id for card in other.cards}
        kept = [card for card in self.cards if card.id not in other_ids]
        old_priorities = self.priorities or (0,) * len(self.cards)
        kept_priorities = [
            old_priorities[index]
            for index, card in enumerate(self.cards)
            if card.id not in other_ids
        ]
        next_priority = max(kept_priorities, default=0) + 1
        cards = (*kept, *other.cards)
        priorities = (*kept_priorities, *((next_priority,) * len(other.cards)))
        joined = "sha256:" + hashlib.sha256(f"{self.hash}:{other.hash}".encode()).hexdigest()
        return PricingCatalog(
            joined,
            tuple(cards),
            joined[7:],
            "overlay",
            False,
            priorities,
            (*self.provenance, *other.provenance),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"catalog_id": self.id, "cards": [card.to_dict() for card in self.cards]}

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        *,
        source: str = "",
        verify: bool = True,
        require_signature: bool = True,
    ) -> PricingCatalog:
        if not isinstance(data, dict):
            raise CatalogError("pricing catalog root is not an object")
        cards = data.get("cards")
        if not isinstance(cards, list) or not all(isinstance(item, dict) for item in cards):
            raise CatalogError("pricing catalog cards must be a list of objects")
        digest = (
            verify_catalog(data, require_signature=require_signature)
            if verify
            else catalog_hash(data)
        )
        catalog_id = data.get("catalog_id") or f"sha256:{digest}"
        try:
            parsed_cards = tuple(RateCard.from_dict(item) for item in cards)
        except (ArithmeticError, AttributeError, KeyError, TypeError, ValueError) as exc:
            raise CatalogError(f"invalid pricing rate card: {exc}") from exc
        return cls(
            catalog_id,
            parsed_cards,
            digest,
            source,
            isinstance(data.get("signature"), dict),
            provenance=(
                {
                    "catalog_hash": digest,
                    "catalog_id": catalog_id,
                    "signature": data.get("signature"),
                    "source": source,
                },
            ),
        )

    @classmethod
    def load(
        cls, path: str | Path, *, verify: bool = True, require_signature: bool = True
    ) -> PricingCatalog:
        p = Path(path)
        try:
            with p.open("rb") as handle:
                data = handle.read(MAX_CATALOG_BYTES + 1)
            if len(data) > MAX_CATALOG_BYTES:
                raise CatalogError("pricing catalog exceeds maximum size")
        except OSError as exc:
            raise CatalogError(f"cannot load pricing catalog {p}: {exc}") from exc
        raw = parse_catalog_json(data, CatalogError)
        return cls.from_dict(raw, source=str(p), verify=verify, require_signature=require_signature)


def user_catalog_path() -> Path:
    """The per-user overlay path, honouring ``XDG_CONFIG_HOME``.

    Writers must resolve this the same way the loader does, or an install lands
    where nothing reads it. ``or`` rather than a ``get()`` default because the
    variable set to "" is present but meaningless, and ``Path("")`` is ``Path(".")``
    — which would make the overlay CWD-relative, and different per process.
    """
    home = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(home, "opentine", "pricing.json")


def catalog_paths(workspace: str | Path | None = None) -> list[Path]:
    root = Path(workspace or Path.cwd())
    paths = [BUNDLED_CATALOG]
    user = os.environ.get("TINE_PRICING_CATALOG")
    paths.extend([user_catalog_path(), root / ".tine" / "pricing.json"])
    if user:
        paths.append(Path(user))
    return paths


def load_catalogs(
    paths: Iterable[str | Path] | None = None, *, workspace: str | Path | None = None
) -> PricingCatalog:
    selected = [Path(item) for item in paths] if paths is not None else catalog_paths(workspace)
    catalog: PricingCatalog | None = None
    for index, path in enumerate(selected):
        if not path.exists():
            continue
        current = PricingCatalog.load(
            path, require_signature=index == 0 and path == BUNDLED_CATALOG
        )
        catalog = current if catalog is None else catalog.overlay(current)
    if catalog is None:
        raise CatalogError("no pricing catalog found")
    return catalog


def install_catalog(data: bytes, path: str | Path) -> PricingCatalog:
    if len(data) > MAX_CATALOG_BYTES:
        raise CatalogError("pricing catalog exceeds maximum size")
    raw = parse_catalog_json(data, CatalogError)
    catalog = PricingCatalog.from_dict(raw, source=str(path), verify=True, require_signature=True)
    atomic_write_text(path, json.dumps(raw, indent=2, sort_keys=True) + "\n", fsync=True)
    return catalog
