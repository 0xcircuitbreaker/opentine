"""Effective-dated catalogs, signature verification, and lookup precedence."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from opentine._canon import atomic_write_text
from opentine.billing import _catalog_trust as _trust
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
    #: The signed ``generated_at``, for rollback checks; ``None`` when undated.
    generated_at: datetime | None = None

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
            generated_at=_trust.generated_at(data),
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


#: Called with the path of a workspace overlay ``load_catalogs`` ignores (unsigned,
#: not opted in; ``_catalog_trust``), and of a signed user catalog it skips as older
#: than the bundled one. The CLI sets them to tell the operator; the library is quiet.
workspace_overlay_hook: Callable[[Path], None] | None = None
stale_catalog_hook: Callable[[Path], None] | None = None


def workspace_catalog_path(workspace: str | Path | None = None) -> Path:
    return Path(workspace or Path.cwd()) / ".tine" / "pricing.json"


def catalog_paths(workspace: str | Path | None = None) -> list[Path]:
    paths = [BUNDLED_CATALOG]
    user = os.environ.get("TINE_PRICING_CATALOG")
    paths.extend([user_catalog_path(), workspace_catalog_path(workspace)])
    if user:
        paths.append(Path(user))
    return paths


def load_catalogs(
    paths: Iterable[str | Path] | None = None, *, workspace: str | Path | None = None
) -> PricingCatalog:
    selected = [Path(item) for item in paths] if paths is not None else catalog_paths(workspace)
    overlay = workspace_catalog_path(workspace) if paths is None else None
    user = user_catalog_path() if paths is None else None
    catalog, bundled_at = None, None
    for index, path in enumerate(selected):
        if not path.exists():
            continue
        bundled = index == 0 and path == BUNDLED_CATALOG
        current = (
            _workspace_overlay(path)
            if path == overlay
            else PricingCatalog.load(path, require_signature=bundled)
        )
        if current is None:
            continue
        if path == BUNDLED_CATALOG:
            bundled_at = current.generated_at
        elif path == user and current.signed and _trust.older(current.generated_at, bundled_at):
            if stale_catalog_hook is not None:
                stale_catalog_hook(path)
            continue
        catalog = current if catalog is None else catalog.overlay(current)
    if catalog is None:
        raise CatalogError("no pricing catalog found")
    return catalog


def _workspace_overlay(path: Path) -> PricingCatalog | None:
    """The workspace overlay if it may apply: validly signed, or opted in."""
    trusted = _trust.workspace_pricing_trusted()
    try:
        current = PricingCatalog.load(path, require_signature=False)
    except CatalogError:
        if trusted:
            raise
        current = None
    if current is not None and (current.signed or trusted):
        return current
    if workspace_overlay_hook is not None:
        workspace_overlay_hook(path)
    return None


def _signed_at(path: Path) -> datetime | None:
    try:
        return PricingCatalog.load(path).generated_at if path.exists() else None
    except CatalogError:
        return None  # an unsigned or damaged file is nothing to roll back from


def install_catalog(data: bytes, path: str | Path) -> PricingCatalog:
    if len(data) > MAX_CATALOG_BYTES:
        raise CatalogError("pricing catalog exceeds maximum size")
    raw = parse_catalog_json(data, CatalogError)
    catalog = PricingCatalog.from_dict(raw, source=str(path), verify=True, require_signature=True)
    for name, reference in (("bundled", BUNDLED_CATALOG), ("installed", Path(path))):
        newer = _signed_at(reference)
        if _trust.older(catalog.generated_at, newer):
            when = raw.get("generated_at") or "at no date"
            raise CatalogError(
                f"refusing a pricing catalog generated {when}: the {name} catalog is newer "
                f"({newer}), and installing this one would roll prices back"
            )
    atomic_write_text(path, json.dumps(raw, indent=2, sort_keys=True) + "\n", fsync=True)
    return catalog
