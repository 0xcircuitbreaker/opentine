"""Effective-dated catalogs, signature verification, and lookup precedence."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from opentine._canon import _canonical_bytes, atomic_write_text
from opentine.billing.types import RateCard, as_date

BUNDLED_CATALOG = Path(__file__).parent.parent / "data" / "pricing_catalog.json"
TRUSTED_KEYS = {
    "opentine-release-2026-07": "7dcohQb6JY+k202f3eeEy1t003t30ez4UG36muaUBYk=",
}


class CatalogError(ValueError):
    pass


def _body(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if key not in {"catalog_id", "signature"}}


def catalog_hash(data: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(_body(data))).hexdigest()


def verify_catalog(data: dict[str, Any], *, require_signature: bool = True) -> str:
    if data.get("schema") != "opentine-pricing/1":
        raise CatalogError("unsupported pricing catalog schema")
    actual = catalog_hash(data)
    if data.get("catalog_id") != f"sha256:{actual}":
        raise CatalogError("catalog id/hash mismatch")
    signature = data.get("signature")
    if not isinstance(signature, dict):
        if require_signature:
            raise CatalogError("catalog is unsigned")
        return actual
    if signature.get("algorithm") != "ed25519":
        raise CatalogError("unsupported catalog signature algorithm")
    key_id = signature.get("key_id")
    encoded_key = TRUSTED_KEYS.get(str(key_id))
    if not encoded_key:
        raise CatalogError(f"untrusted catalog signing key: {key_id}")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded_key))
        public.verify(base64.b64decode(signature["value"]), _canonical_bytes(_body(data)))
    except ImportError as exc:
        raise CatalogError("catalog verification requires cryptography") from exc
    except Exception as exc:
        raise CatalogError("catalog signature mismatch") from exc
    return actual


@dataclass(frozen=True)
class PricingCatalog:
    id: str
    cards: tuple[RateCard, ...]
    hash: str
    source: str = ""
    signed: bool = False
    priorities: tuple[int, ...] = ()
    provenance: tuple[dict[str, Any], ...] = ()

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
        digest = (
            verify_catalog(data, require_signature=require_signature)
            if verify
            else catalog_hash(data)
        )
        catalog_id = data.get("catalog_id") or f"sha256:{digest}"
        return cls(
            catalog_id,
            tuple(RateCard.from_dict(item) for item in data.get("cards") or ()),
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
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CatalogError(f"cannot load pricing catalog {p}: {exc}") from exc
        if not isinstance(raw, dict):
            raise CatalogError("pricing catalog root is not an object")
        return cls.from_dict(raw, source=str(p), verify=verify, require_signature=require_signature)


def catalog_paths(workspace: str | Path | None = None) -> list[Path]:
    root = Path(workspace or Path.cwd())
    paths = [BUNDLED_CATALOG]
    user = os.environ.get("TINE_PRICING_CATALOG")
    home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    paths.extend([home / "opentine" / "pricing.json", root / ".tine" / "pricing.json"])
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
    try:
        raw = json.loads(data)
    except json.JSONDecodeError as exc:
        raise CatalogError(f"invalid catalog JSON: {exc}") from exc
    catalog = PricingCatalog.from_dict(raw, source=str(path), verify=True, require_signature=True)
    atomic_write_text(path, json.dumps(raw, indent=2, sort_keys=True) + "\n", fsync=True)
    return catalog
