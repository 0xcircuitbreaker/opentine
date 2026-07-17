"""Release-quality invariants for the signed bundled pricing snapshot."""

from collections import defaultdict
from datetime import date

from opentine.billing import PricingCatalog
from opentine.billing.catalog import BUNDLED_CATALOG


def test_bundled_catalog_names_are_unique_over_their_effective_windows():
    catalog = PricingCatalog.load(BUNDLED_CATALOG)
    names = defaultdict(list)
    for card in catalog.cards:
        assert card.verified_at is not None
        assert card.source_urls and all(url.startswith("https://") for url in card.source_urls)
        assert len(
            {card.model.casefold(), *(alias.casefold() for alias in card.aliases)}
        ) == 1 + len(card.aliases)
        for name in (card.model, *card.aliases):
            names[(card.provider.casefold(), name.casefold())].append(card)

    for cards in names.values():
        for index, left in enumerate(cards):
            for right in cards[index + 1 :]:
                start = max(left.effective_from, right.effective_from)
                end = min(left.effective_until or date.max, right.effective_until or date.max)
                assert start > end, f"overlapping rate cards: {left.id} and {right.id}"
