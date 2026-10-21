"""Media and per-unit pricing: image, video, audio, speech and request dimensions.

``opentine-pricing/3`` adds two optional rate-card fields on top of ``/2``:

``units``
    ``{dimension: unit}`` for a dimension priced per unit rather than per
    million tokens: an image, a second of video or audio, a minute, a character
    of text-to-speech, a request. A dimension not listed is a token dimension,
    priced per million exactly as before.

``same_rate_as``
    ``{dimension: base}`` for a dimension the vendor prices like another, such
    as image or video *input* tokens billed at the text input rate. Stated on
    the card, never assumed: a used dimension with no rate and no declared base
    leaves the price ``partial`` with a warning, so media is never silently
    billed at the text rate.

A catalog whose cards use either field must say ``opentine-pricing/3``: a
0.10 reader refuses that schema, where it would otherwise read a per-image
price as a price per million images.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any

TOKEN = "token"
#: Every unit a rate-card dimension may be priced in.
UNITS = frozenset({TOKEN, "image", "second", "minute", "character", "request"})

#: Canonical media dimensions. Token dimensions split a modality out of the
#: text buckets (``input``/``output``), so a modality the vendor prices like
#: text needs a ``same_rate_as`` entry rather than a guessed rate.
TOKEN_DIMENSIONS = frozenset(
    f"{side}_{modality}" for side in ("input", "output") for modality in ("image", "audio", "video")
)
#: Per-unit dimensions (``units`` on the card). Variants carry a ``:`` qualifier,
#: for example ``images:1024x1024:high`` or ``video_seconds:1080p``.
UNIT_DIMENSIONS = {
    "images": "image",
    "video_seconds": "second",
    "audio_input_seconds": "second",
    "audio_output_seconds": "second",
    "audio_minutes": "minute",
    "tts_characters": "character",
    "realtime_minutes": "minute",
    "requests": "request",
}
SCHEMA_V3 = "opentine-pricing/3"
_FEATURES = ("units", "same_rate_as")
_MILLION = Decimal(1_000_000)


def validate_media_fields(card: Any) -> None:
    """Shape checks for ``units`` and ``same_rate_as`` on a normalized card."""
    if not isinstance(card.units, Mapping) or not isinstance(card.same_rate_as, Mapping):
        raise ValueError("rate-card units and same_rate_as must be objects")
    for name, unit in card.units.items():
        if not isinstance(name, str) or not name or len(name) > 128 or unit not in UNITS:
            raise ValueError(f"rate-card unit for {name!r} must be one of {sorted(UNITS)}")
    for name, base in card.same_rate_as.items():
        if not all(isinstance(item, str) and item and len(item) <= 128 for item in (name, base)):
            raise ValueError("rate-card same_rate_as entries must be short strings")
        if base in card.same_rate_as or name == base:
            raise ValueError("rate-card same_rate_as must point at a priced dimension, not a chain")
        # By family, as resolve_rate looks units up: ``images:hd`` is per image
        # through ``units['images']`` and must never join a per-million rate.
        kinds = {_family(item) in UNIT_DIMENSIONS for item in (name, base)}
        if (_unit(card, name) or TOKEN) != (_unit(card, base) or TOKEN) or len(kinds) > 1:
            raise ValueError(f"rate-card same_rate_as joins {name!r} to a different unit")
    for name in _rate_names(card):
        if _family(name) in UNIT_DIMENSIONS and (_unit(card, name) or TOKEN) == TOKEN:
            raise ValueError(f"rate-card prices per-unit dimension {name!r} without a unit")


def check_schema_features(data: Mapping[str, Any]) -> None:
    """Refuse per-unit or aliased dimensions in a catalog older than ``/3``."""
    if data.get("schema") == SCHEMA_V3:
        return
    for card in data.get("cards") or ():
        if not isinstance(card, Mapping):
            continue
        if any(card.get(field) for field in _FEATURES):
            raise ValueError(f"rate-card {_FEATURES} need schema {SCHEMA_V3!r}")
        for group in _raw_rate_groups(card):
            if any(isinstance(name, str) and _family(name) in UNIT_DIMENSIONS for name in group):
                raise ValueError(f"per-unit media rates need schema {SCHEMA_V3!r}")


def _raw_rate_groups(card: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    groups = [card.get("rates")]
    service = card.get("service_rates")
    if isinstance(service, Mapping):
        groups.extend(service.values())
    schedule = card.get("schedule")
    if isinstance(schedule, list):
        groups.extend(window.get("rates") for window in schedule if isinstance(window, Mapping))
    return [group for group in groups if isinstance(group, Mapping)]


def _family(dimension: str) -> str:
    """``images:1024x1024:high`` -> ``images``: the canonical name a variant belongs to."""
    return dimension.split(":", 1)[0]


def _unit(card: Any, *names: str) -> str | None:
    for name in names:
        for key in (name, _family(name)):
            if key in card.units:
                return card.units[key]
    return None


def resolve_rate(
    card: Any, rates: Mapping[str, Decimal], dimension: str
) -> tuple[Decimal | None, str, Decimal]:
    """The rate for *dimension*, the dimension it came from, and its divisor.

    A per-unit dimension (an image, a second, a character...) is priced only
    when the card states its unit, for the dimension or its variant family:
    without one, the rate would be read per *million* units, so it is treated
    as missing and the price stays ``partial`` instead of complete and ~free.
    """
    base = dimension
    rate = rates.get(dimension)
    if rate is None and dimension in card.same_rate_as:
        base = card.same_rate_as[dimension]
        rate = rates.get(base)
    unit = _unit(card, dimension, base) or TOKEN
    per_unit = {_family(dimension), _family(base)} & UNIT_DIMENSIONS.keys()
    if unit == TOKEN and per_unit:
        return None, base, Decimal(1)
    return rate, base, (_MILLION if unit == TOKEN else Decimal(1))


def _rate_names(card: Any) -> set[str]:
    groups = [getattr(card, "rates", {}) or {}]
    groups.extend((getattr(card, "service_rates", {}) or {}).values())
    groups.extend(window.get("rates") or {} for window in getattr(card, "schedule", ()) or ())
    return {name for group in groups for name in group}


def media_usage(
    *,
    images: int | Mapping[str, int] = 0,
    video_seconds: float | Mapping[str, float] = 0,
    audio_input_seconds: float = 0,
    audio_output_seconds: float = 0,
    tts_characters: int = 0,
    requests: int = 0,
    tokens: Mapping[str, int] | None = None,
) -> Any:
    """A :class:`~opentine.billing.Usage` for a media call, in the canonical dimension names.

    ``images`` and ``video_seconds`` take either a count or a mapping from a
    variant (``"1024x1024:high"``, ``"720p"``) to a count, so a card that prices
    sizes or resolutions differently can bill each one.
    """
    from opentine.billing.types import Usage

    extra: dict[str, Any] = {}
    for name, value in (("images", images), ("video_seconds", video_seconds)):
        items = value.items() if isinstance(value, Mapping) else (("", value),)
        for variant, count in items:
            if count:
                extra[f"{name}:{variant}" if variant else name] = count
    for name, value in (
        ("audio_input_seconds", audio_input_seconds),
        ("audio_output_seconds", audio_output_seconds),
        ("tts_characters", tts_characters),
        ("requests", requests),
    ):
        if value:
            extra[name] = value
    known = dict(tokens or {})
    base = {name: known.pop(name, 0) for name in ("input", "output")}
    return Usage(**base, extra={**known, **extra})


__all__ = [
    "SCHEMA_V3",
    "TOKEN_DIMENSIONS",
    "UNITS",
    "UNIT_DIMENSIONS",
    "check_schema_features",
    "media_usage",
    "resolve_rate",
    "validate_media_fields",
]
