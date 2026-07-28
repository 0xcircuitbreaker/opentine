"""Strict JSON parsing for pricing catalogs."""

from __future__ import annotations

import json
import math
from typing import Any

from opentine.kernel import validate_json_shape


def parse_catalog_json(raw: bytes, error_type: type[ValueError]) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise error_type(f"duplicate pricing catalog key: {key[:80]!r}")
            result[key] = value
        return result

    def constant(value: str) -> None:
        raise error_type(f"non-finite JSON number in pricing catalog: {value}")

    def integer(value: str) -> int:
        try:
            return int(value)
        except ValueError as exc:
            raise error_type("pricing catalog integer literal is too large") from exc

    def floating(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise error_type("non-finite JSON number in pricing catalog")
        return number

    try:
        validate_json_shape(raw, max_tokens=100_000)
        return json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=constant,
            parse_float=floating,
            parse_int=integer,
        )
    except error_type:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        raise error_type(f"invalid catalog JSON: {exc}") from exc
