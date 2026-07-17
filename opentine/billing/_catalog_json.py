"""Strict JSON parsing for pricing catalogs."""

from __future__ import annotations

import json
from typing import Any


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

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except error_type:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise error_type(f"invalid catalog JSON: {exc}") from exc
