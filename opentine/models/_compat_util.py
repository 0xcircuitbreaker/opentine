"""Small helpers for the hosted OpenAI-compatible presets (kept out of
``_compat_hosted`` to stay inside the module size limit)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


def _has_cache_control(value: Any) -> bool:
    stack, seen = [value], set()
    while stack:
        item = stack.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, dict):
            if "cache_control" in item:
                return True
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return False


def _china_host(url: str | None) -> bool:
    host = (urlsplit((url or "").strip()).hostname or "").lower()
    return host == "bigmodel.cn" or host.endswith(".bigmodel.cn")
