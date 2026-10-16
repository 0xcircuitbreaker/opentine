"""Bound how deep a harness event can sit inside a recorded step.

The parser admits events up to ``kernel.MAX_JSON_DEPTH`` (512) levels, but a step
places parts of an event *inside* the run's own structure (run, graph, steps, step,
inputs), and the ``.tine`` writer refuses anything past the reader's 512. So an
event nested ~505 deep -- a prompt-injected ``tool_use`` input, an MCP server's
result -- recorded fine and then made the whole run unsaveable, and with
``--autosave`` killed the agent mid-run. Subtrees at ``RECORD_DEPTH`` are kept as
their compact JSON text instead, so every recorded step can be saved.

The same holds for an unpaired UTF-16 surrogate: Node-based CLIs write one as a
valid ``\\udXXX`` escape (a string sliced mid-emoji, an MCP result), the parser
decodes it, and the ``.tine`` writer refuses it -- the run was lost, and with
``--autosave`` the agent killed (final pass 8, #5). It is recorded as its six-
character escape text instead, and the step says so (``surrogates_escaped``): a
visible rewrite of external bytes, never a silent U+FFFD.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

#: Below every save-side bound (the ``.tine`` reader's 512 levels less the run's own
#: wrapper levels): an event the parser admitted can always be saved afterwards.
RECORD_DEPTH = 256
#: Any surrogate left in a str is unpaired (JSON decoding joins a valid pair).
_SURROGATE = re.compile("[\ud800-\udfff]")


def escaped_text(text: str) -> str:
    """*text* with each unpaired surrogate as its ``\\udXXX`` escape text."""
    if not isinstance(text, str):
        return text
    return _SURROGATE.sub(lambda match: f"\\u{ord(match.group()):04x}", text)


def _has_surrogate(value: Any) -> bool:
    """Whether any str in *value* (keys included) holds an unpaired surrogate."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, str):
            if _SURROGATE.search(node):
                return True
        elif depth <= RECORD_DEPTH and isinstance(node, Mapping):
            for key, item in node.items():
                stack.append((key, depth))
                stack.append((item, depth + 1))
        elif depth <= RECORD_DEPTH and isinstance(node, list | tuple):
            for item in node:
                stack.append((item, depth + 1))
    return False


def _recordable(value: Any, _depth: int = 0) -> Any:
    """*value* with every subtree at ``RECORD_DEPTH`` kept as its compact JSON text,
    and every unpaired surrogate as escape text (marked on the top-level mapping)."""
    if _depth == 0 and isinstance(value, Mapping) and _has_surrogate(value):
        out = _walk(value, 0)
        out["surrogates_escaped"] = True
        return out
    return _walk(value, _depth)


def _walk(value: Any, _depth: int) -> Any:
    if isinstance(value, str):
        return escaped_text(value)
    if isinstance(value, Mapping | list | tuple):
        if _depth >= RECORD_DEPTH:
            try:
                text = json.dumps(value, default=repr)  # ensure_ascii: escapes surrogates
                return {"truncated_depth": RECORD_DEPTH, "json": text}
            except (RecursionError, ValueError, TypeError):
                return {"truncated_depth": RECORD_DEPTH, "json": "[nested too deep to record]"}
        if isinstance(value, Mapping):
            out: dict[Any, Any] = {}
            for key, item in value.items():
                name = escaped_text(key) if isinstance(key, str) else key
                out[name] = _walk(item, _depth + 1)
            return out
        items: list[Any] = []
        for item in value:
            items.append(_walk(item, _depth + 1))
        return items
    return value
