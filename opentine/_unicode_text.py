"""What counts as text in both opentine formats.

A leaf module with no ``opentine`` imports, so every layer that turns a str into
bytes — the ``.tine`` writer and reader, canonicalization, redaction, the search
index — can apply one rule instead of discovering it as a codec error.
"""

from __future__ import annotations

import re
from typing import Any

#: A UTF-16 surrogate code point. UTF-8 encodes Unicode *scalar* values, and a
#: surrogate is not one, so any str matching this has no UTF-8 spelling at all.
SURROGATE_CHAR = re.compile("[\ud800-\udfff]")
#: Prefilter over undecoded JSON *text*: a ``\\udXXX`` escape, or a literal
#: surrogate char already in a str. It over-matches — an escaped backslash before
#: ``ud83d`` is literal text — which costs a walk that finds nothing, never a
#: false refusal.
SURROGATE_TEXT = re.compile(r"\\u[dD][89a-fA-F]|[\ud800-\udfff]")
#: The same over *bytes*, which needs a second alternative: ``json.loads`` decodes
#: a bytes argument with ``errors="surrogatepass"``, so raw CESU-8/WTF-8 surrogate
#: bytes (``ED A0 80``-``ED BF BF``, what a Java or utf8mb3 producer emits) decode
#: to a lone surrogate too, without ever appearing as an escape. ``ED 80``-``ED 9F``
#: is ordinary U+D000-U+D7FF text and is deliberately not matched.
SURROGATE_BYTES = re.compile(rb"\\u[dD][89a-fA-F]|\xed[\xa0-\xbf]")


def surrogate_suspect(raw: bytes | str) -> bool:
    """Whether undecoded JSON could possibly decode to a lone surrogate."""
    return bool((SURROGATE_TEXT if isinstance(raw, str) else SURROGATE_BYTES).search(raw))


def lone_surrogate_path(value: Any) -> str | None:
    """JSON path of the first string UTF-8 cannot encode, else ``None``.

    Iterative on purpose: containers nest up to the depth ``validate_json_shape``
    permits (512), and a recursive walk that deep competes for stack with the
    parse that produced the value.
    """
    stack: list[tuple[str, Any]] = [("", value)]
    while stack:
        path, item = stack.pop()
        if isinstance(item, str):
            if SURROGATE_CHAR.search(item):
                return path or "<root>"
        elif isinstance(item, dict):
            for key, child in item.items():
                here = f"{path}.{key}" if path else f"{key}"
                if isinstance(key, str) and SURROGATE_CHAR.search(key):
                    return f"{here} (object key)"
                stack.append((here, child))
        elif isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                stack.append((f"{path}[{index}]", child))
    return None


def assert_unicode_text(value: Any, *, where: str) -> None:
    """Refuse strings UTF-8 cannot encode — neither opentine format can carry one.

    ``json.loads`` accepts an unpaired ``\\udXXX`` escape (exactly what
    ``JSON.stringify`` emits for a string sliced mid-emoji) and hands back a str
    holding a lone UTF-16 surrogate. It has no UTF-8 spelling, so the v3 canonical
    form cannot express it and no conforming reader in another language agrees on
    what it means — Go substitutes U+FFFD, changing every digest computed over it,
    while serde refuses outright. Accepting one into a ``.tine`` file therefore
    writes an artifact only this build can read, that verifies here and nowhere
    else, and that ``tine migrate-v3`` cannot convert. Both the ``.tine`` writer
    and its reader enforce this rule, so the two formats accept the same strings
    and the refusal arrives while the run is still in memory, where the caller can
    repair it. Sanitizing instead (U+FFFD, or dropping the char) is rejected: it
    would silently rewrite recorded model output under a digest claiming fidelity.
    """
    path = lone_surrogate_path(value)
    if path is not None:
        # The path itself holds the offending code unit when the surrogate is in an
        # object *key*, and a message no consumer can encode reintroduces the bare
        # codec error this guard exists to remove: str(exc).encode() raised, and the
        # CLI's sanitizer rendered the key as "?", losing the one detail that made
        # the refusal actionable. Spell it as its escape; legal text is untouched.
        shown = path[:200].encode("utf-8", "backslashreplace").decode("utf-8")
        raise ValueError(
            f"{where} holds an unpaired UTF-16 surrogate at {shown}; .tine "
            "artifacts and v3 objects are UTF-8 JSON, which cannot represent one. "
            "Repair it at the source: a truncated \\udXXX escape (a mid-emoji slice "
            "in a streamed model or tool response) or CESU-8 surrogate bytes from a "
            "non-UTF-8 producer. opentine will not substitute a replacement "
            "character on your behalf"
        )
