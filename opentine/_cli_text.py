"""Characters untrusted text must not carry onto a terminal or to an MCP client.

One definition for both sinks. ``_cli_common._terminal`` (Rich output) and the
MCP server's ``_clip`` used to keep their own rules, and the MCP one stripped
nothing but line breaks: run content reached the client with raw escape
sequences, bidi overrides and invisible tag characters intact.

Dropped: C0 controls (the caller decides about ``\\n``/``\\t``), DEL and C1 --
the bytes that start terminal escape sequences (OSC 52 clipboard writes, title
changes, screen clears) -- plus bidi overrides, which reorder what a reader
sees, and zero-width / tag / line-separator characters, which hide text from
the reader while a copy-paste or a model still receives it.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

BIDI_FORMATTING = frozenset(
    {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
)
INVISIBLE = frozenset(
    {
        *range(0x200B, 0x200E),  # zero-width space / non-joiner / joiner
        *range(0x2060, 0x2065),  # word joiner and invisible operators
        0xFEFF,  # zero-width no-break space (BOM)
        0x2028,  # line separator
        0x2029,  # paragraph separator
        *range(0xE0000, 0xE0080),  # tag characters
    }
)
_HIDDEN = BIDI_FORMATTING | INVISIBLE


def displayable(character: str) -> bool:
    """Whether *character* is safe to show as itself (never a control)."""
    codepoint = ord(character)
    return codepoint >= 32 and not 127 <= codepoint <= 159 and codepoint not in _HIDDEN


def plain_text(value: object, *, keep: str = "") -> str:
    """*value* as text with every unsafe character removed; *keep* is exempt."""
    raw = str(value).encode("utf-8", "replace").decode("utf-8")
    return "".join(character for character in raw if character in keep or displayable(character))


def without_userinfo(url: str) -> str:
    """*url* minus any ``user:password@``, for printing an endpoint the user gave."""
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url
    return urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[1]))


__all__ = ["BIDI_FORMATTING", "INVISIBLE", "displayable", "plain_text", "without_userinfo"]
