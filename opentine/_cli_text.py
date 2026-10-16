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

import sys
from urllib.parse import urlsplit, urlunsplit

BIDI_FORMATTING = frozenset(
    {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
)
#: Every format character (General_Category Cf) and Default_Ignorable_Code_Point of
#: Unicode 16, plus the line/paragraph separators: characters that render as
#: nothing. Variation selectors (U+FE00-FE0F, U+E0100-E01EF) and tag characters
#: each carry a hidden byte per character -- the "smuggling" channels -- and
#: fillers such as U+3164 look like blanks. Fixed ranges, so the rule does not
#: change with the Python version's ``unicodedata``.
_INVISIBLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x0600, 0x0605), (0x061C, 0x061C),
    (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2),
    (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F),
    (0x2028, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFFB), (0x110BD, 0x110BD),
    (0x110CD, 0x110CD), (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)  # fmt: skip
INVISIBLE = frozenset(code for low, high in _INVISIBLE_RANGES for code in range(low, high + 1))
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


def endpoint_for_display(url: str) -> str:
    """*url* without credentials, query string or fragment: what a message may print.

    Collectors are often addressed with ``?token=...`` or ``?api_key=...``, which
    ``without_userinfo`` leaves in place.
    """
    parts = urlsplit(without_userinfo(url))
    return urlunsplit(parts._replace(query="", fragment=""))


#: How much of a recorded prompt a harness replay shows before sending it.
TASK_PREVIEW_CHARS = 200


def announce_recorded_task(prompt: str | None, task: str) -> None:
    """Say on stderr that a harness replay is about to send the artifact's own prompt.

    Without ``--prompt``, ``tine replay --harness`` hands a live agent CLI the
    ``user_prompt`` recorded in the artifact -- text whoever wrote the file
    chose. The replay still runs it (that is what a replay is), but never
    silently: the source, the length and a sanitized preview come first.
    """
    if prompt:
        return
    shown = plain_text(" ".join(str(task).split()))
    if len(shown) > TASK_PREVIEW_CHARS:
        shown = shown[: TASK_PREVIEW_CHARS - 3] + "..."
    sys.stderr.write(
        f"Replaying with the artifact's recorded prompt ({len(task)} chars; "
        f"pass --prompt to send your own): {shown}\n"
    )


__all__ = [
    "BIDI_FORMATTING",
    "INVISIBLE",
    "announce_recorded_task",
    "displayable",
    "plain_text",
    "without_userinfo",
]
