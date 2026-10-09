"""Per-model wire rules, as data, with fail-safe defaults for names not yet listed.

Every adapter used to keep its own model-name list, and each new model family
slipped past one of them: 0.8.2 found ``claude-opus-5`` sent a ``temperature``
Anthropic rejects with HTTP 400, and ``gpt-6-*`` the same against OpenAI. The
failure modes decide the defaults. Omitting a sampling parameter never fails a
request; sending one a model rejects fails *every* request. So a vendor's
unlisted model is assumed to be its current kind, and only the legacy families
known to accept a custom temperature are sent one. A new model then works the
day it ships, with at worst the vendor's default temperature, instead of 400ing
until a release adds its name.
"""

from __future__ import annotations

import re

#: Claude families that accept a custom ``temperature``: everything before the
#: 4.6 generation (and the 4.0/4.1/4.5 dated and alias IDs). From 4.6 on, "non-
#: default temperature, top_p, or top_k values return a 400 error", so any other
#: ``claude-*`` name -- including models released after this list -- gets none.
_CLAUDE_SAMPLING = re.compile(r"^claude-(?:instant|2|3)\b|-4-[015](?:-|$)|-4-2025")
#: Claude models that take an explicit ``thinking: {"type": "adaptive"}``.
_CLAUDE_EXPLICIT_ADAPTIVE = ("opus-4-6", "opus-4-7", "opus-4-8", "sonnet-4-6")
#: Claude families without thinking (Haiku 4.5 rejects adaptive thinking).
_CLAUDE_NO_THINKING = ("haiku-3", "haiku-4", "3-haiku", "3-5-haiku", "claude-2", "claude-instant")
_CLAUDE_THINKING = ("opus", "sonnet", "fable", "mythos", "haiku-5")
#: A non-Claude name behind the Anthropic adapter (a compatible endpoint) has no
#: vendor default to fail safe toward, so only these known names are restricted.
_RESTRICTED_FOREIGN = ("fable-5", "mythos-5", "mythos-preview", "sonnet-5", "opus-5", "haiku-5")

#: OpenAI families that accept a custom ``temperature`` (the non-reasoning ones).
#: On the native API every other model -- ``o*``, ``gpt-5*``, ``gpt-6*`` and
#: whatever ships next -- is a reasoning model that rejects it at default effort.
_OPENAI_SAMPLING = ("gpt-4", "gpt-3.5", "chatgpt-", "ft:gpt-4", "ft:gpt-3.5", "davinci", "babbage")
#: Known OpenAI reasoning families, for OpenAI-shaped endpoints that may serve
#: anything (a custom ``base_url``): there, only these names drop temperature.
_OPENAI_REASONING = ("gpt-5", "gpt-6", "o1", "o3", "o4")


def claude_rules(model: str) -> tuple[bool, bool, bool]:
    """``(supports_thinking, restricted_sampling, explicit_adaptive)`` for a model."""
    name = model.lower().replace(".", "-")
    claude = name.startswith("claude-")
    explicit_adaptive = any(item in name for item in _CLAUDE_EXPLICIT_ADAPTIVE)
    supports = any(item in name for item in _CLAUDE_THINKING) or (
        claude and not any(item in name for item in _CLAUDE_NO_THINKING)
    )
    if claude:
        restricted = explicit_adaptive or not _CLAUDE_SAMPLING.search(name)
    else:
        restricted = explicit_adaptive or any(item in name for item in _RESTRICTED_FOREIGN)
    return supports, restricted, explicit_adaptive


def openai_omits_temperature(model: str, *, native: bool) -> bool:
    """Whether a request to *model* must not carry ``temperature``.

    ``native`` is the first-party API, where an unlisted name is a reasoning
    model; elsewhere only the known reasoning families are.
    """
    name = model.lower()
    if native:
        return not name.startswith(_OPENAI_SAMPLING)
    return name.startswith(_OPENAI_REASONING)
