"""The CLIs that speak the Claude-compatible stream, and what each leaves out.

Qwen Code maps Gemini's ``promptTokenCount`` to ``input_tokens``, so its input
*includes* cache reads (and its thoughts sit outside ``output_tokens``); Amp
reports usage but no model name; Cursor reports neither usage nor a model id
(only a display name); Droid and Auggie print one closing ``result`` object.
"""

from __future__ import annotations

from opentine.harnesses._dialects_messages import ClaudeCompatible


class QwenCode(ClaudeCompatible):
    cli = "qwen-code"
    input_includes_cache = True  # BaseJsonOutputAdapter maps promptTokenCount

    def provider_for(self, model: str) -> str:
        if self.provider:
            return self.provider
        return "qwen" if model.lower().startswith("qwen") else ""


class Amp(ClaudeCompatible):
    cli = "amp"


class Cursor(ClaudeCompatible):
    cli = "cursor"


class Qoder(ClaudeCompatible):
    cli = "qoder"


class Auggie(ClaudeCompatible):
    cli = "auggie"


class Droid(ClaudeCompatible):
    cli = "droid"


class GrokBuild(ClaudeCompatible):
    cli = "grok"
    default_provider = "xai"


__all__ = ["Amp", "Auggie", "Cursor", "Droid", "GrokBuild", "Qoder", "QwenCode"]
