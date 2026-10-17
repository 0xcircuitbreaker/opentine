"""Map the provider names foreign emitters use onto OpenTine's catalog ids.

A rate card matches its provider exactly (case-insensitively), and an imported
trace carried whatever ``gen_ai.provider.name`` / ``gen_ai.system`` (or a
framework's ``ls_provider``) its emitter chose. The OpenTelemetry GenAI
registry spells Google as ``gcp.gemini``, xAI as ``x_ai`` and Mistral as
``mistral_ai``; LangChain says ``google_genai`` and ``mistralai``. None of
those matched a card, so an imported Gemini, Grok or Mistral call priced
``unknown`` for no reason but spelling.

Only well-known spellings are translated, and only to a provider a catalog
names; an unrecognized value is kept as it was (lowercased) rather than guessed.
"""

from __future__ import annotations

#: Foreign spelling (casefolded) -> catalog provider id.
PROVIDER_ALIASES: dict[str, str] = {
    # OpenTelemetry GenAI registry (gen_ai.provider.name / gen_ai.system)
    "gcp.gemini": "google",
    "gcp.vertex_ai": "google",
    "gcp.gen_ai": "google",
    "vertex_ai": "google",
    "x_ai": "xai",
    "mistral_ai": "mistral",
    "aws.bedrock": "bedrock",
    "az.ai.openai": "foundry",
    "azure.ai.openai": "foundry",
    "azure.ai.inference": "foundry",
    "az.ai.inference": "foundry",
    "moonshot_ai": "kimi",
    "moonshot": "kimi",
    "zhipu": "glm",
    "z_ai": "glm",
    "zai": "glm",
    "alibaba": "qwen",
    "dashscope": "qwen",
    "together_ai": "together",
    "togetherai": "together",
    # LangChain ls_provider values
    "google_genai": "google",
    "google_vertexai": "google",
    "google_anthropic_vertex": "vertex",
    "mistralai": "mistral",
    "amazon_bedrock": "bedrock",
    "bedrock_converse": "bedrock",
    "azure": "foundry",
    "azure_openai": "foundry",
    "azure_ai": "foundry",
    "fireworks_ai": "fireworks",
    # Claude Code's own provider labels (modelUsage / OTel resource)
    "firstparty": "anthropic",
    "first_party": "anthropic",
}


def canonical_provider(value: object) -> str:
    """The catalog provider id for *value*, or *value* itself (stripped) when unknown."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    return PROVIDER_ALIASES.get(text.casefold(), text)


__all__ = ["PROVIDER_ALIASES", "canonical_provider"]
