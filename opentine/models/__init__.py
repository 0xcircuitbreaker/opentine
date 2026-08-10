"""Model adapters — same protocol, any provider.

``resolve_model`` turns a ``provider[:model]`` string into a ready adapter, so a
caller holding only text — ``tine run --model openai:gpt-5.6`` — never has to
import an adapter class by hand.  Nothing here imports a provider SDK: each
adapter lazy-imports its own inside ``_get_client``, and this module imports an
adapter module only once its provider has actually been named.
"""

from __future__ import annotations

import importlib
from typing import Any

# The four native adapters live in modules named for their provider, so one name
# serves as both the CLI word and the module.  The hosted OpenAI-compatible
# providers are deliberately *not* listed again here: they are read back off
# ``_compat_hosted`` below, so a hosted adapter added there is nameable at once
# and no second list can drift away from the first.
_NATIVE = {
    "anthropic": "Anthropic",
    "google": "Google",
    "ollama": "Ollama",
    "openai": "OpenAI",
}


class UnknownProvider(ValueError):
    """No bundled adapter answers to this provider name."""


def _hosted() -> dict[str, type]:
    from opentine.models import _compat_hosted
    from opentine.models._chat import ChatCompletions

    return {
        name.casefold(): value
        for name, value in vars(_compat_hosted).items()
        if isinstance(value, type)
        and issubclass(value, ChatCompletions)
        and value.__module__ == _compat_hosted.__name__
    }


def provider_names() -> list[str]:
    """Every provider ``resolve_model`` accepts, in the order errors list them."""
    return sorted({*_NATIVE, *_hosted()})


def model_class(provider: str) -> type:
    """The adapter class registered under *provider*, matched case-insensitively."""
    name = provider.strip().casefold()
    if name in _NATIVE:
        module = importlib.import_module(f"opentine.models.{name}")
        return getattr(module, _NATIVE[name])
    hosted = _hosted()
    if name in hosted:
        return hosted[name]
    raise UnknownProvider(
        f"Unknown provider {provider!r}. Valid providers: {', '.join(provider_names())}"
    )


def resolve_model(spec: str) -> Any:
    """Build the adapter named by ``provider[:model]``; the model id is optional.

    The split takes the *first* colon only, so a model id that contains one
    (``ollama:llama3.1:8b``) reaches the adapter intact.  Without a model id the
    adapter keeps its own default, which is the one the README quotes.
    """
    provider, _, model = spec.partition(":")
    adapter = model_class(provider)
    return adapter(model) if model else adapter()


__all__ = ["UnknownProvider", "model_class", "provider_names", "resolve_model"]
