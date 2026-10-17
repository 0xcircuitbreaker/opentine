"""Providers whose API calls are unmetered: inference on the user's own hardware.

Capture records a local preset's call as ``unmetered`` (an override card) because
there is no API bill; local infrastructure cost may still apply. ``tine price``
re-derives prices from the record alone, so it has to know the same set, or a run
captured as unmetered re-prices as ``unknown`` (audit round 3, L-1). One frozen
set, checked against the preset registry by a test, keeps the two in step.

Deliberately absent: ``litellm`` (a proxy, usually to metered APIs) and
``ollama-cloud`` (Ollama's hosted models bill per token), and
``anthropic-compatible`` (a non-loopback Anthropic-shaped gateway; who bills it
is unknown). ``local-anthropic-compatible`` is an agent CLI pointed at a loopback
Anthropic-compatible server, recorded by the harness capture.
"""

from __future__ import annotations

from typing import Any

LOCAL_UNMETERED_PROVIDERS = frozenset(
    {
        "aphrodite",
        "docker-model-runner",
        "dynamo",
        "foundry-local",
        "jan",
        "koboldcpp",
        "lemonade",
        "llama-cpp-python",
        "llamacpp",
        "llamafile",
        "lmdeploy",
        "lmstudio",
        "local",
        "local-anthropic-compatible",
        "localai",
        "mistralrs",
        "mlx-lm",
        "nvidia-nim",
        "ollama",
        "ovms",
        "sglang",
        "tabbyapi",
        "tensorrt-llm",
        "tgi",
        "unsloth",
        "vllm",
        "xinference",
    }
)


def unmetered_provider(provider: str) -> bool:
    return provider.casefold() in LOCAL_UNMETERED_PROVIDERS


def cloud_model(model: str) -> bool:
    """An Ollama-style ``:cloud`` / ``:*-cloud`` tag: proxied to a per-token API.

    The same rule as ``opentine.models._ollama_host.cloud_model`` (a test keeps
    them in step); repeated here so pricing does not import the model adapters.
    """
    tag = model.rsplit(":", 1)[-1].lower() if ":" in model else ""
    return tag == "cloud" or tag.endswith("-cloud")


def unmetered_call(
    provider: str, model: str, recorded_status: str | None, *, harness_capture: bool = False
) -> bool:
    """Whether re-pricing may book a recorded call as ``unmetered`` ($0).

    A provider *name* alone is not enough (final security pass, #5): a cloud
    tag routed through a local daemon bills per token, and a name written by an
    importer is a label, not a capture. So the provider must be local, the model
    must not carry a cloud tag, and the record must carry positive evidence:
    either the capture's own ``unmetered`` verdict (``recorded_status``), or no
    billing at all inside a run the harness wrapper captured (*harness_capture*:
    its provider came from the operator's own flags or a loopback base URL).

    A step with no billing outside a harness run is not evidence of anything --
    it is what a library import (``Recorder.import_events``) or a 0.9.x
    ``tine import`` stored -- so it re-prices from the catalog, never as free
    (final security pass 5, #4).
    """
    if not unmetered_provider(provider) or cloud_model(model):
        return False
    if recorded_status is None:
        return harness_capture
    return recorded_status == "unmetered"


def harness_run(run: Any) -> bool:
    """Whether *run* was captured by the harness wrapper (``tine run --harness``).

    The wrapper writes ``manifest["kind"] == "external-harness"`` and
    ``metadata["harness"]`` on every run it records (0.9.x and 0.10 alike). Nothing an
    importer builds carries either, so a step with no billing in any other run is
    not evidence that its provider name was the operator's.
    """
    manifest = getattr(run, "manifest", None)
    metadata = getattr(run, "metadata", None)
    kind = manifest.get("kind") if isinstance(manifest, dict) else None
    named = metadata.get("harness") if isinstance(metadata, dict) else None
    return kind == "external-harness" or (isinstance(named, str) and bool(named))


__all__ = [
    "LOCAL_UNMETERED_PROVIDERS",
    "cloud_model",
    "harness_run",
    "unmetered_call",
    "unmetered_provider",
]
