"""Managed-cloud re-host adapters: usage is recorded, regional cost is not.

Bedrock, Vertex, and Azure OpenAI resell the same models under per-region,
per-account contract pricing that no signed snapshot can state truthfully. Every
adapter here records usage in full and reports cost as ``unknown`` unless the
operator supplies their own negotiated rates (``rates=`` or an overlay card).

    from opentine.models.managed import AzureOpenAI, Bedrock, Vertex

``opentine.__init__`` is deliberately untouched: managed adapters are reached
through ``opentine.models.*`` like every other provider.

``AzureOpenAI`` needs no extra of its own — it is a preset over the
OpenAI-compatible transport, so the existing ``compat`` extra serves it.
"""

from opentine.models._managed_aws import Bedrock, BedrockCompatible
from opentine.models._managed_azure import AzureOpenAI
from opentine.models._managed_gcp import Vertex, VertexAnthropic

__all__ = [
    "AzureOpenAI",
    "Bedrock",
    "BedrockCompatible",
    "Vertex",
    "VertexAnthropic",
]
