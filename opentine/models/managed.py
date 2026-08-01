"""Managed-cloud re-host adapters: usage is recorded, regional cost is not.

Bedrock, Vertex, and Azure OpenAI resell the same models under per-region,
per-account contract pricing that no signed snapshot can state truthfully. Every
adapter here records usage in full and reports cost as ``unknown`` unless the
operator supplies their own negotiated rates (``rates=`` or an overlay card).

    from opentine.models.managed import Bedrock, Vertex

``opentine.__init__`` is deliberately untouched: managed adapters are reached
through ``opentine.models.*`` like every other provider.
"""

# AzureOpenAI lands here in Phase 13; it is served by the existing `compat`
# extra and needs no new dependency.
from opentine.models._managed_aws import Bedrock, BedrockCompatible
from opentine.models._managed_gcp import Vertex, VertexAnthropic

__all__ = [
    "Bedrock",
    "BedrockCompatible",
    "Vertex",
    "VertexAnthropic",
]
