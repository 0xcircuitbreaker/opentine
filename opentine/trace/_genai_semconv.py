"""OpenTelemetry GenAI semantic-convention key names.

Single source of truth for every ``gen_ai.*`` attribute OpenTine reads on import
(:func:`opentine.trace.otel_genai_events`) and writes on export
(:func:`opentine.trace.to_otel_genai`). Both directions import these names, so a
convention update lands in one place instead of drifting between the two halves
and silently breaking the round trip.

Targeted convention: **OpenTelemetry semantic conventions v1.27.0**, the release
that settled the ``gen_ai.usage.input_tokens`` / ``gen_ai.usage.output_tokens``
counters (renamed there from ``gen_ai.usage.prompt_tokens`` /
``gen_ai.usage.completion_tokens``). ``gen_ai.prompt`` and ``gen_ai.completion``
are the content attributes from that same generation; later releases move
content onto ``gen_ai.input.messages`` / ``gen_ai.output.messages``, but the
1.27-era keys are what SDK exporters in the wild still emit, so they stay the
shape OpenTine both accepts and produces.
"""

from __future__ import annotations

SEMCONV_VERSION = "1.27.0"

NAMESPACE = "gen_ai."

OPERATION_NAME = "gen_ai.operation.name"
REQUEST_MODEL = "gen_ai.request.model"
RESPONSE_MODEL = "gen_ai.response.model"
PROMPT = "gen_ai.prompt"
COMPLETION = "gen_ai.completion"
INPUT_TOKENS = "gen_ai.usage.input_tokens"
OUTPUT_TOKENS = "gen_ai.usage.output_tokens"

#: OpenTine usage dimension -> GenAI token counter. Import reads right to left,
#: export writes left to right; neither side spells the keys itself.
USAGE_BY_DIMENSION: dict[str, str] = {"input": INPUT_TOKENS, "output": OUTPUT_TOKENS}

#: Model attributes in importer preference order (response wins over request).
MODEL_KEYS: tuple[str, ...] = (RESPONSE_MODEL, REQUEST_MODEL)

#: OpenTine-namespaced (not a GenAI convention): carries a step's kind when the
#: GenAI operation name cannot express it. Export writes it; import reads it back
#: and drops it, so a natively recorded run round-trips through OTel with its
#: tool/think/error kinds intact instead of collapsing every step to "model".
KIND_ATTRIBUTE = "opentine.trace.kind"
