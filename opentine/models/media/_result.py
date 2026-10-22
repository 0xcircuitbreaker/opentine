"""The result of one media call, and how it is recorded as a run step.

Media bytes (an image, an audio file) never go into the step JSON: the step
records each output's size, content type and SHA-256, and the caller writes the
bytes where it wants them. The step carries the call's usage and the same
digest-covered billing record a chat adapter produces, so ``tine price`` and
``tine cost`` treat it like any other model call.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from typing import Any

from opentine.billing import Usage
from opentine.models._metered import metered_response


@dataclass
class MediaOutput:
    data: bytes
    content_type: str

    def describe(self) -> dict[str, Any]:
        return {
            "content_type": self.content_type,
            "bytes": len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest(),
        }


@dataclass
class MediaResult:
    provider: str
    model: str
    kind: str
    usage: Usage
    billing: dict[str, Any]
    cost: float
    outputs: list[MediaOutput] = field(default_factory=list)
    text: str = ""
    request: dict[str, Any] = field(default_factory=dict)

    def record(self, run: Any) -> Any:
        """Add this call to *run* as a model step and return the step."""
        from opentine.core import StepKind

        return run.add_step(
            StepKind.model,
            {"media": self.kind, **self.request},
            outputs={"text": self.text, "media": [item.describe() for item in self.outputs]},
            cost=self.cost,
            usage=self.usage.to_dict(),
            billing=self.billing,
            model_info=self.model,
            provider=self.provider,
        )


def finish(
    provider: str,
    model: str,
    kind: str,
    usage: Usage,
    *,
    outputs: list[MediaOutput] | None = None,
    text: str = "",
    request: dict[str, Any] | None = None,
    usage_reported: bool = True,
    reported_model: Any = None,
    catalog: Any = None,
) -> MediaResult:
    metered = metered_response(
        provider,
        model,
        usage,
        catalog=catalog,
        usage_reported=usage_reported,
        reported_model=reported_model,
    )
    return MediaResult(
        provider=provider,
        model=model,
        kind=kind,
        usage=usage,
        billing=metered["billing"],
        cost=float(metered["cost"] or 0.0),
        outputs=list(outputs or ()),
        text=text,
        request=dict(request or {}),
    )


def decode_b64(value: Any, limit: int) -> bytes:
    if not isinstance(value, str) or len(value) > limit * 4 // 3 + 8:
        raise ValueError("media payload is missing or too large")
    return base64.b64decode(value, validate=True)


__all__ = ["MediaOutput", "MediaResult", "decode_b64", "finish"]
