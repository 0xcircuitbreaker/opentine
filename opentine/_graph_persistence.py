"""Compatibility methods that delegate v2 persistence away from Run semantics."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentine._artifact_io import read_artifact_json
from opentine._graph_types import RunStatus


class RunPersistenceMixin:
    def save(self, path: str | Path, **kwargs: Any) -> Path:
        from opentine._graph_serde import save_run

        return save_run(self, path, **kwargs)

    @staticmethod
    def verify_signature(
        path_or_data: str | Path | dict[str, Any],
        *,
        hmac_key: bytes | None = None,
        public_key: Any | None = None,
        trust_embedded: bool = False,
    ):
        from opentine.signing import SignatureResult, verify_artifact

        try:
            data = (
                path_or_data if isinstance(path_or_data, dict) else read_artifact_json(path_or_data)
            )
        except FileNotFoundError:
            return SignatureResult(False, "error", None, None, None, None, "file not found")
        except (
            OSError,
            json.JSONDecodeError,
            UnicodeDecodeError,
            RecursionError,
            ValueError,
        ) as exc:
            return SignatureResult(False, "error", None, None, None, None, f"unreadable: {exc}")
        if not isinstance(data, dict):
            return SignatureResult(False, "error", None, None, None, None, "root is not an object")
        return verify_artifact(
            data,
            hmac_key=hmac_key,
            public_key=public_key,
            trust_embedded=trust_embedded,
        )

    @staticmethod
    def verify_integrity(path_or_data: str | Path | dict[str, Any]):
        from opentine._graph_serde import verify_integrity

        return verify_integrity(path_or_data)

    @classmethod
    def load(cls, path: str | Path):
        from opentine._graph_serde import load_run

        return load_run(path, cls)

    def pause(self, path: str | Path) -> Path:
        self.status = RunStatus.paused
        return self.save(path)

    @classmethod
    def resume(cls, path: str | Path):
        run = cls.load(path)
        run.status = RunStatus.running
        return run

    def to_dict(self, *, redact: bool = False) -> dict[str, Any]:
        from opentine._graph_serde import run_to_dict

        return run_to_dict(self, redact=redact)
