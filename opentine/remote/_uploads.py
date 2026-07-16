"""Bounded resumable-upload state and per-upload synchronization."""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_UPLOAD_ID = re.compile(r"^[0-9a-f]{32}$")


class TerminalUploadError(ValueError):
    """An upload declaration cannot be resumed and should be discarded."""


class UploadRegistry:
    def __init__(self, root: Path, *, ttl_seconds: float, max_pending: int):
        if ttl_seconds <= 0 or max_pending < 1:
            raise ValueError("upload TTL and pending-upload limit must be positive")
        self.root = root
        self.ttl_seconds = ttl_seconds
        self.max_pending = max_pending
        self._guard = threading.Lock()
        self._reap_guard = threading.Lock()
        self._entries: dict[str, list[Any]] = {}
        self._last_reap = 0.0

    @staticmethod
    def _key(tenant: str, upload_id: str) -> str:
        if not _UPLOAD_ID.fullmatch(upload_id):
            raise ValueError("invalid upload id")
        return f"{tenant}/{upload_id}"

    def paths(self, tenant: str, upload_id: str) -> tuple[Path, Path]:
        self._key(tenant, upload_id)
        directory = self.root / tenant
        directory.mkdir(parents=True, exist_ok=True)
        return directory / f"{upload_id}.part", directory / f"{upload_id}.json"

    @contextmanager
    def locked(self, tenant: str, upload_id: str) -> Iterator[tuple[Path, Path]]:
        key = self._key(tenant, upload_id)
        with self._guard:
            entry = self._entries.setdefault(key, [threading.Lock(), 0])
            entry[1] += 1
        lock = entry[0]
        lock.acquire()
        try:
            yield self.paths(tenant, upload_id)
        finally:
            lock.release()
            with self._guard:
                entry[1] -= 1
                if entry[1] == 0:
                    self._entries.pop(key, None)

    def _active(self) -> set[str]:
        with self._guard:
            return set(self._entries)

    def reap(self, *, force: bool = False) -> int:
        now = time.time()
        if not force and now - self._last_reap < min(60.0, self.ttl_seconds):
            return 0
        if not self._reap_guard.acquire(blocking=False):
            return 0
        removed = 0
        try:
            active = self._active()
            seen: set[str] = set()
            for candidate in self.root.glob("*/*"):
                if candidate.suffix not in {".json", ".part"}:
                    continue
                key = f"{candidate.parent.name}/{candidate.stem}"
                if key in seen:
                    continue
                seen.add(key)
                metadata = candidate.with_suffix(".json")
                part = candidate.with_suffix(".part")
                try:
                    modified = max(
                        path.stat().st_mtime for path in (metadata, part) if path.exists()
                    )
                    stale = now - modified >= self.ttl_seconds
                except (FileNotFoundError, ValueError):
                    continue
                if stale and key not in active:
                    metadata.unlink(missing_ok=True)
                    part.unlink(missing_ok=True)
                    removed += 1
            self._last_reap = now
            return removed
        finally:
            self._reap_guard.release()

    def create(self, tenant: str, upload_id: str, metadata: dict[str, Any]) -> tuple[Path, Path]:
        self.reap(force=True)
        if sum(1 for _ in self.root.glob("*/*.json")) >= self.max_pending:
            raise ValueError("too many pending uploads")
        part, metadata_path = self.paths(tenant, upload_id)
        part.touch(exist_ok=False)
        try:
            with metadata_path.open("x", encoding="utf-8") as handle:
                json.dump(metadata, handle, sort_keys=True, separators=(",", ":"))
        except Exception:
            part.unlink(missing_ok=True)
            raise
        return part, metadata_path

    @staticmethod
    def cleanup(paths: tuple[Path, Path]) -> None:
        for path in paths:
            path.unlink(missing_ok=True)

    def lock_count(self) -> int:
        with self._guard:
            return len(self._entries)
