"""Bounded resumable-upload state and per-upload synchronization."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from opentine._canon import _fsync_dir
from opentine.remote._upload_crypto import append_frames, read_frames, spool_bound
from opentine.remote.interfaces import KeyProvider
from opentine.repository.pack import MAX_PACK_BYTES, minimum_upload_chunk

_UPLOAD_ID = re.compile(r"^[0-9a-f]{32}$")


class TerminalUploadError(ValueError):
    """An upload declaration cannot be resumed and should be discarded."""


class UploadRegistry:
    def __init__(
        self,
        root: Path,
        keys: KeyProvider | None,
        *,
        ttl_seconds: float,
        max_pending: int,
        max_bytes: int = MAX_PACK_BYTES,
    ):
        if ttl_seconds <= 0 or max_pending < 1 or not 0 < max_bytes <= MAX_PACK_BYTES:
            raise ValueError("upload TTL and pending-upload limit must be positive")
        if not callable(getattr(keys, "encrypt", None)) or not callable(
            getattr(keys, "decrypt", None)
        ):
            raise RuntimeError("resumable uploads require a staging KeyProvider")
        self.root = root
        self.keys = keys
        self._private_directory(root)
        self.ttl_seconds = ttl_seconds
        self.max_pending = max_pending
        self.max_bytes = max_bytes
        self._guard = threading.Lock()
        self._reap_guard = threading.Lock()
        self._entries: dict[str, list[Any]] = {}
        self._last_reap = 0.0

    @staticmethod
    def _private_directory(path: Path) -> None:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        junction = getattr(path, "is_junction", None)
        unsafe = path.is_symlink() or (callable(junction) and junction())
        if not stat.S_ISDIR(path.lstat().st_mode) or unsafe:
            raise ValueError("upload state directory is not a real directory")
        path.chmod(0o700)

    @staticmethod
    def _private_file(path: Path) -> None:
        try:
            current = path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
            raise ValueError("upload state path is not a regular file")
        path.chmod(0o600)

    @staticmethod
    def _read_metadata(path: Path) -> bytes:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ValueError("upload metadata is not a regular file")
        with os.fdopen(fd, "rb") as handle:
            return handle.read(4097)

    @staticmethod
    def _key(tenant: str, upload_id: str) -> str:
        if not _UPLOAD_ID.fullmatch(upload_id):
            raise ValueError("invalid upload id")
        return f"{tenant}/{upload_id}"

    def paths(self, tenant: str, upload_id: str) -> tuple[Path, Path]:
        self._key(tenant, upload_id)
        self._private_directory(self.root)
        directory = self.root / tenant
        self._private_directory(directory)
        paths = directory / f"{upload_id}.part", directory / f"{upload_id}.json"
        for path in paths:
            self._private_file(path)
        return paths

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
        part_fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(part_fd)
        part.chmod(0o600)
        try:
            metadata.update({"offset": 0, "spool_size": 0})
            metadata_fd = os.open(metadata_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(metadata_fd, "w", encoding="utf-8") as handle:
                json.dump(metadata, handle, sort_keys=True, separators=(",", ":"))
            metadata_path.chmod(0o600)
        except Exception:
            part.unlink(missing_ok=True)
            metadata_path.unlink(missing_ok=True)
            raise
        return part, metadata_path

    @staticmethod
    def _write_metadata(path: Path, metadata: dict[str, Any]) -> None:
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        try:
            os.chmod(temporary, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(metadata, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            _fsync_dir(path.parent)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def load(self, tenant: str, paths: tuple[Path, Path]) -> dict[str, Any]:
        part, metadata_path = paths
        raw = self._read_metadata(metadata_path)
        if len(raw) > 4096:
            raise ValueError("upload metadata exceeds its size limit")
        metadata = json.loads(raw)
        required = ("sha256", "size", "offset", "spool_size")
        if not isinstance(metadata, dict) or any(key not in metadata for key in required):
            raise ValueError("invalid upload metadata")
        if type(metadata["size"]) is not int or type(metadata["offset"]) is not int:
            raise ValueError("invalid upload metadata")
        if type(metadata["spool_size"]) is not int:
            raise ValueError("invalid upload metadata")
        if (
            not isinstance(metadata["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"])
            or not 0 <= metadata["offset"] <= metadata["size"] <= self.max_bytes
            or metadata["spool_size"] < 0
        ):
            raise ValueError("invalid upload metadata")
        physical_size = part.lstat().st_size
        if physical_size > spool_bound(metadata["size"]):
            raise ValueError("encrypted upload spool exceeds its declared bound")
        if physical_size != metadata["spool_size"]:
            data, spool_size = read_frames(
                part, self.keys, tenant, metadata["size"], repair_tail=True
            )
            metadata.update({"offset": len(data), "spool_size": spool_size})
            self._write_metadata(metadata_path, metadata)
        return metadata

    def append(
        self, tenant: str, paths: tuple[Path, Path], metadata: dict[str, Any], chunk: bytes
    ) -> dict[str, Any]:
        if metadata["offset"] + len(chunk) < metadata["size"] and len(chunk) < minimum_upload_chunk(
            metadata["size"]
        ):
            raise ValueError("resumable upload chunk is below the safe minimum")
        offset, spool_size = append_frames(
            paths[0], self.keys, tenant, metadata["offset"], chunk, metadata["size"]
        )
        metadata.update({"offset": offset, "spool_size": spool_size})
        self._write_metadata(paths[1], metadata)
        return metadata

    def materialize(self, tenant: str, paths: tuple[Path, Path], metadata: dict[str, Any]) -> bytes:
        data, spool_size = read_frames(
            paths[0], self.keys, tenant, metadata["size"], repair_tail=False
        )
        if len(data) != metadata["offset"] or spool_size != metadata["spool_size"]:
            raise ValueError("encrypted upload metadata does not match its frames")
        return data

    @staticmethod
    def cleanup(paths: tuple[Path, Path]) -> None:
        for path in paths:
            path.unlink(missing_ok=True)

    def lock_count(self) -> int:
        with self._guard:
            return len(self._entries)
