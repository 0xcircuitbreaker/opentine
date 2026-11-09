"""An in-memory ``BlobClient`` that behaves like S3 Object Lock / Azure WORM."""

from __future__ import annotations

import datetime

from opentine.remote._worm import COMPLIANCE, BlobRetention, RetentionLocked


class FakeBlobClient:
    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.locks: dict[str, BlobRetention] = {}
        self.gets: list[str] = []
        self.deletes: list[str] = []

    def put(self, key, data, *, mode, until, legal_hold) -> None:
        current = self.locks.get(key)
        if key in self.blobs and current is not None and current.locked():
            raise RetentionLocked(f"cannot overwrite {key}")
        self.blobs[key] = bytes(data)
        self.locks[key] = BlobRetention(mode, until, legal_hold)

    def get(self, key):
        self.gets.append(key)
        try:
            return self.blobs[key]
        except KeyError:
            raise KeyError(key) from None

    def exists(self, key):
        return key in self.blobs

    def keys(self, prefix):
        return iter(sorted(k for k in self.blobs if k.startswith(prefix)))

    def retention(self, key):
        if key not in self.blobs:
            raise KeyError(key)
        return self.locks[key]

    def delete(self, key):
        if self.retention(key).locked():  # the cloud's own refusal
            raise RetentionLocked(f"{key} is locked")
        self.deletes.append(key)
        del self.blobs[key]
        del self.locks[key]

    def set_legal_hold(self, key, on):
        state = self.retention(key)
        self.locks[key] = BlobRetention(state.mode, state.until, on)

    def expire(self, key: str) -> None:
        """Move *key*'s retention date into the past (time passing)."""
        state = self.locks[key]
        past = datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC)
        self.locks[key] = BlobRetention(state.mode, past, state.legal_hold)

    def shorten(self, key: str) -> None:
        """A governance bypass: allowed for governance, refused for compliance."""
        if self.locks[key].mode == COMPLIANCE:
            raise RetentionLocked("compliance retention cannot be shortened")
        self.expire(key)
