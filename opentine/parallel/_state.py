"""The resumable record of one fan-out, kept at ``<state-dir>/<id>.json``.

Written atomically after every member event, so a coordinator killed at any
point leaves a record ``--resume`` can trust as far as it goes: members whose
status is ``ok`` or ``failed`` are finished; everything else is run again. The
record is read back strictly -- a malformed or tampered file is refused, never
half-used -- and it holds no command: ``--resume`` takes the command again and
must match the recorded digest, so a planted record cannot choose what runs.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import threading
from pathlib import Path

from opentine.parallel._executor import STATUSES
from opentine.parallel._matrix import MAX_VALUE_CHARS, VARY_KEY

STATE_FORMAT = "opentine-fanout-state/1"
FANOUT_ID = re.compile(r"^[0-9a-f]{12}$")
MAX_STATE_BYTES = 16 * 1024 * 1024
_FIELDS = {"budget", "command_digest", "format", "id", "members", "source", "spent"}
_MEMBER = {"cost", "key", "ref", "returncode", "run", "status", "vary"}


def new_id() -> str:
    return secrets.token_hex(6)


def _str_or_none(value: object, limit: int = 512) -> bool:
    return value is None or (isinstance(value, str) and len(value) <= limit)


def validate(data: object, fanout_id: str) -> dict:
    if not isinstance(data, dict) or set(data) != _FIELDS:
        raise ValueError("fan-out state has the wrong fields")
    if data["format"] != STATE_FORMAT or data["id"] != fanout_id:
        raise ValueError("fan-out state format or id mismatch")
    if not isinstance(data["command_digest"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", data["command_digest"]
    ):
        raise ValueError("fan-out state command digest is malformed")
    if not _str_or_none(data["budget"], 64) or not isinstance(data["source"], dict):
        raise ValueError("fan-out state budget or source is malformed")
    spent = data["spent"]
    if not isinstance(spent, dict) or not all(
        isinstance(k, str) and _str_or_none(v, 64) for k, v in spent.items()
    ):
        raise ValueError("fan-out state ledger is malformed")
    members = data["members"]
    if not isinstance(members, list) or not 1 <= len(members) <= 1000:
        raise ValueError("fan-out state members are malformed")
    for position, member in enumerate(members):
        if not isinstance(member, dict) or set(member) != _MEMBER:
            raise ValueError("fan-out state member has the wrong fields")
        if member["key"] != str(position) or member["status"] not in STATUSES:
            raise ValueError("fan-out state member key or status is malformed")
        vary = member["vary"]
        if not isinstance(vary, dict) or not all(
            isinstance(k, str)
            and VARY_KEY.fullmatch(k)
            and isinstance(v, str)
            and 0 < len(v) <= MAX_VALUE_CHARS
            and "\x00" not in v
            for k, v in vary.items()
        ):
            raise ValueError("fan-out state member variation is malformed")
        if not all(_str_or_none(member[name]) for name in ("cost", "ref", "run")):
            raise ValueError("fan-out state member fields are malformed")
        code = member["returncode"]
        if code is not None and (type(code) is not int or abs(code) > 2**31):
            raise ValueError("fan-out state member return code is malformed")
    return data


class State:
    def __init__(self, directory: Path, data: dict):
        self.directory = directory
        self.data = data
        self._lock = threading.Lock()

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def path(self) -> Path:
        return self.directory / f"{self.id}.json"

    def cost_file(self, key: str) -> Path:
        folder = self.directory / self.id
        folder.mkdir(parents=True, exist_ok=True)
        return folder / f"{key}.cost"

    @classmethod
    def create(cls, directory: Path, **fields) -> State:
        data = {"format": STATE_FORMAT, "spent": {}, **fields}
        state = cls(directory, validate(data, data["id"]))
        if state.path.exists():
            raise ValueError(f"fan-out {state.id} already exists")
        state.save()
        return state

    @classmethod
    def load(cls, directory: Path, fanout_id: str) -> State:
        if not FANOUT_ID.fullmatch(fanout_id or ""):
            raise ValueError(f"not a fan-out id: {fanout_id!r}")
        path = directory / f"{fanout_id}.json"
        if path.is_symlink():
            raise ValueError("fan-out state is a symlink")
        try:
            with open(path, "rb") as handle:
                raw = handle.read(MAX_STATE_BYTES + 1)
        except FileNotFoundError:
            raise ValueError(f"no fan-out {fanout_id} in {directory}") from None
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError("fan-out state exceeds its size limit")
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise ValueError("fan-out state is not JSON") from exc
        return cls(directory, validate(data, fanout_id))

    def update(self, key: str, spent: dict[str, str], **fields) -> None:
        with self._lock:
            self.data["members"][int(key)].update(fields)
            self.data["spent"] = dict(spent)
            self.save()

    def save(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(self.data, sort_keys=True, indent=1).encode()
        fd, temporary = tempfile.mkstemp(dir=self.directory, prefix=f".{self.id}.")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            Path(temporary).unlink(missing_ok=True)


__all__ = ["FANOUT_ID", "STATE_FORMAT", "State", "new_id", "validate"]
