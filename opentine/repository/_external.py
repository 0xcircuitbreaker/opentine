"""External blob pointers ``{uri, sha256, size}`` (0.40; SPEC §2.10).

A large artifact can stay in object storage, on a shared disk or behind an
HTTPS URL: the repository keeps a *pointer* for the blob oid it stands for, in
the side table ``external/<64 hex>.json``. The blob's oid is unchanged (it is
still ``object_id("blob", 1, content)``), so runs link it like any blob, and a
reader that predates 0.40 simply sees the blob as absent.

The pointer is never trusted: :func:`resolve` reads at most ``size`` bytes
from an allowlisted location, checks ``size`` and ``sha256``, then that the
content hashes to the oid, and only then stores the blob locally.
:func:`status` is the offline check: it never opens a URI and reports a
pointer whose content is not stored locally as ``unresolved``.

Allowed locations are URI prefixes from ``config.json``
(``"external_blobs": {"allow": ["https://host/path/", "file:///dir/"]}``) or
the caller; nothing is fetched without one (no SSRF by default). Redirects are
not followed and userinfo, ``..`` segments and backslashes are refused.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

from opentine.kernel import KernelError, ObjectEnvelope, canonical_json, object_id, parse_oid
from opentine.repository._config import read_config
from opentine.repository._packs import MAX_OBJECT_BYTES
from opentine.repository._paths import atomic_bytes, internal_path

_SHA = re.compile(r"^[0-9a-f]{64}$")
_SCHEMES = ("file", "https", "http")
_CHUNK = 1 << 20


class ExternalError(KernelError):
    """A pointer is malformed, not allowed, or its content does not verify."""


@dataclass(frozen=True)
class Pointer:
    oid: str
    uri: str
    sha256: str
    size: int

    def encode(self) -> bytes:
        body = {"oid": self.oid, "sha256": self.sha256, "size": self.size, "uri": self.uri}
        return canonical_json({**body, "version": 1}) + b"\n"


def _blob_digest(oid: str) -> str:
    object_type, digest = parse_oid(oid)
    if object_type != "blob":
        raise ExternalError("only a blob can be stored externally")
    return digest


def _path(root: Path, oid: str) -> Path:
    return internal_path(root, "external", f"{_blob_digest(oid)}.json")


def _check(pointer: Pointer) -> Pointer:
    _blob_digest(pointer.oid)
    if not _SHA.fullmatch(pointer.sha256):
        raise ExternalError("external pointer sha256 must be 64 lowercase hex")
    if type(pointer.size) is not int or not 0 <= pointer.size <= MAX_OBJECT_BYTES:
        raise ExternalError("external pointer size is out of range")
    parts = urlsplit(pointer.uri)
    if parts.scheme not in _SCHEMES or parts.username or parts.password or "\\" in pointer.uri:
        raise ExternalError("external pointer uri is not a plain file/https uri")
    if any(segment in (".", "..") for segment in unquote(parts.path).split("/")):
        raise ExternalError("external pointer uri has a dot segment")
    return pointer


def add(root: Path, uri: str, source: bytes | Path) -> Pointer:
    """Record *source* (bytes or a local file) as stored at *uri*; the pointer.

    The content is hashed here, never stored; it is not redacted (§2.10).
    """
    sha, size = hashlib.sha256(), 0
    oid_hash = hashlib.sha256(b"blob\0" + b"1\0")
    chunks = [source] if isinstance(source, bytes) else _file_chunks(Path(source), None)
    for chunk in chunks:
        sha.update(chunk)
        oid_hash.update(chunk)
        size += len(chunk)
    oid = f"blob:sha256:{oid_hash.hexdigest()}"
    pointer = _check(Pointer(oid, uri, sha.hexdigest(), size))
    atomic_bytes(_path(root, oid), pointer.encode())
    return pointer


def load(root: Path, oid: str) -> Pointer | None:
    """The pointer recorded for *oid*, or ``None``; a malformed one raises."""
    try:
        raw = _path(root, oid).read_bytes()
    except FileNotFoundError:
        return None
    try:
        data = json.loads(raw[:4096])
        pointer = Pointer(data["oid"], data["uri"], data["sha256"], data["size"])
    except (ValueError, KeyError, TypeError) as exc:
        raise ExternalError("external pointer is malformed") from exc
    if pointer.oid != oid or data.get("version") != 1 or not isinstance(pointer.uri, str):
        raise ExternalError("external pointer does not match its blob")
    return _check(pointer)


def known(repo, oid: str) -> bool:
    """Whether *oid* is a blob with a recorded pointer (a link to it is valid)."""
    try:
        return oid.startswith("blob:") and _path(repo.path, oid).is_file()
    except KernelError:
        return False


def pointers(root: Path) -> list[str]:
    try:
        names = sorted(os.listdir(internal_path(root, "external")))
    except FileNotFoundError:
        return []
    return [f"blob:sha256:{n[:64]}" for n in names if n.endswith(".json") and _SHA.match(n[:64])]


def allowed_prefixes(root: Path) -> tuple[str, ...]:
    try:
        setting = read_config(internal_path(root, "config.json")).get("external_blobs")
    except (OSError, ValueError):
        return ()
    allow = setting.get("allow") if isinstance(setting, dict) else None
    return tuple(item for item in allow or () if isinstance(item, str))


def _permitted(uri: str, allow: tuple[str, ...]) -> bool:
    for prefix in allow:
        head = urlsplit(prefix)
        if head.scheme in _SCHEMES and prefix.endswith("/") and uri.startswith(prefix):
            return True
    return False


def _file_chunks(path: Path, limit: int | None):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ExternalError("external content is not a regular file")
        read = 0
        while chunk := handle.read(_CHUNK):
            read += len(chunk)
            if limit is not None and read > limit:
                raise ExternalError("external content is larger than its pointer says")
            yield chunk


def _local_file(uri: str, allow: tuple[str, ...]) -> Path:
    path = Path(url2pathname(urlsplit(uri).path))
    real = os.path.normcase(os.path.realpath(path))
    for prefix in allow:
        if urlsplit(prefix).scheme == "file" and uri.startswith(prefix):
            base = os.path.normcase(os.path.realpath(url2pathname(urlsplit(prefix).path)))
            if os.path.commonpath([real, base]) == base:
                return path
    raise ExternalError("external file resolves outside its allowed directory")


def _download(uri: str, limit: int, timeout: float):
    import httpx

    with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        with client.stream("GET", uri) as response:
            if response.status_code != 200:
                raise ExternalError(f"external fetch failed with HTTP {response.status_code}")
            declared = response.headers.get("content-length")
            if declared is not None and (not declared.isdigit() or int(declared) > limit):
                raise ExternalError("external content is larger than its pointer says")
            read = 0
            for chunk in response.iter_raw():
                read += len(chunk)
                if read > limit:
                    raise ExternalError("external content is larger than its pointer says")
                yield chunk


def resolve(
    repo, oid: str, *, allow: tuple[str, ...] | None = None, timeout: float = 30.0
) -> bytes:
    """Fetch, verify and store the blob *oid* points at; its canonical bytes."""
    from opentine.repository._storage import object_exists, read_object, write_loose

    if object_exists(repo, oid):
        return read_object(repo, oid)
    pointer = load(repo.path, oid)
    if pointer is None:
        raise KeyError(oid)
    allow = allowed_prefixes(repo.path) if allow is None else tuple(allow)
    if not _permitted(pointer.uri, allow):
        raise ExternalError("external pointer uri is not in the allowed locations")
    if urlsplit(pointer.uri).scheme == "file":
        chunks = _file_chunks(_local_file(pointer.uri, allow), pointer.size)
    else:
        chunks = _download(pointer.uri, pointer.size, timeout)
    content = b"".join(chunks)
    if len(content) != pointer.size:
        raise ExternalError("external content size does not match its pointer")
    if hashlib.sha256(content).hexdigest() != pointer.sha256:
        raise ExternalError("external content sha256 does not match its pointer")
    if object_id("blob", 1, content) != oid:
        raise ExternalError("external content does not hash to its blob id")
    raw = ObjectEnvelope.create("blob", content).encode()
    write_loose(repo, oid, raw)
    return raw


def status(repo) -> dict[str, str]:
    """Offline: ``resolved`` (stored locally) or ``unresolved``, per pointer; no I/O
    beyond the repository, never a URI. A malformed pointer is ``invalid``."""
    from opentine.repository._storage import object_exists

    report: dict[str, str] = {}
    for oid in pointers(repo.path):
        try:
            load(repo.path, oid)
        except (KernelError, OSError):
            report[oid] = "invalid"
            continue
        report[oid] = "resolved" if object_exists(repo, oid) else "unresolved"
    return report
