"""Require release archives to contain exactly the intended tracked files."""

from __future__ import annotations

import argparse
import hashlib
import stat
import subprocess
import tarfile
import tomllib
import zipfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import BinaryIO

ROOT = Path(__file__).resolve().parents[1]


class InventoryError(ValueError):
    pass


def _project() -> tuple[str, str]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    return str(project["name"]), str(project["version"])


def _tracked() -> set[str]:
    output = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        check=True,
        capture_output=True,
    ).stdout
    return {item.decode("utf-8") for item in output.split(b"\0") if item}


_CHUNK = 1024 * 1024


def _digest(stream: BinaryIO) -> bytes:
    value = hashlib.sha256()
    while chunk := stream.read(_CHUNK):
        value.update(chunk)
    return value.digest()


def _digest_pair(stream: BinaryIO, chunk_size: int = _CHUNK) -> tuple[bytes, bytes]:
    """Return (raw sha256, sha256 of the bytes with CRLF normalized to LF).

    The normalized digest is diagnostic only — the gate passes or fails on the
    raw digest, because content fidelity is the point of the check.  It lets
    the error message say when a mismatch is pure line-ending skew (a CRLF
    working tree vs the LF object database) instead of real content drift.
    """
    raw = hashlib.sha256()
    normalized = hashlib.sha256()
    pending_cr = False
    while chunk := stream.read(chunk_size):
        raw.update(chunk)
        if pending_cr:
            chunk = b"\r" + chunk
        pending_cr = chunk.endswith(b"\r")
        if pending_cr:
            chunk = chunk[:-1]
        normalized.update(chunk.replace(b"\r\n", b"\n"))
    if pending_cr:
        normalized.update(b"\r")
    return raw.digest(), normalized.digest()


def _source_hashes(tracked: set[str]) -> dict[str, bytes]:
    hashes: dict[str, bytes] = {}
    for name in sorted(tracked):
        try:
            body = subprocess.run(
                ["git", "-C", str(ROOT), "show", f"HEAD:{name}"],
                check=True,
                capture_output=True,
            ).stdout
        except subprocess.CalledProcessError as exc:
            raise InventoryError(f"cannot read tracked source from HEAD: {name}") from exc
        hashes[name] = hashlib.sha256(body).digest()
    return hashes


def _parts(name: str) -> tuple[str, ...]:
    if not name or "\\" in name:
        raise InventoryError(f"unsafe archive path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise InventoryError(f"unsafe archive path: {name!r}")
    return path.parts


def _content_mismatch(
    mismatched: list[str],
    normalized: Mapping[str, bytes],
    source_hashes: Mapping[str, bytes],
) -> str:
    message = "sdist content differs from source: " + ", ".join(mismatched)
    eol_only = [name for name in mismatched if normalized[name] == source_hashes[name]]
    if eol_only:
        message += (
            f" [{len(eol_only)} of {len(mismatched)} differ only in CRLF vs LF line endings:"
            " the working tree was materialized with CRLF (e.g. core.autocrlf=true) while git"
            " stores LF; make sure .gitattributes pins 'eol=lf' and re-checkout before building]"
        )
    return message


def _difference(actual: set[str], expected: set[str]) -> None:
    extra = sorted(actual - expected)
    missing = sorted(expected - actual)
    if extra or missing:
        details = []
        if extra:
            details.append("unexpected: " + ", ".join(extra))
        if missing:
            details.append("missing: " + ", ".join(missing))
        raise InventoryError("; ".join(details))


def check_sdist(
    path: Path,
    tracked: set[str],
    project: str,
    version: str,
    *,
    source_hashes: Mapping[str, bytes] | None = None,
) -> dict[str, bytes]:
    expected_root = f"{project}-{version}"
    names: list[str] = []
    hashes: dict[str, bytes] = {}
    normalized: dict[str, bytes] = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            parts = _parts(member.name)
            if parts[0] != expected_root:
                raise InventoryError(f"unexpected sdist root: {parts[0]!r}")
            if member.isdir():
                continue
            if not member.isfile():
                raise InventoryError(f"sdist member is not a regular file: {member.name}")
            if len(parts) < 2:
                raise InventoryError(f"sdist file is outside its root: {member.name}")
            name = "/".join(parts[1:])
            stream = archive.extractfile(member)
            if stream is None:
                raise InventoryError(f"cannot read sdist member: {member.name}")
            names.append(name)
            hashes[name], normalized[name] = _digest_pair(stream)
    if len(names) != len(set(names)):
        raise InventoryError("sdist contains duplicate paths")
    _difference(set(names), tracked | {"PKG-INFO"})
    if source_hashes is not None:
        mismatched = sorted(name for name in tracked if hashes[name] != source_hashes[name])
        if mismatched:
            raise InventoryError(_content_mismatch(mismatched, normalized, source_hashes))
    return hashes


def check_wheel(
    path: Path,
    tracked: set[str],
    project: str,
    version: str,
    *,
    sdist_hashes: Mapping[str, bytes] | None = None,
) -> None:
    dist_info = f"{project.replace('-', '_')}-{version}.dist-info"
    generated = {
        f"{dist_info}/METADATA",
        f"{dist_info}/RECORD",
        f"{dist_info}/WHEEL",
        f"{dist_info}/entry_points.txt",
        f"{dist_info}/licenses/LICENSE",
    }
    expected = {name for name in tracked if name.startswith("opentine/")} | generated
    names: list[str] = []
    hashes: dict[str, bytes] = {}
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            _parts(member.filename)
            if member.is_dir():
                continue
            kind = (member.external_attr >> 16) & 0o170000
            if kind and not stat.S_ISREG(kind):
                raise InventoryError(f"wheel member is not a regular file: {member.filename}")
            names.append(member.filename)
            with archive.open(member) as stream:
                hashes[member.filename] = _digest(stream)
    if len(names) != len(set(names)):
        raise InventoryError("wheel contains duplicate paths")
    _difference(set(names), expected)
    if sdist_hashes is not None:
        package = sorted(name for name in expected if name.startswith("opentine/"))
        mismatched = [name for name in package if hashes[name] != sdist_hashes[name]]
        if mismatched:
            raise InventoryError("wheel content differs from sdist: " + ", ".join(mismatched))


def release_artifacts(paths: list[Path]) -> list[Path]:
    artifacts: list[Path] = []
    for path in paths:
        if path.is_dir():
            artifacts.extend(sorted(path.glob("*.whl")))
            artifacts.extend(sorted(path.glob("*.tar.gz")))
        else:
            artifacts.append(path)
    wheels = [path for path in artifacts if path.suffix == ".whl"]
    sdists = [path for path in artifacts if path.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1 or len(artifacts) != 2:
        raise InventoryError(
            "release must contain exactly one wheel and one sdist "
            f"(found {len(wheels)} wheel, {len(sdists)} sdist, {len(artifacts)} total)"
        )
    return [*sdists, *wheels]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args(argv)
    project, version = _project()
    tracked = _tracked()
    try:
        artifacts = release_artifacts(args.artifacts)
        source_hashes = _source_hashes(tracked)
        sdist_hashes: dict[str, bytes] | None = None
        for artifact in artifacts:
            if artifact.name.endswith(".tar.gz"):
                sdist_hashes = check_sdist(
                    artifact,
                    tracked,
                    project,
                    version,
                    source_hashes=source_hashes,
                )
            elif artifact.suffix == ".whl":
                check_wheel(
                    artifact,
                    tracked,
                    project,
                    version,
                    sdist_hashes=sdist_hashes,
                )
            else:
                raise InventoryError(f"unsupported release artifact: {artifact}")
            print(f"release inventory passed: {artifact}")
    except (InventoryError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"release inventory check failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
