"""Require release archives to contain exactly the intended tracked files."""

from __future__ import annotations

import argparse
import stat
import subprocess
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

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


def _parts(name: str) -> tuple[str, ...]:
    if not name or "\\" in name:
        raise InventoryError(f"unsafe archive path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise InventoryError(f"unsafe archive path: {name!r}")
    return path.parts


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


def check_sdist(path: Path, tracked: set[str], project: str, version: str) -> None:
    expected_root = f"{project}-{version}"
    names: list[str] = []
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
            names.append("/".join(parts[1:]))
    if len(names) != len(set(names)):
        raise InventoryError("sdist contains duplicate paths")
    _difference(set(names), tracked | {"PKG-INFO"})


def check_wheel(path: Path, tracked: set[str], project: str, version: str) -> None:
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
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            _parts(member.filename)
            if member.is_dir():
                continue
            kind = (member.external_attr >> 16) & 0o170000
            if kind and not stat.S_ISREG(kind):
                raise InventoryError(f"wheel member is not a regular file: {member.filename}")
            names.append(member.filename)
    if len(names) != len(set(names)):
        raise InventoryError("wheel contains duplicate paths")
    _difference(set(names), expected)


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
        for artifact in artifacts:
            if artifact.name.endswith(".tar.gz"):
                check_sdist(artifact, tracked, project, version)
            elif artifact.suffix == ".whl":
                check_wheel(artifact, tracked, project, version)
            else:
                raise InventoryError(f"unsupported release artifact: {artifact}")
            print(f"release inventory passed: {artifact}")
    except (InventoryError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"release inventory check failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
