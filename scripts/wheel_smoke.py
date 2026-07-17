"""Install the built wheel in a clean venv and smoke-test the public CLI."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _dist_dir() -> Path:
    configured = os.environ.get("OPENTINE_WHEEL_SMOKE_DIST")
    if not configured:
        return ROOT / "dist"

    path = Path(configured)
    if not path.is_absolute():
        path = ROOT / path
    return path


DIST = _dist_dir()


def _venv_python(venv_dir: Path) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _console_script(venv_dir: Path, name: str) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / f"{name}.exe"
    return venv_dir / "bin" / name


def _run(cmd: list[str | Path], *, cwd: Path | None = None) -> None:
    rendered = " ".join(str(part) for part in cmd)
    print(f"+ {rendered}")
    subprocess.run([str(part) for part in cmd], cwd=cwd, check=True)


def _install_locked_core(python: Path, wheel: Path, work: Path) -> None:
    uv = shutil.which("uv")
    if uv is None:
        raise SystemExit("uv is required for the hash-locked wheel smoke test")
    requirements = work / "core-requirements.txt"
    _run(
        [
            uv,
            "export",
            "--frozen",
            "--no-dev",
            "--no-emit-project",
            "--format",
            "requirements-txt",
            "--output-file",
            requirements,
        ],
        cwd=ROOT,
    )
    _run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--only-binary=:all:",
            "--require-hashes",
            "-r",
            requirements,
        ]
    )
    _run([python, "-m", "pip", "install", "--no-deps", wheel])


def main() -> None:
    wheels = sorted(DIST.glob("opentine-*.whl"))
    if not wheels:
        raise SystemExit(f"No wheel found in {DIST}")
    wheel = wheels[-1]
    # Version-agnostic: assert the installed package matches the built wheel's
    # own version (parsed from "opentine-<version>-py3-none-any.whl") so a
    # version bump never requires editing this smoke test.
    wheel_version = wheel.name.split("-")[1]

    with tempfile.TemporaryDirectory(prefix="opentine-wheel-smoke-") as tmp:
        work = Path(tmp)
        venv_dir = work / "venv"
        venv.EnvBuilder(with_pip=True).create(venv_dir)
        python = _venv_python(venv_dir)
        tine = _console_script(venv_dir, "tine")
        artifact = work / "smoke.tine"

        _install_locked_core(python, wheel, work)
        _run([python, "-m", "pip", "check"])
        _run(
            [
                python,
                "-c",
                f"import opentine; assert opentine.__version__ == {wheel_version!r}, "
                f"opentine.__version__",
            ]
        )
        _run([tine, "--help"])
        _run(
            [
                python,
                "-c",
                (
                    "from opentine import Run, StepKind; "
                    "run = Run(id='wheel-smoke'); "
                    "run.add_step(StepKind.done, {'text': 'ok'}); "
                    f"run.save({str(artifact)!r})"
                ),
            ]
        )
        _run([tine, "verify", artifact])
        _run([tine, "pricing", "check"])
        repository = work / "repo"
        _run([tine, "init", repository])
        _run(
            [
                python,
                "-c",
                (
                    "from opentine import Repo; "
                    f"r=Repo.open({str(repository)!r}); "
                    "oid=r.put('blob', b'wheel'); "
                    "assert r.get(oid).body == b'wheel'; assert r.fsck().ok"
                ),
            ]
        )


if __name__ == "__main__":
    main()
