#!/usr/bin/env python3
"""Run the Ubuntu GitHub Actions preflight in local Docker containers."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PYTHONS = ("3.11", "3.12", "3.13")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python",
        dest="pythons",
        action="append",
        metavar="VERSION",
        help=(
            "Python version to test. Repeat for multiple versions. "
            "Defaults to 3.11, 3.12, and 3.13."
        ),
    )
    return parser.parse_args()


def docker_command() -> str:
    docker = shutil.which("docker")
    if docker is None:
        raise SystemExit(
            "Docker is required for this preflight, but the docker executable was not found."
        )

    result = subprocess.run(
        [docker, "version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        details = (result.stderr or result.stdout).strip()
        message = "Docker is installed, but it is not available."
        if details:
            message = f"{message}\n{details}"
        raise SystemExit(message)

    return docker


def container_script() -> str:
    return """
set -euo pipefail
python --version
python -m venv /tmp/uv-bootstrap
/tmp/uv-bootstrap/bin/python -m pip install --disable-pip-version-check --no-input uv
export PATH="/tmp/uv-bootstrap/bin:$PATH"
uv --version
uv sync --extra dev
uv run ruff check .
uv run ruff format --check .
uv run pytest tests -m "not live and not live_harness" -v -o cache_dir=/tmp/pytest-cache
uv build --sdist --wheel --out-dir "$OPENTINE_WHEEL_SMOKE_DIST"
uv run python scripts/wheel_smoke.py
""".strip()


def user_args() -> list[str]:
    if hasattr(os, "getuid") and hasattr(os, "getgid"):
        return ["--user", f"{os.getuid()}:{os.getgid()}"]
    return []


def run_for_python(docker: str, version: str) -> int:
    label = version.replace(".", "-")
    image = f"python:{version}-bookworm"
    print(f"==> Running Ubuntu preflight with {image}", flush=True)

    cmd = [
        docker,
        "run",
        "--rm",
        *user_args(),
        "--workdir",
        "/work",
        "--mount",
        f"type=bind,source={ROOT},target=/work",
        "-e",
        f"UV_PROJECT_ENVIRONMENT=/tmp/opentine-venv-{label}",
        "-e",
        f"UV_CACHE_DIR=/tmp/uv-cache-{label}",
        "-e",
        f"RUFF_CACHE_DIR=/tmp/ruff-cache-{label}",
        "-e",
        f"PYTHONPYCACHEPREFIX=/tmp/pycache-{label}",
        "-e",
        f"OPENTINE_WHEEL_SMOKE_DIST=/tmp/opentine-dist-{label}",
        "-e",
        "HOME=/tmp",
        image,
        "bash",
        "-lc",
        container_script(),
    ]
    return subprocess.run(cmd, check=False).returncode


def main() -> int:
    args = parse_args()
    versions = args.pythons or list(DEFAULT_PYTHONS)
    docker = docker_command()

    failures: list[str] = []
    for version in versions:
        if run_for_python(docker, version) != 0:
            failures.append(version)

    if failures:
        print(f"Docker preflight failed for Python: {', '.join(failures)}", file=sys.stderr)
        return 1

    print("Docker preflight passed for Python: " + ", ".join(versions))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
