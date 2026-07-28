"""Release automation must preserve least privilege and artifact identity."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTION = re.compile(r"uses:\s+[^\s@]+@([^\s#]+)")


def _workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def test_actions_are_pinned_to_full_commit_ids():
    for name in ("ci.yml", "publish.yml"):
        revisions = ACTION.findall(_workflow(name))
        assert revisions
        assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for revision in revisions)


def test_publish_reuses_one_validated_distribution_pair():
    workflow = _workflow("publish.yml")
    assert workflow.count("uv build --no-build-isolation --sdist") == 1
    assert workflow.count("uv build --no-build-isolation --wheel") == 1
    assert "uv build --no-build-isolation --wheel dist/opentine-*.tar.gz" in workflow
    assert workflow.count("name: opentine-release-distributions") == 3
    assert "needs: [build, github-release]" in workflow
    assert "packages-dir: dist" in workflow
    assert workflow.count("uv build --no-build-isolation") == 2
    assert "GH_REPO: ${{ github.repository }}" in workflow


def test_pypi_trusted_publishing_is_environment_gated_and_tokenless():
    workflow = _workflow("publish.yml")
    assert "\npermissions: {}\n" in workflow
    pypi = workflow.split("\n  pypi:\n", 1)[1]
    assert "name: pypi" in pypi
    assert "id-token: write" in pypi
    assert "gh-action-pypi-publish@" in pypi
    assert "password:" not in workflow
    assert "api-token" not in workflow
    build = workflow.split("\n  build:\n", 1)[1].split("\n  github-release:\n", 1)[0]
    assert "id-token: write" not in build


def test_release_build_disables_mutable_dependency_caches():
    workflow = _workflow("publish.yml")
    build = workflow.split("\n  build:\n", 1)[1].split("\n  github-release:\n", 1)[0]
    assert "enable-cache: false" in build


def test_tag_release_requires_successful_main_ci_for_exact_commit():
    workflow = _workflow("publish.yml")
    build = workflow.split("\n  build:\n", 1)[1].split("\n  github-release:\n", 1)[0]
    assert "actions: read" in build
    assert "actions/workflows/ci.yml/runs?branch=main" in build
    assert "head_sha=$RELEASE_COMMIT" in build
    assert 'select(.conclusion == "success")' in build
    assert 'UV_PYTHON: "3.14.4"' in build


def test_release_toolchain_is_locked_and_sdist_carries_the_lock():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["build-system"]["requires"] == ["hatchling==1.31.0"]
    assert project["project"]["requires-python"] == ">=3.11,<3.15"
    assert "hatchling==1.31.0" in project["project"]["optional-dependencies"]["dev"]
    assert "/uv.lock" in project["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    assert "uv.lock" not in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for name in ("ci.yml", "publish.yml"):
        workflow = _workflow(name)
        assert "uv sync --locked --all-extras" in workflow
        assert "uv build --no-build-isolation" in workflow
    assert "UV_PYTHON: ${{ matrix.python-version }}" in _workflow("ci.yml")
