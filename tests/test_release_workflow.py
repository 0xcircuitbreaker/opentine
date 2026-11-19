"""Release automation must preserve least privilege and artifact identity."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ACTION = re.compile(r"uses:\s+[^\s@]+@([^\s#]+)")


def _workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def test_actions_are_pinned_to_full_commit_ids():
    for name in ("ci.yml", "publish.yml", "release-on-green.yml"):
        revisions = ACTION.findall(_workflow(name))
        assert revisions or name == "release-on-green.yml"
        assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for revision in revisions)


def test_publish_reuses_one_validated_distribution_pair():
    workflow = _workflow("publish.yml")
    assert workflow.count("uv build --no-build-isolation --sdist") == 1
    assert workflow.count("uv build --no-build-isolation --wheel") == 1
    assert "uv build --no-build-isolation --wheel dist/opentine-*.tar.gz" in workflow
    assert workflow.count("name: opentine-release-distributions") == 4
    assert "needs: [build, artifact-smoke, github-release]" in workflow
    assert "packages-dir: dist" in workflow
    assert workflow.count("uv build --no-build-isolation") == 2
    assert "GH_REPO: ${{ github.repository }}" in workflow


def test_release_artifacts_are_installed_on_every_os_before_publishing():
    # 0.17: the exact files about to be released are installed and smoke-tested
    # on Linux, macOS and Windows; the GitHub release and PyPI both wait on it.
    workflow = _workflow("publish.yml")
    smoke = workflow.split("\n  artifact-smoke:\n", 1)[1].split("\n  github-release:\n", 1)[0]
    assert "os: [ubuntu-24.04, macos-latest, windows-latest]" in smoke
    assert "OPENTINE_WHEEL_SMOKE_DIST: release-dist" in smoke
    assert "scripts/wheel_smoke.py" in smoke
    assert "id-token" not in smoke and "contents: write" not in smoke
    assert "needs: [build, artifact-smoke]" in workflow


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


def _release_subject_regex() -> re.Pattern[str]:
    # Extract the bash regex from release-on-green.yml and translate the bash
    # escaped spaces into a Python pattern, so the test checks the shipped one.
    workflow = _workflow("release-on-green.yml")
    match = re.search(r'\[\[ ! "\$subject" =~ (\S+\\ —\\ ) \]\]', workflow)
    assert match, "release subject regex not found"
    return re.compile(match.group(1).replace("\\ ", " "))


def test_release_on_green_runs_only_after_ci_on_main_with_least_privilege():

    workflow = _workflow("release-on-green.yml")
    data = yaml.safe_load(workflow)
    triggers = data[True]  # YAML 1.1 parses the `on` key as True
    assert set(triggers) == {"workflow_run"}
    run = triggers["workflow_run"]
    assert run["workflows"] == ["CI"]
    assert run["types"] == ["completed"]
    assert run["branches"] == ["main"]
    assert "pull_request" not in workflow and "pull_request_target" not in workflow
    assert data["permissions"] == {}
    (job,) = data["jobs"].values()
    assert job["permissions"] == {"contents": "write", "actions": "write"}
    condition = job["if"]
    assert "vars.AUTO_RELEASE != 'false'" in condition
    assert "github.event.workflow_run.conclusion == 'success'" in condition
    assert "github.event.workflow_run.event == 'push'" in condition
    assert "head_repository.full_name == github.repository" in condition
    assert "actions/checkout" not in workflow
    for step in job["steps"]:
        assert "${{" not in step.get("run", "")
    assert "contents/opentine/_version.py?ref=$HEAD_SHA" in workflow
    assert "contents/pyproject.toml?ref=$HEAD_SHA" in workflow
    assert "actions/workflows/ci.yml/runs?branch=main&event=push" in workflow
    assert 'message="opentine $VERSION"' in workflow
    assert 'gh workflow run publish.yml --ref "$TAG" -f tag="$TAG"' in workflow


def test_release_subject_regex():
    pattern = _release_subject_regex()
    match = pattern.match("0.55.0 — Code mirror and review runner (#109)")
    assert match and match.group(1) == "0.55.0"
    assert not pattern.match("0.55.0 - x")
    assert not pattern.match("Fix 0.55.0 — x")


def test_publish_accepts_tag_push_and_dispatch_and_keeps_id_token_scoped():

    data = yaml.safe_load(_workflow("publish.yml"))
    triggers = data[True]
    assert set(triggers) == {"push", "workflow_dispatch"}
    assert triggers["push"]["tags"] == ["v*"]
    assert triggers["workflow_dispatch"]["inputs"]["tag"]["required"] is True
    assert "inputs.tag" in data["env"]["RELEASE_TAG"]
    assert "github.ref_name" in data["env"]["RELEASE_TAG"]
    workflow = _workflow("publish.yml")
    assert "GITHUB_REF_NAME" not in workflow
    assert 'test "$GITHUB_REF" = "refs/tags/$RELEASE_TAG"' in workflow
    holders = {
        name for name, job in data["jobs"].items() if "id-token" in job.get("permissions", {})
    }
    assert holders == {"github-release", "pypi"}
    assert data["jobs"]["pypi"]["environment"]["name"] == "pypi"


_FAKE_GH = """#!/usr/bin/env bash
# Stub gh for the decide step: answers from FAKE_* environment variables.
args="$*"
case "$args" in
  *contents/pyproject.toml*) printf 'version = "%s"\\n' "$FAKE_PY" ;;
  *contents/opentine/_version.py*) printf '__version__ = "%s"\\n' "$FAKE_MOD" ;;
  *compare/*) echo identical ;;
  *git/ref/tags/*) [[ -n "${FAKE_TAG_EXISTS:-}" ]] && exit 0 || exit 1 ;;
  *commits\\?sha=*) printf '%b' "$FAKE_COMMITS" ;;
  *actions/workflows/ci.yml/runs*) echo 1 ;;
  *) echo "unexpected gh $args" >&2; exit 2 ;;
esac
"""


def _decide(tmp_path, message, py, mod=None, commits="", tag_exists=False):
    data = yaml.safe_load(_workflow("release-on-green.yml"))
    (job,) = data["jobs"].values()
    script = next(step["run"] for step in job["steps"] if step.get("id") == "decide")
    stub = tmp_path / "bin"
    stub.mkdir(exist_ok=True)
    (stub / "gh").write_text(_FAKE_GH, encoding="utf-8")
    (stub / "gh").chmod(0o755)
    output = tmp_path / "out"
    output.write_text("", encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}",
        "GH_REPO": "o/r",
        "HEAD_SHA": "headsha",
        "HEAD_MESSAGE": message,
        "GITHUB_OUTPUT": str(output),
        "FAKE_PY": py,
        "FAKE_MOD": mod or py,
        "FAKE_COMMITS": commits,
        "FAKE_TAG_EXISTS": "1" if tag_exists else "",
    }
    result = subprocess.run(
        ["bash", "-c", script], env=env, capture_output=True, text=True, check=False
    )
    lines = output.read_text(encoding="utf-8").split()
    return result.returncode, dict(line.split("=", 1) for line in lines)


needs_bash = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None, reason="runs the workflow's bash"
)


@needs_bash
def test_release_commit_itself_is_tagged(tmp_path):
    code, out = _decide(tmp_path, "0.60.0 — Title (#117)\n\nbody", "0.60.0")
    assert code == 0 and out == {"tag": "v0.60.0", "version": "0.60.0"}


@needs_bash
def test_a_green_fix_after_a_red_release_commit_catches_up(tmp_path):
    commits = "headsha\\tFix a race (#118)\\nrel\\t0.60.0 — Title (#117)\\nold\\t0.59.0 — Old\\n"
    code, out = _decide(tmp_path, "Fix a race (#118)", "0.60.0", commits=commits)
    assert code == 0 and out == {"tag": "v0.60.0", "version": "0.60.0"}


@needs_bash
def test_catch_up_needs_the_release_commit_an_untagged_version_and_agreeing_files(tmp_path):
    no_release = "headsha\\tFix (#118)\\nold\\t0.59.0 — Old\\n"
    assert _decide(tmp_path, "Fix (#118)", "0.60.0", commits=no_release) == (0, {})
    tagged = "headsha\\tFix (#118)\\nrel\\t0.60.0 — Title\\n"
    assert _decide(tmp_path, "Fix (#118)", "0.60.0", commits=tagged, tag_exists=True) == (0, {})
    assert _decide(tmp_path, "Fix (#118)", "0.60.0", "0.59.0", commits=tagged) == (0, {})


def test_release_on_green_catch_up_lists_main_history_from_head():
    workflow = _workflow("release-on-green.yml")
    assert "commits?sha=$HEAD_SHA&per_page=100" in workflow
