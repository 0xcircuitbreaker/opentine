"""Supply-chain CI: SBOM, dependency audit, workflow analysis, scanning."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GITHUB = ROOT / ".github"
WORKFLOWS = GITHUB / "workflows"
ACTION = re.compile(r"uses:\s+[^\s@]+@([^\s#]+)")


def _workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def _job(workflow: str, name: str) -> str:
    body = workflow.split(f"\n  {name}:\n", 1)[1]
    return re.split(r"\n  [a-z][a-z0-9-]*:\n", body, maxsplit=1)[0]


def test_every_workflow_pins_actions_by_commit_and_drops_default_permissions():
    names = sorted(path.name for path in WORKFLOWS.glob("*.yml"))
    assert {"codeql.yml", "scorecard.yml", "supply-chain.yml"} <= set(names)
    for name in names:
        workflow = _workflow(name)
        revisions = ACTION.findall(workflow)
        assert all(re.fullmatch(r"[0-9a-f]{40}", rev) for rev in revisions), name
        assert re.search(r"^permissions:( \{\}|\n  contents: read)$", workflow, re.M), name
        assert "contents: write" not in workflow or name == "publish.yml", name
        assert "${{ matrix." not in "".join(
            line for line in workflow.splitlines() if line.strip().startswith("run:")
        ), name


def test_supply_chain_workflow_audits_analyzes_and_emits_an_sbom():
    workflow = _workflow("supply-chain.yml")
    assert "\npermissions: {}\n" in workflow
    assert "uvx pip-audit==" in _job(workflow, "pip-audit")
    assert "--require-hashes" in _job(workflow, "pip-audit")
    assert "uvx zizmor==" in _job(workflow, "zizmor")
    sbom = _job(workflow, "sbom")
    assert "cyclonedx-bom==" in sbom and "opentine.cdx.json" in sbom
    assert "id-token:" not in workflow and ": write" not in workflow


def test_codeql_and_scorecard_hold_only_what_they_need():
    codeql = _workflow("codeql.yml")
    assert "languages: python" in codeql
    assert "id-token" not in codeql
    scorecard = _workflow("scorecard.yml")
    assert "ossf/scorecard-action@" in scorecard
    assert "pull_request" not in scorecard


def test_dependabot_covers_pip_and_github_actions():
    config = (GITHUB / "dependabot.yml").read_text(encoding="utf-8")
    assert "package-ecosystem: pip" in config
    assert "package-ecosystem: github-actions" in config


def test_release_build_job_installs_no_test_extras_and_ships_an_sbom():
    workflow = _workflow("publish.yml")
    gates = _job(workflow, "gates")
    assert "uv sync --locked --all-extras" in gates
    assert 'pytest tests -m "not live and not live_harness"' in gates
    assert "id-token" not in gates
    build = _job(workflow, "build")
    assert "needs: gates" in build
    assert "--all-extras" not in build and "pytest" not in build
    assert "uv sync --locked --no-default-groups --extra release" in build
    assert "opentine.cdx.json" in build
    release = _job(workflow, "github-release")
    assert "dist/opentine.cdx.json dist/SHA256SUMS" in release
    pypi = _job(workflow, "pypi")
    assert "opentine-sbom" not in pypi
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    release_extra = project["project"]["optional-dependencies"]["release"]
    assert "hatchling==1.31.0" in release_extra
    assert not any(dep.startswith("pytest") for dep in release_extra)
