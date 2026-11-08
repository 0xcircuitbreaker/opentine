"""0.45: ``docs/SPEC.md`` is versioned and citable, with stable section anchors.

The anchor set below is append-only: a later spec version may add anchors but
never drop one, so a citation of ``SPEC.md#s-4.8`` keeps resolving.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs" / "SPEC.md"

PINNED = (
    "stable-anchors spec-changelog "
    + " ".join(f"part-{n}" for n in range(13))
    + " s-0.1 s-0.2 s-0.3 s-0.4 s-0.5 s-1.1 s-1.2 s-1.3 s-1.4 s-1.5 s-1.6"
    " s-2.1 s-2.2 s-2.3 s-2.4 s-2.5 s-2.6 s-2.7 s-2.8 s-2.9 s-2.10"
    " s-3.1 s-3.2 s-3.3 s-3.4 s-3.5 s-3.6 s-3.7 s-3.8"
    " s-4.1 s-4.2 s-4.3 s-4.4 s-4.5 s-4.6 s-4.7 s-4.8 s-4.9 s-4.10 s-4.11"
    " s-5.1 s-5.2 s-5.3 s-5.4"
    " s-8.1 s-8.2 s-8.3 s-8.4 s-8.5 s-8.6 s-8.7 s-8.8 s-8.9 s-8.10 s-8.11 s-8.12"
    " s-9.1 s-9.2 s-9.3 s-9.4 s-9.5 s-9.6 s-9.7 s-9.8 s-9.9 s-9.10"
    " s-10.1 s-10.2 s-10.3 s-10.4 s-10.5 s-10.6 s-10.7 s-11.1 s-11.2"
    " s-12.1 s-12.2 s-12.3 s-12.4"
).split()


@pytest.fixture(scope="module")
def text() -> str:
    if not SPEC.is_file():  # pragma: no cover - installed distribution
        pytest.skip("docs/ is not part of an installed distribution")
    return SPEC.read_text(encoding="utf-8")


def _version(text: str) -> str:
    match = re.search(r"\*\*Spec version:\*\* ([0-9]+\.[0-9]+\.[0-9]+)", text)
    assert match, "SPEC.md must open with its spec version"
    return match.group(1)


def test_the_header_the_citation_and_the_changelog_agree(text):
    version = _version(text)
    assert f"`docs/SPEC.md`, version {version}." in text
    assert f"/blob/v{version}/docs/SPEC.md" in text
    changelog = text[text.index('<a id="spec-changelog"></a>') :]
    assert f"| {version} |" in changelog, "a new spec version needs a changelog row"


def test_anchors_are_unique_and_never_dropped(text):
    anchors = re.findall(r'<a id="([^"]+)"></a>', text)
    assert len(anchors) == len(set(anchors))
    assert not set(PINNED) - set(anchors), "a cited anchor was removed"


def test_every_part_and_numbered_section_has_its_anchor(text):
    lines = text.splitlines()
    for i, line in enumerate(lines):
        part = re.match(r"^# Part (\d+) ", line)
        section = re.match(r"^## (\d+\.\d+[a-z]?) ", line)
        want = f"part-{part.group(1)}" if part else f"s-{section.group(1)}" if section else None
        if want:
            assert lines[i - 1] == f'<a id="{want}"></a>', line


def test_the_conformance_manifest_cites_the_same_version(text):
    import json

    manifest = json.loads((ROOT / "docs" / "conformance" / "MANIFEST.json").read_text("utf-8"))
    assert manifest["spec_version"] == _version(text)
