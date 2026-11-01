"""0.24: ``tine view RUN`` writes one self-contained, inert, deterministic page."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from opentine import Run
from opentine._view_html import FIELD_CAP
from opentine.cli import main
from opentine.core import StepKind

XSS = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'


@pytest.fixture
def saved(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.chdir(tmp_path)
    run = Run(user_prompt="fix the bug " + XSS, model_info="model-a")
    run.metadata["forked_from"] = "parent_run_123"
    run.add_step(
        StepKind.model,
        inputs={"messages": [{"role": "user", "content": XSS}]},
        outputs={"text": "ok " + XSS},
        model_info="model-a",
        usage={"input": 10, "output": 5},
        duration=1.5,
    )
    run.add_step(
        StepKind.tool, inputs={"name": "Bash", "arguments": {"command": "x" * (FIELD_CAP + 500)}}
    )
    path = tmp_path / "r.tine"
    run.save(path)
    return path


def _view(path: Path, out: Path) -> str:
    main(["view", str(path), "-o", str(out)])
    return out.read_text(encoding="utf-8")


def test_renders_header_and_steps(saved, tmp_path):
    page = _view(saved, tmp_path / "v.html")
    run = Run.load(saved)
    assert run.id in page
    assert "fix the bug" in page and "model-a" in page and "parent_run_123" in page
    assert run.metadata["integrity"]["digest"] in page
    assert "<details>" in page and "Bash" in page and "1.500s" in page
    assert page.count('<li id="step-') == 2
    assert "prefers-color-scheme:dark" in page


def test_recorded_markup_is_inert(saved, tmp_path):
    page = _view(saved, tmp_path / "v.html")
    assert "<script" not in page.lower()
    assert "<img" not in page.lower()
    assert "onerror=alert" not in page.replace("onerror=alert(2)&gt;", "")
    assert "&lt;script&gt;" in page and "&quot;&gt;&lt;img" in page


def test_same_run_same_bytes(saved, tmp_path):
    first = (tmp_path / "a.html", tmp_path / "b.html")
    _view(saved, first[0])
    _view(saved, first[1])
    assert first[0].read_bytes() == first[1].read_bytes()


def test_huge_field_is_truncated(saved, tmp_path):
    page = _view(saved, tmp_path / "v.html")
    assert "truncated" in page
    assert "x" * (FIELD_CAP + 1) not in page


def test_no_external_resources(saved, tmp_path):
    page = _view(saved, tmp_path / "v.html")
    assert "http://" not in page and "https://" not in page
    assert not re.search(r"""(src|href)\s*=\s*["']?(https?:)?//""", page, re.I)


def test_default_output_name(saved, tmp_path, capsys):
    main(["view", str(saved)])
    run = Run.load(saved)
    assert (tmp_path / f"{run.id[:12]}.html").is_file()
    assert "Wrote" in capsys.readouterr().out


def test_unknown_run_is_refused(saved, tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["view", "no_such_run_zz", "-o", str(tmp_path / "v.html")])
    assert exc.value.code == 1
    assert not (tmp_path / "v.html").exists()
