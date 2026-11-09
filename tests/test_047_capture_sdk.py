"""0.47 TS capture SDK: what ``ts/capture`` emits is what the Python recorder accepts.

``ts/capture/test/fixtures/expected.json`` pins the ``opentine-hook/1`` events
the TS adapters produce from Vercel AI SDK and OpenAI Agents SDK results (its
own ``npm test`` checks the TS side). Here every one of those events must
validate against the published schema and be recorded, in order, by
``tine hook capture --agent generic`` into one run per session.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from opentine._schemas import validate

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = ROOT / "ts" / "capture" / "test" / "fixtures" / "expected.json"

pytestmark = pytest.mark.skipif(not EXPECTED.is_file(), reason="ts/ is not in the sdist")


def _cases() -> list[dict]:
    return json.loads(EXPECTED.read_text("utf-8"))["cases"] if EXPECTED.is_file() else []


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    from opentine import _porcelain_config as porcelain
    from opentine.repo import Repo

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    root = tmp_path / "repo"
    created = Repo.init(root)
    porcelain.save(Path(created.path), {"remotes": {}, "config": {"hooks.capture": "true"}})
    return root


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["fixture"])
def test_every_ts_capture_event_is_schema_valid_and_recorded(repo, case):
    from opentine._hook_protocol import run_capture

    answers = []
    for event in case["events"]:
        assert validate(event, "opentine-hook-1")[1] == []
        out = io.StringIO()
        assert run_capture(str(repo), "generic", io.BytesIO(json.dumps(event).encode()), out) == 0
        answers.append(json.loads(out.getvalue()))
    assert all(answer["ok"] for answer in answers), answers
    assert [a["event"] for a in answers] == [e["event"] for e in case["events"]]
    assert len({a["ref"] for a in answers}) == 1, "one session is one run ref"
    steps = [e for e in case["events"] if e["event"] != "session_end"]  # it only closes the run
    assert max(a["steps"] for a in answers) == len(steps)


def test_the_package_pins_its_dev_dependencies_and_has_no_runtime_ones():
    package = json.loads((EXPECTED.parents[2] / "package.json").read_text("utf-8"))
    assert "dependencies" not in package
    assert all(v[0].isdigit() for v in package["devDependencies"].values()), "pin exact versions"
    assert (EXPECTED.parents[2] / "package-lock.json").is_file()
