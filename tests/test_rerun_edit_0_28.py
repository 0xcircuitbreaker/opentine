"""0.28: ``tine fork RUN --from-step K --set PATH=VALUE`` reruns from an edited step."""

from __future__ import annotations

import hashlib
import json

import pytest

from opentine import Run
from opentine._canon import _canonical_bytes
from opentine._fork_identity import verify_fork_id
from opentine.cli import main
from opentine.core import StepKind


def _sha(value) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _flat(text: str) -> str:
    return " ".join(text.split())


@pytest.fixture
def source(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.chdir(tmp_path)
    run = Run(user_prompt="summarize")
    run.add_step(StepKind.think, inputs={"text": "plan"})
    run.add_step(
        StepKind.model,
        inputs={"messages": [{"role": "user", "content": "old prompt"}]},
        outputs={"text": "old answer"},
        model_info="model-a",
    )
    run.add_step(StepKind.tool, inputs={"name": "Bash", "arguments": {"command": "ls"}})
    run.add_step(StepKind.done, inputs={"summary": "ok"})
    path = tmp_path / "src.tine"
    run.save(path)
    return tmp_path, path


def _fork(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        main(["fork", *argv])
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, _flat(captured.out + captured.err)


def test_edited_fork_leaves_original_byte_identical_and_keeps_prefix(source, capsys):
    root, path = source
    before = path.read_bytes()
    out = root / "edited.tine"
    edit = root / "edit.json"
    edit.write_bytes(json.dumps({"model": "model-b"}).encode())
    code, text = _fork(
        capsys, str(path), "--from-step", "1", "--save", str(out),
        "--set", "inputs.messages.0.content=new prompt", "--edit-file", str(edit),
    )  # fmt: skip
    assert code == 0, text
    assert "Edited step" in text
    assert path.read_bytes() == before
    original, forked = Run.load(path), Run.load(out)
    assert forked.steps[0] == original.steps[0]  # the prefix before K, exactly
    assert len(forked.steps) == 2
    edited = forked.steps[1]
    assert edited.inputs["messages"][0]["content"] == "new prompt"
    assert edited.model_info == "model-b"
    assert edited.outputs == {} and edited.id != original.steps[1].id
    assert edited.parent_ids == original.steps[1].parent_ids


def test_edit_is_recorded_in_provenance(source, capsys):
    root, path = source
    out = root / "edited.tine"
    code, text = _fork(
        capsys, str(path), "--from-step", "2", "--save", str(out),
        "--set", 'inputs.arguments.command="pwd"',
    )  # fmt: skip
    assert code == 0, text
    original, forked = Run.load(path), Run.load(out)
    record = forked.metadata["edit"]
    assert record["step"] == original.steps[2].id
    assert record["edited_step"] == forked.steps[-1].id
    assert record["changes"] == [
        {"path": "inputs.arguments.command", "old_digest": _sha("ls"), "new_digest": _sha("pwd")}
    ]
    assert forked.metadata["forked_from"] == original.id
    assert verify_fork_id(forked) is True
    # A plain fork of the same point gets no edit record.
    plain = root / "plain.tine"
    assert _fork(capsys, str(path), "--from-step", "2", "--save", str(plain))[0] == 0
    assert "edit" not in Run.load(plain).metadata


@pytest.mark.parametrize(
    ("argv", "needle"),
    [
        (["--from-step", "1", "--set", "outputs.text=x"], "Cannot edit 'outputs.text'"),
        (["--from-step", "1", "--set", "inputs.nope.deep=x"], "no field 'nope'"),
        (["--from-step", "1", "--set", "noequals"], "PATH=VALUE"),
        (["--from-step", "9", "--set", "model=x"], "out of range"),
        (["--from-step", "1", "--set", "model=model-a"], "changes nothing"),
        (["--from-step", "1", "--set", "model=5"], "must be a string"),
    ],
)
def test_bad_path_or_step_is_refused_cleanly(source, capsys, argv, needle):
    root, path = source
    before = path.read_bytes()
    out = root / "never.tine"
    code, text = _fork(capsys, str(path), *argv, "--save", str(out))
    assert code == 1
    assert needle in text
    assert not out.exists()
    assert path.read_bytes() == before


def test_bad_edit_file_is_refused(source, capsys):
    root, path = source
    bad = root / "bad.json"
    bad.write_bytes(b"[1, 2]")
    code, text = _fork(capsys, str(path), "--from-step", "1", "--edit-file", str(bad))
    assert code == 1 and "JSON object" in text
