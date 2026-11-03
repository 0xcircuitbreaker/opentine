"""0.33: fork edits everywhere -- repository forks, --unset and [+] append, transcript."""

from __future__ import annotations

import hashlib
import json

import pytest

from opentine import Run, cli
from opentine._canon import _canonical_bytes
from opentine._fork_identity import fork_id, verify_fork_id
from opentine.cli import main
from opentine.core import StepKind
from opentine.repository import Repo


def _sha(value) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _flat(text: str) -> str:
    return " ".join(text.split())


def _source_run() -> Run:
    run = Run(id="src00001", user_prompt="summarize", model_info="model-a")
    run.add_step(StepKind.think, inputs={"text": "plan"})
    model = run.add_step(
        StepKind.model,
        inputs={"messages": [{"role": "user", "content": "old"}], "temperature": 0.5},
        outputs={"text": "old answer"},
        model_info="model-a",
    )
    run.add_step(StepKind.done, inputs={"summary": "ok"})
    run.transcript = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "old answer", "step_id": model.id},
    ]
    return run


@pytest.fixture
def room(tmp_path, monkeypatch):
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    monkeypatch.delenv("OPENTINE_FORMAT", raising=False)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _tine(capsys, *argv: str) -> tuple[int, str]:
    capsys.readouterr()
    code = 0
    try:
        main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, _flat(captured.out + captured.err)


# -- .tine file forks: --unset, [+], transcript ------------------------------------------


@pytest.fixture
def source(room):
    path = room / "src.tine"
    _source_run().save(path)
    return room, path


def test_unset_and_append_are_recorded(source, capsys):
    root, path = source
    out = root / "e.tine"
    code, text = _tine(
        capsys, "fork", str(path), "--from-step", "1", "--save", str(out),
        "--set", 'inputs.messages[+]={"role": "user", "content": "more"}',
        "--unset", "inputs.temperature",
    )  # fmt: skip
    assert code == 0, text
    forked = Run.load(out)
    step = forked.steps[-1]
    assert step.inputs == {
        "messages": [{"role": "user", "content": "old"}, {"role": "user", "content": "more"}]
    }
    assert forked.metadata["edit"]["changes"] == [
        {"path": "inputs.messages[+]", "old_digest": "",
         "new_digest": _sha({"role": "user", "content": "more"}), "op": "append"},
        {"path": "inputs.temperature", "old_digest": _sha(0.5), "new_digest": "", "op": "unset"},
    ]  # fmt: skip
    assert verify_fork_id(forked) is True


def test_unset_list_item(source, capsys):
    root, path = source
    out = root / "e.tine"
    code, text = _tine(
        capsys, "fork", str(path), "--from-step", "1", "--save", str(out),
        "--unset", "inputs.messages.0",
    )  # fmt: skip
    assert code == 0, text
    assert Run.load(out).steps[-1].inputs["messages"] == []


def test_set_unset_and_append_give_distinct_ids(source, capsys):
    root, path = source
    ids = set()
    for index, edit in enumerate(
        (
            ["--unset", "inputs.temperature"],
            ["--set", "inputs.temperature=1"],
            ["--set", "inputs.messages[+]=1"],
        )  # fmt: skip
    ):
        out = root / f"f{index}.tine"
        code, text = _tine(capsys, "fork", str(path), "--from-step", "1", "--save", str(out), *edit)
        assert code == 0, text
        ids.add(Run.load(out).id)
    assert len(ids) == 3


@pytest.mark.parametrize(
    ("edit", "needle"),
    [
        (["--unset", "inputs.nope"], "'nope' does not name a field"),
        (["--unset", "inputs.messages.7"], "does not name a field or list item"),
        (["--unset", "model"], "must be a string"),
        (["--unset", "inputs.x[+]"], "--unset expects"),
        (["--set", "inputs.temperature[+]=1"], "[+] appends to a list, not a float"),
        (["--set", "inputs[+]=1"], "a path starts with"),
        (["--set", "model[+]=x"], "a path starts with"),
    ],
)
def test_bad_unset_or_append_is_refused(source, capsys, edit, needle):
    root, path = source
    before = path.read_bytes()
    code, text = _tine(
        capsys, "fork", str(path), "--from-step", "1", "--save", str(root / "x.tine"), *edit
    )
    assert code == 1 and needle in text, text
    assert "Traceback" not in text
    assert not (root / "x.tine").exists() and path.read_bytes() == before


def test_transcript_drops_the_edited_steps_entries(source, capsys):
    root, path = source
    out = root / "e.tine"
    code, _ = _tine(
        capsys, "fork", str(path), "--from-step", "1", "--save", str(out), "--set", "model=b"
    )
    assert code == 0
    assert Run.load(out).transcript == [{"role": "user", "content": "hi"}]
    plain = root / "p.tine"
    assert _tine(capsys, "fork", str(path), "--from-step", "1", "--save", str(plain))[0] == 0
    assert len(Run.load(plain).transcript) == 2  # an unedited fork keeps them


def test_unedited_fork_id_is_unchanged(source, capsys):
    """A plain fork's identity record is the pre-0.33 one: intent without an edit."""
    root, path = source
    out = root / "p.tine"
    assert _tine(capsys, "fork", str(path), "--from-step", "1", "--save", str(out))[0] == 0
    forked = Run.load(out)
    record = forked.metadata["fork"]
    assert fork_id(record) == forked.id and verify_fork_id(forked) is True
    run = Run.load(path)
    nonce = record["nonce"]
    again = run.fork(run.steps[1].id, intent={"harness": None, "prompt": None}, nonce=nonce)
    assert again.id == forked.id


# -- repository forks (format v4 by default, and v3) -------------------------------------


@pytest.fixture(params=["4", "3"])
def repo(room, monkeypatch, request):
    monkeypatch.setenv("OPENTINE_FORMAT", request.param)
    store = Repo.init(room)
    store.put_run(_source_run(), ref="heads/main")
    return store


def _repo_fork(capsys, ref: str, *edit: str) -> tuple[int, str]:
    return _tine(capsys, "fork", "heads/main", "--from-step", "2", "--ref", ref, *edit)


def test_repo_fork_applies_and_records_the_edit(repo, capsys, room):
    edit = room / "edit.json"
    edit.write_bytes(json.dumps({"inputs.messages.0.content": "new"}).encode())
    code, text = _repo_fork(
        capsys, "experiments/e1", "--edit-file", str(edit), "--set", "model=model-b",
        "--unset", "inputs.temperature", "--set", "inputs.messages[+]=1",
    )  # fmt: skip
    assert code == 0, text
    assert "Edited step" in text
    source = repo.get(repo.read_ref("heads/main")).payload()
    forked = repo.get(repo.read_ref("experiments/e1")).payload()
    record = forked["fork_overrides"]["edit"]
    point = source["events"][1]
    assert record["step"] == point and record["executed"] is False
    assert [c["path"] for c in record["changes"]] == [  # edit-file, sets, then unsets
        "inputs.messages.0.content", "model", "inputs.messages[+]", "inputs.temperature",
    ]  # fmt: skip
    assert record["changes"][1]["old_digest"] == _sha("model-a")
    assert forked["events"] == [source["events"][0], record["edited_step"]]
    assert forked["tips"] == [record["edited_step"]]
    loaded = repo.load_run(repo.read_ref("experiments/e1"))
    step = loaded.steps[-1]
    assert step.inputs == {"messages": [{"role": "user", "content": "new"}, 1]}
    assert step.model_info == "model-b" and step.outputs == {} and step.cost == 0
    assert all(item.get("step_id") != point for item in loaded.transcript)
    assert repo.fsck().ok


def test_repo_fork_id_binds_the_edit_and_unedited_is_unchanged(repo, capsys):
    main_id = repo.read_ref("heads/main")
    point = repo.get(main_id).payload()["events"][1]
    plain = repo.fork(main_id, point, overrides={})
    assert _repo_fork(capsys, "experiments/p")[0] == 0
    assert repo.read_ref("experiments/p") == plain  # same oid as a fork with no edit
    assert repo.fork(main_id, point, overrides={"edit": None}) == plain
    assert "edit" not in repo.get(plain).payload()["fork_overrides"]
    assert _repo_fork(capsys, "experiments/a", "--set", "model=x")[0] == 0
    assert _repo_fork(capsys, "experiments/b", "--set", "model=y")[0] == 0
    ids = {repo.read_ref(f"experiments/{name}") for name in "pab"}
    assert len(ids) == 3


def test_repo_fork_edit_json_output(repo, capsys):
    point = repo.get(repo.read_ref("heads/main")).payload()["events"][1]
    code, text = _tine(
        capsys, "repo-fork", "heads/main", "--from-event", point, "--ref", "experiments/j",
        "--unset", "inputs.temperature", "--json",
    )  # fmt: skip
    assert code == 0, text
    payload = json.loads(text)
    assert payload["edit"]["changes"][0]["op"] == "unset"
    assert "edit" not in payload["overrides"]


@pytest.mark.parametrize(
    ("edit", "needle"),
    [
        (["--set", "outputs.text=x"], "Cannot edit 'outputs.text'"),
        (["--unset", "inputs.nope"], "does not name a field"),
        (["--set", "model=model-a"], "changes nothing"),
    ],
)
def test_repo_fork_bad_edit_is_a_clean_refusal(repo, capsys, edit, needle):
    code, text = _repo_fork(capsys, "experiments/bad", *edit)
    assert code == 1 and needle in text and "Traceback" not in text
    assert repo.read_ref("experiments/bad") is None


def test_repo_fork_edit_override_shape_is_checked(repo):
    main_id = repo.read_ref("heads/main")
    point = repo.get(main_id).payload()["events"][1]
    with pytest.raises(ValueError, match="non-empty list"):
        repo.fork(main_id, point, overrides={"edit": "model=x"})
