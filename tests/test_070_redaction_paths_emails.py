"""Publication redaction: home paths, email addresses and the local login (Unreleased)."""

from __future__ import annotations

import json

import pytest

from opentine import _bundle, _redact_publish, _redacted_copy, _redacted_derive, cli
from opentine.graph import Run, StepKind
from opentine.policies import PolicySet
from opentine.repository import Repo
from opentine.repository.pack import inspect_pack

KEY = b"ab" * 32

# (input, expected) for the path rule. Rows whose input equals the output are false
# positives the rule must leave alone.
PATHS = [
    ("/home/alice/proj/a.py", "<HOME>/proj/a.py"),
    ("cd /Users/Bob/src && ls", "cd <HOME>/src && ls"),
    ("/root/.cache/pip", "<HOME>/.cache/pip"),
    ("/root", "<HOME>"),
    ('"cwd": "/home/alice"', '"cwd": "<HOME>"'),
    ("C:\\Users\\Ann\\src\\x.py", "<HOME>\\src\\x.py"),
    ("c:/users/Ann Lee/src", "<HOME>/src"),
    ("D:\\\\Users\\\\Ann\\\\src", "<HOME>\\\\src"),  # JSON-escaped backslashes
    ("~/notes.txt", "<HOME>/notes.txt"),
    ("~bob/notes.txt", "<HOME>/notes.txt"),
    ("file:///home/u/x", "file://<HOME>/x"),
    ("/var/home/x", "/var/home/x"),
    ("/homework/a", "/homework/a"),
    ("/rootfs/etc", "/rootfs/etc"),
    ("/home", "/home"),
    ("https://example.com/Users/list", "https://example.com/Users/list"),
    ("src/home/page.tsx", "src/home/page.tsx"),
    ("~5 minutes", "~5 minutes"),
    ("a~/b", "a~/b"),
]

# (input, expected) for the email rule: true positives first, then false positives.
EMAILS = [
    ("mail alice@example.com now", "mail <EMAIL> now"),
    ("Bob.Smith+tag@mail.example.co.uk", "<EMAIL>"),
    ("<jane_doe@corp.io>", "<<EMAIL>>"),
    ('{"email": "a.b@example.org"}', '{"email": "<EMAIL>"}'),
    ("x-user@sub.example.dev.", "<EMAIL>."),
    ("alice@build.example.com:/srv/app", "<USER>@build.example.com:/srv/app"),
    ("ssh://alice@host.example.com/x", "ssh://<USER>@host.example.com/x"),
    ("git@github.com:org/repo.git", "git@github.com:org/repo.git"),
    ("ssh://git@github.com/org/repo", "ssh://git@github.com/org/repo"),
    ("pnpm@10.33.0", "pnpm@10.33.0"),
    ("ms@4.0.0", "ms@4.0.0"),
    ("@click.option('--x')", "@click.option('--x')"),
    ("@types/node", "@types/node"),
    ("@scope/pkg@1.2.3", "@scope/pkg@1.2.3"),
    ("icon@2x.png", "icon@2x.png"),
    ("lodash@npm:4.17.21", "lodash@npm:4.17.21"),
    ("foo@latest", "foo@latest"),
    ("y = x@w.shape", "y = x@w.shape"),
    ("a @ b.com", "a @ b.com"),
    ("user@localhost", "user@localhost"),
    ("main.py@v1.2", "main.py@v1.2"),
    ("pkg@file.js", "pkg@file.js"),
]


@pytest.mark.parametrize(("text", "expected"), PATHS)
def test_home_paths_become_a_placeholder_and_keep_the_rest(text, expected):
    assert _redact_publish.scrub_text(text, login=None)[0] == expected


@pytest.mark.parametrize(("text", "expected"), EMAILS)
def test_emails_are_redacted_and_package_specifiers_are_not(text, expected):
    assert _redact_publish.scrub_text(text, login=None)[0] == expected


def test_counts_name_each_kind():
    text = "/home/a/x and /Users/b/y mail c@example.com"
    clean, counts = _redact_publish.scrub_text(text, login=None)
    assert clean == "<HOME>/x and <HOME>/y mail <EMAIL>"
    assert dict(counts) == {"path": 2, "email": 1}


def test_actor_fields_lose_a_real_login_only():
    value = {"actor": "alice", "writers": ["alice", "ci"], "note": "alice ran it"}
    clean, counts = _redact_publish.scrub_value(value, login="alice")
    assert clean == {"actor": "<USER>", "writers": ["<USER>", "ci"], "note": "alice ran it"}
    assert counts["user"] == 2
    for generic in ("local", "root", ""):
        assert _redact_publish.real_login(generic) is None
    assert _redact_publish.real_login("alice") == "alice"
    assert _redact_publish.scrub_value({"actor": "local"}, login=None)[0] == {"actor": "local"}


def test_colliding_keys_are_refused_rather_than_merged():
    with pytest.raises(ValueError, match="collapsed"):
        _redact_publish.scrub_value({"/home/a/x": 1, "/home/b/x": 2}, login=None)


def test_blob_bytes_stay_json_and_non_utf8_is_left_alone():
    raw = json.dumps({"p": "C:\\Users\\Ann\\x", "e": "a@example.com"}).encode()
    clean, counts = _redact_publish.scrub_bytes(raw, login=None)
    assert json.loads(clean) == {"p": "<HOME>\\x", "e": "<EMAIL>"}
    assert counts == {"path": 1, "email": 1}
    assert _redact_publish.scrub_bytes(b"\xff/home/a", login=None) == (b"\xff/home/a", {})


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(_redact_publish, "login", lambda: "alice")
    repo = Repo.init(tmp_path / "s")
    run = Run(id="r", model_info="m", user_prompt="fix /home/alice/proj/a.py",
              policies=PolicySet().to_dict())  # fmt: skip
    run.add_step(StepKind.done, {"text": "mailed bob@example.com from /Users/alice/x",
                                 "actor": "alice"})  # fmt: skip
    return repo, repo.put_run(run, ref="heads/main").run_id


def test_the_public_copy_has_no_home_email_or_login_and_verifies(store, tmp_path):
    repo, run = store
    counts: dict = {}
    data = _redacted_derive.public_bundle(
        repo, "heads/main", run, KEY, algorithm="hmac-sha256", counts=counts
    )
    checked = _bundle.verify(data)
    record = checked.redacted_public
    assert record["ruleset"] == _redact_publish.PUBLISH_RULESET
    assert record["public_run"] != run and record["redacted"] > 0
    _, objects, _ = inspect_pack(checked.pack)
    for _oid, raw in objects:
        assert b"/home/alice" not in raw and b"/Users/alice" not in raw
        assert b"bob@example.com" not in raw and b'"alice"' not in raw
    assert _redacted_copy.check(record, hmac_key=KEY)["state"] == "verified"
    assert counts and set(counts) <= {oid for oid, _ in objects}
    kinds = {kind for per in counts.values() for kind in per}
    assert kinds == {"path", "email", "user"}
    target = Repo.init(tmp_path / "pub")
    _bundle.unbundle(target, data, "public")
    assert target.fsck().ok and target.load_run(record["public_run"]) is not None


def test_cli_reports_per_object_counts(store, tmp_path, capsys):
    repo, _run = store
    key = tmp_path / "k"
    key.write_bytes(KEY)
    out = tmp_path / "public.bundle"
    cli.main(["bundle", "create", str(out), "heads/main", "--redacted-public",
              "--key-file", str(key), "--repo", str(repo.path)])  # fmt: skip
    report = json.loads(capsys.readouterr().out)
    redaction = report["redaction"]
    assert redaction["ruleset"] == _redact_publish.PUBLISH_RULESET
    assert redaction["totals"]["path"] >= 2 and redaction["totals"]["email"] == 1
    assert all(oid.split(":")[0] in {"blob", "event", "run"} for oid in redaction["objects"])


def test_op_log_redact_hides_the_login(tmp_path, capsys, monkeypatch):
    from opentine.repository import _oplog

    monkeypatch.setattr(_redact_publish, "login", lambda: "alice")
    monkeypatch.setattr(_oplog, "_actor", lambda: "alice")
    repo = Repo.init(tmp_path / "s")
    run = Run(id="r", model_info="m", user_prompt="p", policies=PolicySet().to_dict())
    with _oplog.operation("tine commit /home/alice/x"):
        repo.put_run(run, ref="heads/main")
    cli.main(["op", "log", "--json", "--redact", "--repo", str(repo.path)])
    ops = json.loads(capsys.readouterr().out)["ops"]
    assert ops and all(op["actor"] == "<USER>" for op in ops)
    assert "/home/alice" not in json.dumps(ops)
    cli.main(["op", "log", "--json", "--repo", str(repo.path)])
    assert json.loads(capsys.readouterr().out)["ops"][0]["actor"] == "alice"
