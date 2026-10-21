"""0.11: which agents did what -- the action index, ``tine who`` and friends."""

from __future__ import annotations

import json
import sqlite3

import pytest

import opentine.cli as cli
from opentine._actions import extract_actions
from opentine._actions_db import ActionIndex, Source
from opentine._actions_parse import argv0, programs
from opentine._actions_policy import evaluate, load_policy
from opentine._actions_query import ActionQuery, ActionQueryError, find, group, parse_time
from opentine._actions_source import open_repo, open_runs_dir, runs_dir_sources
from opentine._actions_targets import hosts
from opentine.graph import Run, StepKind
from opentine.index import RunIndex
from opentine.repository import Repo

GHP = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
ANT = "sk-ant-api03-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0PpOoNnMmLlKk"


def _alpha() -> Run:
    run = Run(run_id="run-alpha", model_info="claude-opus-5-5", metadata={"harness": "claude-code"})
    run.add_step(
        StepKind.tool,
        {
            "name": "Bash",
            "arguments": {"command": "rm -rf /tmp/build && curl https://api.github.com/x"},
            "session_id": "sess-1",
        },
    )
    run.add_step(
        StepKind.tool, {"name": "Write", "arguments": {"file_path": "src/app.py", "content": "x"}}
    )
    run.add_step(
        StepKind.tool,
        {"name": "Bash", "arguments": {"command": f"export GITHUB_TOKEN={GHP} && make"}},
    )
    return run


def _beta() -> Run:
    run = Run(run_id="run-beta", model_info="gpt-6.1-sol", metadata={"harness": "codex"})
    run.add_step(
        StepKind.tool,
        {"name": "shell", "arguments": {"command": ["bash", "-lc", "git push --force"]}},
    )
    run.add_step(
        StepKind.tool, {"name": "mcp__github__create_pull_request", "arguments": {"title": "t"}}
    )
    run.add_step(StepKind.think, {"text": "not an action"})
    return run


@pytest.fixture
def runs(tmp_path, monkeypatch):
    directory = tmp_path / ".tine_runs"
    directory.mkdir()
    _alpha().save(directory / "run-alpha.tine")
    _beta().save(directory / "run-beta.tine")
    monkeypatch.setattr(cli, "RUNS_DIR", directory)
    return directory


def _json(capsys, *argv: str) -> dict:
    cli.main([*argv, "--json"])
    return json.loads(capsys.readouterr().out)


# --- (1) the run index searches tool arguments, harness and provider ------------ #


def test_search_finds_a_tool_argument_and_filters_by_harness(runs):
    index = RunIndex.open(runs).sync()
    assert [entry.run_id for entry in index.search("/tmp/build")] == ["run-alpha"]
    assert [entry.run_id for entry in index.search("harness:codex")] == ["run-beta"]
    assert index.search("harness:codex /tmp/build") == []


def test_search_reads_past_the_index_text_cut_off(tmp_path):
    run = Run(run_id="long", model_info="m")
    for number in range(400):
        run.add_step(
            StepKind.tool, {"name": "Read", "arguments": {"file_path": f"pad/{number:04d}.txt"}}
        )
    run.add_step(StepKind.tool, {"name": "Bash", "arguments": {"command": "needle-at-the-end"}})
    run.save(tmp_path / "long.tine")
    index = RunIndex.open(tmp_path).sync()
    assert index.entries["long.tine"].truncated
    assert [entry.run_id for entry in index.search("needle-at-the-end")] == ["long"]


def test_provider_predicate(tmp_path):
    run = Run(run_id="p", model_info="m")
    run.add_step(StepKind.model, {"text": "x"}, provider="anthropic")
    run.save(tmp_path / "p.tine")
    index = RunIndex.open(tmp_path).sync()
    assert [entry.run_id for entry in index.search("provider:anthropic")] == ["p"]
    assert index.search("provider:openai") == []


# --- (2) extraction ---------------------------------------------------------------- #


def test_extraction_classifies_verbs_programs_paths_hosts_and_mcp():
    actions, truncated = extract_actions(_alpha())
    assert not truncated and len(actions) == 3
    bash, write, _ = actions
    assert bash.verbs == ["exec", "file.delete"] and bash.programs == ["rm", "curl"]
    assert bash.paths == ["/tmp/build"] and bash.hosts == ["api.github.com"]
    assert bash.agent == "claude-code" and bash.session == "sess-1"
    assert write.verbs == ["file.write"] and write.writes == ["src/app.py"]
    beta = extract_actions(_beta())[0]
    assert beta[0].verbs == ["exec", "git"] and beta[0].argv0 == "git"
    assert (beta[1].verbs, beta[1].mcp_server, beta[1].mcp_tool) == (
        ["mcp"],
        "github",
        "create_pull_request",
    )


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("sudo -u root rm -rf x", ["rm"]),
        ("FOO=1 env -u X /usr/bin/git status | grep y", ["git", "grep"]),
        ("timeout 10 python x.py; ls", ["python", "ls"]),
        ("bash -c 'curl https://a.b'", ["curl"]),
        ('unterminated "quote', ["unterminated"]),
    ],
)
def test_programs(command, expected):
    assert programs(command) == expected
    assert argv0(command) == expected[0]


def test_hosts_from_urls_and_scp_remotes():
    assert hosts("git clone git@github.com:o/r.git && curl http://u:p@Example.COM:8080/x") == [
        "example.com",
        "github.com",
    ]


def test_extraction_reads_only_redacted_content():
    actions, _ = extract_actions(_alpha())
    assert GHP not in json.dumps([action.to_dict() for action in actions])
    assert actions[2].redacted


# --- (3) the sidecar index --------------------------------------------------------- #


def test_no_secret_reaches_the_index_file(runs):
    run = Run(run_id="secret", model_info="m")
    run.add_step(
        StepKind.tool,
        {"name": "Bash", "arguments": {"command": f"curl -H 'x-api-key: {ANT}' https://h"}},
    )
    run.add_step(StepKind.tool, {"name": "Write", "arguments": {"file_path": "a", "content": GHP}})
    run.save(runs / "secret.tine")
    index, _ = open_runs_dir(runs)
    index.close()
    stored = (runs / "actions.sqlite").read_bytes()
    assert GHP.encode() not in stored and ANT.encode() not in stored


def _snapshot(index: ActionIndex) -> list[tuple]:
    return [tuple(sorted(action.to_dict().items())) for action in index.rows()]


def test_incremental_sync_equals_a_fresh_build(runs, tmp_path):
    index, report = open_runs_dir(runs)
    assert report.indexed == 2
    extra = Run(run_id="run-gamma", model_info="m", metadata={"harness": "gemini"})
    extra.add_step(
        StepKind.tool, {"name": "web_fetch", "arguments": {"url": "https://docs.example"}}
    )
    extra.save(runs / "run-gamma.tine")
    (runs / "run-beta.tine").unlink()
    second = index.sync(runs_dir_sources(runs))
    assert (second.indexed, second.removed) == (1, 1)
    incremental = _snapshot(index)
    index.close()
    fresh = ActionIndex(tmp_path / "fresh.sqlite")
    fresh.sync(runs_dir_sources(runs))
    assert _snapshot(fresh) == incremental
    fresh.close()


def test_a_corrupt_index_is_rebuilt(runs):
    (runs / "actions.sqlite").write_bytes(b"not a database" * 100)
    index, report = open_runs_dir(runs)
    assert report.indexed == 2 and len(find(index, ActionQuery())) == 5
    index.close()


def test_an_unreadable_run_is_counted_not_fatal(runs):
    (runs / "broken.tine").write_text("{not json", encoding="utf-8")
    index, report = open_runs_dir(runs)
    assert report.unreadable == 1 and index.coverage()["unreadable_runs"] == 1
    index.close()


def test_query_text_is_bound_never_spliced(runs):
    index, _ = open_runs_dir(runs)
    hostile = ActionQuery(tool="x' OR 1=1 --", cmd=["%"], path="'; DROP TABLE actions; --")
    assert find(index, hostile) == []
    assert len(find(index, ActionQuery())) == 5
    index.close()


def test_glob_and_substring_filters_and_grouping(runs):
    index, _ = open_runs_dir(runs)
    assert [a.tool for a in find(index, ActionQuery(path="src/*"))] == ["Write"]
    assert [a.tool for a in find(index, ActionQuery(host="github.com"))] == ["Bash"]
    assert [a.mcp_tool for a in find(index, ActionQuery(mcp="github/create_*"))] == [
        "create_pull_request"
    ]
    rows = group(find(index, ActionQuery()), ["agent"])
    assert [(row["agent"], row["actions"]) for row in rows] == [("claude-code", 3), ("codex", 2)]
    index.close()


def test_parse_time():
    assert parse_time("2d", now=1_000_000.0) == 1_000_000.0 - 2 * 86400
    with pytest.raises(ActionQueryError):
        parse_time("yesterday")


# --- (4) CLI ----------------------------------------------------------------------- #


def test_who_groups_agents_that_ran_a_program(runs, capsys):
    out = _json(capsys, "who", "--program", "rm", "--by", "agent,model")
    assert out["command"] == "who" and out["matched"] == 1
    assert out["groups"][0]["agent"] == "claude-code"


def test_who_reports_redacted_coverage(runs, capsys):
    out = _json(capsys, "who", "--cmd", "ghp_")
    assert out["matched"] == 0 and out["coverage"]["redacted_unmatched"] == 1


def test_touched_lists_writers_only(runs, capsys):
    out = _json(capsys, "touched", "--path", "src/app.py")
    assert out["matched"] == 1 and out["groups"][0]["agent"] == "claude-code"
    assert _json(capsys, "touched", "--path", "/tmp/build")["matched"] == 1  # rm is a delete


def test_actions_timeline(runs, capsys):
    out = _json(capsys, "actions", "run-beta")
    assert [action["tool"] for action in out["actions"]] == [
        "shell",
        "mcp__github__create_pull_request",
    ]


def test_audit_exits_nonzero_on_a_deny_rule(runs, tmp_path, capsys):
    policy = tmp_path / "policy.toml"
    policy.write_text(
        '[[rule]]\nid = "no-force-push"\nprogram = "git"\ncmd = "--force"\n'
        '[[rule]]\nid = "watch-mcp"\nlevel = "warn"\nverb = "mcp"\n',
        encoding="utf-8",
    )
    with pytest.raises(SystemExit) as stopped:
        cli.main(["audit", "--policy", str(policy), "--json"])
    assert stopped.value.code == 1
    out = json.loads(capsys.readouterr().out)
    assert sorted(row["rule"] for row in out["violations"]) == ["no-force-push", "watch-mcp"]


def test_audit_passes_with_only_warnings_unless_strict(runs, tmp_path, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"rules": [{"id": "w", "level": "warn", "verb": "mcp"}]}))
    # The fixture runs carry a redacted command, so the verdict is partial.
    out = _json(capsys, "audit", "--policy", str(policy), "--allow-partial")
    assert out["ok"] is True and out["partial"] is True
    with pytest.raises(SystemExit):
        cli.main(["audit", "--policy", str(policy), "--strict", "--allow-partial"])


@pytest.mark.parametrize(
    "body",
    ['[[rule]]\nid = "x"\n', '[[rule]]\nlevel = "block"\ntool = "x"\n', "[[rule]]\nbogus = 1\n"],
)
def test_bad_policy_rules_are_refused(tmp_path, body):
    policy = tmp_path / "p.toml"
    policy.write_text(body, encoding="utf-8")
    with pytest.raises(ActionQueryError):
        load_policy(policy)


def test_who_over_a_v3_repository(tmp_path, capsys):
    repo = Repo.init(tmp_path / "repo")
    repo.put_run(_beta(), ref="heads/main")
    index, _ = open_repo(repo)
    assert [a.argv0 for a in find(index, ActionQuery(verb="git"))] == ["git"]
    index.close()
    out = _json(capsys, "who", "--repo", str(tmp_path / "repo"), "--verb", "mcp", "--list")
    assert [action["mcp_server"] for action in out["actions"]] == ["github"]


def test_policy_evaluate_directly(runs, tmp_path):
    policy = tmp_path / "p.toml"
    policy.write_text('[[rule]]\nid = "net"\nhost = "*.github.com"\n', encoding="utf-8")
    index, _ = open_runs_dir(runs)
    assert [v.action.tool for v in evaluate(index, load_policy(policy))] == ["Bash"]
    index.close()


# --- (5) MCP ----------------------------------------------------------------------- #


class _Server:
    def __init__(self, name: str = "opentine"):
        self.tools: dict = {}

    def tool(self, *args, **kwargs):
        def register(function):
            self.tools[function.__name__] = function
            return function

        return register

    def resource(self, *args, **kwargs):
        return lambda function: function


def test_mcp_find_actions(runs, tmp_path):
    from opentine._mcp_actions import register_action_tools

    server = _Server()
    register_action_tools(server, runs, tmp_path)
    found = server.tools["find_actions"](program="rm")
    assert found["matched"] == 1 and found["actions"][0]["agent"] == "claude-code"
    grouped = server.tools["find_actions"](group_by="agent")
    assert [row["agent"] for row in grouped["groups"]] == ["claude-code", "codex"]
    with pytest.raises(ValueError):
        server.tools["find_actions"](limit=10_000)
    with pytest.raises(ValueError):
        server.tools["find_actions"](tool="x" * 5000)


def test_index_schema_is_plain_sqlite(runs):
    open_runs_dir(runs)[0].close()
    tables = {
        row[0]
        for row in sqlite3.connect(runs / "actions.sqlite").execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    assert {"actions", "paths", "hosts", "sources", "meta"} <= tables


# --- 0.11 audit follow-ups -----------------------------------------------------


def _bash_run(run_id: str, *commands: str) -> Run:
    run = Run(run_id=run_id, model_info="m", metadata={"harness": "claude-code"})
    for command in commands:
        run.add_step(StepKind.tool, {"name": "Bash", "arguments": {"command": command}})
    return run


def test_a_password_in_a_url_does_not_hide_its_host():
    assert hosts("curl https://u:[REDACTED]@evil.example:8443/x") == ["evil.example"]
    assert hosts("curl https://evil.example/") == ["evil.example"]
    assert hosts("curl http://[::1]:8080/") == ["::1"]
    action = extract_actions(_bash_run("r", "curl https://u:p4ssw0rdXYZ@evil.example/"))[0][0]
    assert action.hosts == ["evil.example"]
    assert "p4ssw0rdXYZ" not in action.command


def test_a_host_rule_matches_a_url_with_userinfo(tmp_path):
    policy = tmp_path / "p.toml"
    policy.write_text('[[rule]]\nid = "no-evil"\nhost = "evil.example"\n', encoding="utf-8")
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    _bash_run("r", "curl https://u:secretpw@evil.example/").save(runs_dir / "r.tine")
    index, _ = open_runs_dir(runs_dir)
    with index:
        violations = evaluate(index, load_policy(policy))
    assert [v.rule.id for v in violations] == ["no-evil"]


@pytest.mark.parametrize(
    "command",
    [
        "echo pwn > /etc/hosts.allow",
        "echo pwn >> /etc/hosts.allow",
        "cmd &>/etc/hosts.allow",
        "cp evil /etc/hosts.allow",
        "mv evil /etc/hosts.allow",
        "sed -i s/a/b/ /etc/hosts.allow",
        "echo x | tee -a /etc/hosts.allow",
        "dd if=/dev/zero of=/etc/hosts.allow",
        "truncate -s 0 /etc/hosts.allow",
        "chmod 777 /etc/hosts.allow",
        "install -m 644 evil /etc/hosts.allow",
        "cp evil -t /etc/hosts.allow",
    ],
)
def test_shell_side_writes_count_as_writes(command):
    action = extract_actions(_bash_run("r", command))[0][0]
    assert "file.write" in action.verbs, command
    assert "/etc/hosts.allow" in action.writes, command


def test_reads_and_dev_null_are_not_writes():
    action = extract_actions(_bash_run("r", "cat /etc/hosts.allow 2>/dev/null"))[0][0]
    assert "file.write" not in action.verbs and action.writes == []


def test_touched_finds_a_shell_redirect(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    _bash_run("run-shell", "echo pwn > /etc/hosts.allow").save(runs_dir / "s.tine")
    monkeypatch.setenv("OPENTINE_RUNS_DIR", str(runs_dir))
    index, _ = open_runs_dir(runs_dir)
    with index:
        matched = find(index, ActionQuery(path="/etc/hosts.allow", writes=True))
    assert [a.run_id for a in matched] == ["run-shell"]


def test_grouping_by_program_names_the_matched_program():
    actions = extract_actions(_bash_run("r", "cd /x && git push"))[0]
    rows = group(actions, ["program"], program="git")
    assert [row["program"] for row in rows] == ["git"]
    assert [row["program"] for row in group(actions, ["program"])] == ["cd"]


# --- 0.11 audit round 2 -------------------------------------------------------


def _deny_rm(tmp_path):
    policy = tmp_path / "deny-rm.toml"
    policy.write_text('[[rule]]\nid = "no-rm"\nprogram = "rm"\n', encoding="utf-8")
    return policy


def test_audit_fails_when_a_run_was_cut_at_the_action_cap(tmp_path, monkeypatch, capsys):
    import opentine._actions as actions_module

    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    _bash_run("long", "ls", "ls", "ls", "ls", "rm -rf /").save(runs_dir / "long.tine")
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)
    monkeypatch.setattr(actions_module, "MAX_ACTIONS_PER_RUN", 3)
    policy = _deny_rm(tmp_path)
    with pytest.raises(SystemExit) as stopped:
        cli.main(["audit", "--policy", str(policy), "--json"])
    assert stopped.value.code == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and out["partial"] is True
    assert out["coverage"]["truncated_runs"] == 1
    # An explicit opt-in accepts the partial check (the hidden rm stays unseen).
    out = _json(capsys, "audit", "--policy", str(policy), "--allow-partial")
    assert out["ok"] is True and out["partial"] is True


def test_audit_fails_when_a_run_cannot_be_read(runs, tmp_path, capsys):
    (runs / "broken.tine").write_bytes(b"{not json")
    policy = tmp_path / "p.toml"
    policy.write_text('[[rule]]\nid = "x"\nprogram = "nothing-matches"\n', encoding="utf-8")
    with pytest.raises(SystemExit) as stopped:
        cli.main(["audit", "--policy", str(policy), "--json"])
    assert stopped.value.code == 1
    assert json.loads(capsys.readouterr().out)["coverage"]["unreadable_runs"] == 1


def test_audit_never_trusts_an_index_file_it_did_not_build(tmp_path, monkeypatch):
    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    _bash_run("r1", "rm -rf /").save(runs_dir / "r1.tine")
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)
    index, _ = open_runs_dir(runs_dir)
    with index:
        # A planted cache: every source is "up to date" and holds no actions.
        with index.db:
            index.db.execute("DELETE FROM actions")
    with pytest.raises(SystemExit) as stopped:
        cli.main(["audit", "--policy", str(_deny_rm(tmp_path))])
    assert stopped.value.code == 1


def test_audit_over_a_repo_ignores_a_planted_index(tmp_path, capsys):
    repo = Repo.init(tmp_path / "repo")
    repo.put_run(_bash_run("r1", "rm -rf /"), ref="heads/main")
    index, _ = open_repo(repo)
    with index:
        with index.db:
            index.db.execute("DELETE FROM actions")
    with pytest.raises(SystemExit) as stopped:
        cli.main(["audit", "--repo", str(repo.path), "--policy", str(_deny_rm(tmp_path)), "--json"])
    assert stopped.value.code == 1
    assert json.loads(capsys.readouterr().out)["violations"][0]["rule"] == "no-rm"


@pytest.mark.parametrize(
    "command",
    ["rm secrets.txt", "rm -r secrets.txt", "unlink secrets.txt", "shred -n 3 secrets.txt"],
)
def test_deleting_a_bare_filename_is_recorded_on_that_path(command):
    action = extract_actions(_bash_run("r", command))[0][0]
    assert "secrets.txt" in action.paths
    assert "file.delete" in action.verbs or "file.write" in action.verbs


# --- audit round 4 ------------------------------------------------------------ #


def _audit(capsys, tmp_path, monkeypatch, run: Run, rule: dict, *flags: str) -> tuple[int, dict]:
    directory = tmp_path / ".tine_runs"
    directory.mkdir(exist_ok=True)
    run.save(directory / f"{run.id}.tine")
    monkeypatch.setattr(cli, "RUNS_DIR", directory)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"rules": [rule]}))
    code = 0
    try:
        cli.main(["audit", "--policy", str(policy), *flags, "--json"])
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def test_audit_fails_when_redaction_swallowed_a_command(tmp_path, monkeypatch, capsys):
    run = _bash_run("r-swallow", "export TOKEN=abc123secretvalue; rm -rf /")
    code, out = _audit(capsys, tmp_path, monkeypatch, run, {"id": "x", "program": "rm"})
    assert code == 1 and out["ok"] is False and out["partial"] is True
    assert out["coverage"]["redacted_commands"] >= 1
    code, out = _audit(
        capsys, tmp_path, monkeypatch, run, {"id": "x", "program": "rm"}, "--allow-partial"
    )
    assert out["partial"] is True


def test_program_names_survive_redaction_but_arguments_never_do():
    secret = "abc123secretvalue9876"
    run = Run(run_id="r-raw", model_info="m")
    step = run.add_step(StepKind.tool, {"name": "Bash", "arguments": {"command": "x"}})
    # An in-memory step whose raw command is still unredacted.
    step.inputs["arguments"]["command"] = f"export TOKEN={secret}; rm -rf /"
    (action,), _ = extract_actions(run)
    assert "rm" in action.programs and "file.delete" in action.verbs
    assert secret not in json.dumps(action.to_dict())


@pytest.mark.parametrize(
    "command, written, read",
    [
        ("cat /etc/app/config.yml > /tmp/out", ["/tmp/out"], "/etc/app/config.yml"),
        ("cp /etc/app/config.yml /tmp/copy", ["/tmp/copy"], "/etc/app/config.yml"),
        ("sed -i s/a/b/ /etc/app/x.conf", ["/etc/app/x.conf"], "s/a/b/"),
        ("sed -i -e s/a/b/ /etc/app/x.conf", ["/etc/app/x.conf"], "s/a/b/"),
    ],
)
def test_only_write_targets_count_as_written(command, written, read):
    (action,), _ = extract_actions(_bash_run("r-roles", command))
    assert action.writes == written and read not in action.writes
    index = ActionIndex(":memory:")
    index.sync([Source("k", "s", lambda: _bash_run("r-roles", command))])
    assert find(index, ActionQuery(path=written[0], writes=True))
    if read.startswith("/"):
        assert not find(index, ActionQuery(path=read, writes=True))
        assert find(index, ActionQuery(path=read))
