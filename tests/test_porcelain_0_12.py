"""0.12 git-parity porcelain: remote, pull, branch, tag, reflog, reset, config,
log --graph, hooks, .tineignore, rebase, cherry-pick and verb unification."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from opentine import Run, StepKind, _hooks, _tineignore, cli
from opentine import _porcelain_config as porcelain
from opentine._cli_git_sync import is_ancestor
from opentine.repository import Repo


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli, "RUNS_DIR", Path(".tine_runs"))
    store = Repo.init(tmp_path)
    run = Run(id="base0001", model_info="m-old")
    for index in range(3):
        run.add_step(StepKind.model, {"text": str(index)}, {"text": "ok"})
    store.put_run(run, ref="heads/main")
    return store


def _cli(capsys, argv: list[str]) -> str:
    capsys.readouterr()
    cli.main(argv)
    return capsys.readouterr().out


def _json(capsys, argv: list[str]):
    return json.loads(_cli(capsys, [*argv, "--json"]))


def _fails(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code not in (0, None)


# -- remotes / config / trust -------------------------------------------------------


def test_remote_add_ls_rename_rm_stores_no_secret(repo, capsys):
    cli.main(["remote", "add", "origin", "https://tine.example/r", "--token-file", "tok.txt"])
    raw = (repo.path / "porcelain.json").read_text()
    assert "tok.txt" in raw and "Bearer" not in raw
    assert _json(capsys, ["remote"])["remotes"]["origin"]["url"] == "https://tine.example/r"
    cli.main(["remote", "rename", "origin", "up"])
    cli.main(["remote", "rm", "up"])
    assert _json(capsys, ["remote"])["remotes"] == {}


@pytest.mark.parametrize("url", ["ftp://x", "https://u:p@h/r", "https://h/r?token=1", "nope"])
def test_remote_add_refuses_bad_urls(repo, url):
    _fails(["remote", "add", "origin", url])


def test_config_set_get_unset_and_trust_revocation(repo, capsys):
    cli.main(["config", "alias.st", "log --oneline"])
    assert _cli(capsys, ["config", "alias.st"]).strip() == "log --oneline"
    assert porcelain.trusted(repo.path)
    # An edit by anything but `tine config` revokes trust: alias/hooks go inert.
    path = repo.path / "porcelain.json"
    path.write_text(path.read_text().replace("--oneline", "--graph"))
    assert not porcelain.trusted(repo.path)
    assert "alias.st" not in porcelain.effective(repo.path)
    cli.main(["config", "--trust"])
    assert porcelain.effective(repo.path)["alias.st"] == "log --graph"
    cli.main(["config", "alias.st", "--unset"])
    _fails(["config", "alias.st"])


def test_untrusted_remote_token_file_is_refused(repo):
    cli.main(["remote", "add", "origin", "https://h/r", "--token-file", "/etc/hostname"])
    path = repo.path / "porcelain.json"
    path.write_text(path.read_text() + " ")  # e.g. arrived in a clone
    with pytest.raises(ValueError, match="not trusted"):
        porcelain.remote(repo.path, "origin")


def test_porcelain_file_rejects_unknown_shape(repo):
    (repo.path / "porcelain.json").write_text('{"remotes": {}, "evil": 1}')
    with pytest.raises(ValueError):
        porcelain.load(repo.path)


# -- branch / tag / reflog / reset --------------------------------------------------------


def test_branch_create_list_delete_and_reflog_recovery(repo, capsys):
    main = repo.read_ref("heads/main")
    cli.main(["branch", "feature"])
    assert _json(capsys, ["branch"])["branches"] == {"heads/feature": main, "heads/main": main}
    _fails(["branch", "feature"])  # create-only without --force
    _fails(["branch", "-d", "main"])  # protected
    cli.main(["branch", "-d", "feature"])
    assert repo.read_ref("heads/feature") is None
    rows = _json(capsys, ["reflog", "heads/feature"])["entries"]
    assert rows[0]["new"] is None and rows[1]["new"] == main
    cli.main(["reset", "heads/feature", main])
    assert repo.read_ref("heads/feature") == main


def test_reset_expect_is_compare_and_swap(repo):
    main = repo.read_ref("heads/main")
    _fails(["reset", "heads/main", main, "--expect", "run:sha256:" + "0" * 64])
    cli.main(["reset", "heads/main", main, "--expect", main])


def test_v3_tag_create_list_force_delete(repo, capsys):
    main = repo.read_ref("heads/main")
    cli.main(["tag", "v1"])
    assert repo.read_ref("tags/v1") == main
    assert _json(capsys, ["tag"])["tags"] == {"v1": main}
    _fails(["tag", "v1", "heads/main"])
    cli.main(["tag", "v1", "heads/main", "--force"])
    cli.main(["tag", "-d", "v1"])
    assert repo.read_ref("tags/v1") is None


def test_signed_tag_verifies_and_unsigned_does_not(repo, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("TAG_KEY", "k" * 40)
    cli.main(["tag", "-s", "rel", "--key-env", "TAG_KEY"])
    assert _json(capsys, ["verify-tag", "rel", "--key-env", "TAG_KEY"])["ok"] is True
    cli.main(["tag", "plain"])
    _fails(["verify-tag", "plain", "--key-env", "TAG_KEY"])
    monkeypatch.setenv("WRONG", "w" * 40)
    _fails(["verify-tag", "rel", "--key-env", "WRONG"])


def test_legacy_tag_labels_still_work(repo, capsys):
    run = Run(id="legacy01")
    run.add_step(StepKind.done, {"text": "x"})
    Path(".tine_runs").mkdir()
    run.save(Path(".tine_runs/legacy01.tine"))
    cli.main(["tag", "legacy01", "--add", "keep"])
    assert repo.read_ref("tags/legacy01") is None
    assert "keep" in _cli(capsys, ["tag", "legacy01", "--list"])


# -- log / rebase / cherry-pick ------------------------------------------------------------


def test_rebase_and_cherry_pick_show_in_graph(repo, capsys):
    main = repo.read_ref("heads/main")
    rebased = _json(capsys, ["rebase", "heads/main", "--onto-model", "m-new", "--from-step", "2"])
    payload = repo.get(rebased["run_id"]).payload()
    assert payload["model"] == "m-new" and payload["forked_from"] == main
    assert len(payload["events"]) == 2
    assert rebased["ref"].startswith("experiments/rebase/")
    picked = _json(capsys, ["cherry-pick", "heads/main:3", "--onto", rebased["ref"]])
    new = repo.get(picked["run_id"]).payload()
    assert len(new["events"]) == 3 and new["tips"] == [new["events"][-1]]
    assert repo.get(new["events"][-1]).payload()["parent_ids"] == [payload["tips"][-1]]
    assert repo.read_ref(rebased["ref"]) == rebased["run_id"]  # onto run untouched
    graph = _cli(capsys, ["log", "--graph", "--all"])
    assert graph.count("* ") == 3 and "|\\" in graph and "m-new" in graph
    runs = _json(capsys, ["log", "--all"])["runs"]
    assert {run["run_id"] for run in runs} >= {main, rebased["run_id"], picked["run_id"]}
    assert is_ancestor(repo, main, picked["run_id"])
    assert not is_ancestor(repo, picked["run_id"], main)


def test_rebase_rejects_out_of_range_step(repo):
    _fails(["rebase", "heads/main", "--onto-model", "m", "--from-step", "99"])


def test_plain_log_without_graph_is_the_event_log(repo, capsys):
    assert _cli(capsys, ["log"]) == _cli(capsys, ["repo-log", "heads/main"])


# -- unification ---------------------------------------------------------------------------


def test_plain_show_and_diff_use_the_v3_repo(repo, capsys):
    assert _cli(capsys, ["show", "heads/main"]) == _cli(capsys, ["repo-show", "heads/main"])
    cli.main(["branch", "b2"])
    assert json.loads(_cli(capsys, ["diff", "heads/main", "heads/b2", "--json"]))


def test_plain_fork_with_ref_forks_in_the_repo(repo):
    cli.main(["fork", "heads/main", "--from-step", "1", "--ref", "experiments/f1"])
    assert repo.read_ref("experiments/f1") is not None


# -- hooks ------------------------------------------------------------------------------------


def _hook(repo: Repo, name: str, body: str) -> None:
    (repo.path / "hooks").mkdir(exist_ok=True)
    (repo.path / "hooks" / f"{name}.py").write_text(body)


def test_hooks_are_off_until_enabled_and_trusted(repo, tmp_path):
    marker = tmp_path / "ran"
    _hook(repo, "post-run", f"open({str(marker)!r}, 'w').write('x')\n")
    assert not _hooks.run_hook(repo.path, "post-run").ran
    cli.main(["config", "hooks.enabled", "true"])
    cli.main(["config", "--trust"])  # hooks written before the first config need review
    assert _hooks.run_hook(repo.path, "post-run").ok and marker.exists()
    path = repo.path / "porcelain.json"
    path.write_text(path.read_text() + "\n")  # an untrusted edit disables hooks again
    assert not _hooks.run_hook(repo.path, "post-run").ran


def test_hook_env_is_scrubbed_and_pre_hook_refusal_aborts(repo, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    cli.main(["config", "hooks.enabled", "true"])
    _hook(
        repo,
        "pre-record",
        "import os, sys\nsys.exit(3 if 'ANTHROPIC_API_KEY' in os.environ else 7)\n",
    )
    cli.main(["config", "--trust"])  # a hook added after trust needs a new review
    result = _hooks.run_hook(repo.path, "pre-record")
    assert result.returncode == 7
    _fails(["rebase", "heads/main", "--onto-model", "m"])


def test_hook_timeout(repo):
    cli.main(["config", "hooks.enabled", "true"])
    cli.main(["config", "hooks.timeout", "1"])
    _hook(repo, "post-fetch", "import time\ntime.sleep(30)\n")
    cli.main(["config", "--trust"])
    result = _hooks.run_hook(repo.path, "post-fetch")
    assert not result.ok and "timed out" in result.output


def test_symlinked_hook_is_refused(repo, tmp_path):
    if sys.platform == "win32":
        pytest.skip("symlinks need privileges on Windows")
    cli.main(["config", "hooks.enabled", "true"])
    (repo.path / "hooks").mkdir()
    target = tmp_path / "elsewhere.py"
    target.write_text("")
    (repo.path / "hooks" / "post-run.py").symlink_to(target)
    cli.main(["config", "--trust"])
    with pytest.raises(ValueError, match="symlink|regular file"):
        _hooks.run_hook(repo.path, "post-run")


# -- .tineignore ---------------------------------------------------------------------------------


PATCH = (
    "diff --git a/src/app.py b/src/app.py\n+ok\n"
    "diff --git a/dist/bundle.js b/dist/bundle.js\n+huge\n"
    "diff --git a/config/prod.env b/config/prod.env\n+API_KEY=secret\n"
)


def test_tineignore_excludes_and_redacts():
    rules = _tineignore.parse("# c\ndist/\nredact:config/*.env\n")
    out = _tineignore.filter_patch(PATCH, rules)
    assert "+ok" in out and "bundle" not in out
    assert "config/prod.env" in out and "secret" not in out and _tineignore.REDACTED in out
    assert _tineignore.filter_paths(["dist/a/b.js", "x.py"], rules) == ["x.py"]


def test_tineignore_limits(tmp_path):
    (tmp_path / ".tineignore").write_text("x\n" * (_tineignore.MAX_PATTERNS + 1))
    with pytest.raises(ValueError):
        _tineignore.load(tmp_path)
    assert not _tineignore.load(tmp_path / "missing")


def test_alias_expands_only_when_trusted_and_never_shadows(repo, capsys):
    cli.main(["config", "alias.graph", "log --graph --all"])
    assert "* " in _cli(capsys, ["graph"])
    cli.main(["config", "alias.show", "branch -d main --force"])
    assert repo.read_ref("heads/main")  # builtin `show` is never shadowed
    path = repo.path / "porcelain.json"
    path.write_text(path.read_text() + " ")
    _fails(["graph"])


@pytest.mark.parametrize(
    "argv",
    [["remote", "add", "origin", "https://tine.example/r"], ["config", "user.name", "x"]],
)
def test_a_cloned_porcelain_file_stays_untrusted_after_a_harmless_write(repo, tmp_path, argv):
    # A cloned repo ships hooks.enabled and an alias; an ordinary write must not
    # silently trust them (audit 0.12 #2).
    (repo.path / "porcelain.json").write_text(
        json.dumps({"config": {"hooks.enabled": "true", "alias.st": "log"}, "remotes": {}})
    )
    marker = tmp_path / "planted-ran"
    _hook(repo, "post-run", f"open({str(marker)!r}, 'w').write('x')\n")
    cli.main(argv)
    assert not porcelain.trusted(repo.path)
    assert "alias.st" not in porcelain.effective(repo.path)
    assert not _hooks.run_hook(repo.path, "post-run").ran
    assert not marker.exists()


# -- 0.12 audit round 2: trust covers hooks; untrusted remotes carry no credential -------


def test_a_hook_changed_after_trust_does_not_run(repo, tmp_path):
    marker = tmp_path / "ran"
    _hook(repo, "post-run", "pass\n")
    cli.main(["config", "hooks.enabled", "true"])
    cli.main(["config", "--trust"])
    assert _hooks.run_hook(repo.path, "post-run").ran
    _hook(repo, "post-run", f"open({str(marker)!r}, 'w').write('x')\n")  # edited later
    assert not _hooks.run_hook(repo.path, "post-run").ran and not marker.exists()
    _hook(repo, "pre-push", "pass\n")  # a new hook file also revokes trust
    cli.main(["config", "--trust"])
    assert _hooks.run_hook(repo.path, "post-run").ran and marker.exists()


def test_an_untrusted_remote_never_receives_the_operators_token(repo, monkeypatch):
    import http.server
    import threading

    seen: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen.append(self.headers.get("Authorization") or "")
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/x"
        (repo.path / "porcelain.json").write_text(
            json.dumps({"remotes": {"origin": {"url": url, "tenant": "t1"}}, "config": {}})
        )
        monkeypatch.setenv("TINE_REMOTE_TOKEN", "s3cret-token")
        for argv in (["pull"], ["fetch", "origin"]):
            with pytest.raises(SystemExit):
                cli.main(argv)
        assert not any("s3cret" in header for header in seen)
        assert seen == []  # the untrusted remote is not contacted at all
    finally:
        server.shutdown()


# -- 0.12 audit round 4: no implicit trust of hooks shipped without a porcelain file --------


def test_a_first_write_does_not_trust_shipped_hooks(repo, tmp_path, capsys):
    # A cloned project ships .tine/hooks/ but no porcelain.json: the first harmless
    # write must not record those unreviewed hooks as trusted.
    assert not (repo.path / "porcelain.json").exists()
    marker = tmp_path / "shipped-ran"
    _hook(repo, "post-run", f"open({str(marker)!r}, 'w').write('x')\n")
    cli.main(["config", "hooks.enabled", "true"])
    assert not porcelain.trusted(repo.path)
    assert "tine config --trust" in capsys.readouterr().err
    assert not _hooks.run_hook(repo.path, "post-run").ran and not marker.exists()
    cli.main(["config", "--trust"])  # the explicit review makes them live
    assert _hooks.run_hook(repo.path, "post-run").ran and marker.exists()


def test_a_first_write_with_no_hooks_is_trusted(repo):
    cli.main(["config", "user.name", "x"])
    assert porcelain.trusted(repo.path)
