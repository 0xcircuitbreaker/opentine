"""0.11: the shell tool's git guard is an allowlist, contained to the shell root.

Each case asserts what :func:`opentine.tools._git_guard.refusal` says about an
argument list; nothing here runs git.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from opentine.policies import FilesystemPolicy, ShellPolicy
from opentine.tools import fs, shell
from opentine.tools._dotgit import is_dotgit
from opentine.tools._git_guard import git_env, hardened_config, is_git_family, refusal

#: Built, not written literally: the checkout meta-test flags any module naming
#: the directory, and this one only checks name normalisation.
DOTGIT = "." + "git"

#: Long options that run a program, read another configuration, or point git
#: at a template or another repository, with a subcommand that knows them.
DANGEROUS = [
    ("fetch", "--upload-pack"),
    ("ls-remote", "--upload-pack"),
    ("push", "--receive-pack"),
    ("push", "--exec"),
    ("diff", "--ext-diff"),
    ("diff", "--output"),
    ("log", "--output"),
    ("grep", "--open-files-in-pager"),
    ("grep", "--no-index"),
    ("diff", "--no-index"),
    ("clone", "--template"),
    ("clone", "--separate-git-dir"),
    ("clone", "--config"),
    ("clone", "--upload-pack"),
    ("init", "--template"),
    ("init", "--separate-git-dir"),
]


@pytest.mark.parametrize(("subcommand", "option"), DANGEROUS)
def test_every_abbreviation_of_a_dangerous_long_option_is_refused(subcommand, option, tmp_path):
    for length in range(3, len(option) + 1):
        prefix = option[:length]
        for token in (prefix, f"{prefix}=x"):
            args = [subcommand, token, "x"]
            assert refusal(args, root=tmp_path, network=True, write_out=True), args


@pytest.mark.parametrize(
    "command",
    [
        "status",
        "status --short --branch",
        "log --oneline -n 5",
        "log --format=%H --since 2.weeks",
        "show HEAD --stat",
        "diff --cached --stat",
        "diff -U3 HEAD~1",
        "add -u",
        "add src/a.py",
        "commit -m msg",
        "commit -am msg",
        "commit --amend --no-edit",
        "branch -a",
        "checkout -b topic",
        "switch -c topic",
        "restore --staged a.py",
        "rev-parse --show-toplevel",
        "ls-files -z",
        "grep -n needle",
        "blame a.py",
        "stash push -m wip",
        "tag -a v1 -m release",
        "merge --no-ff topic",
        "merge -s ours topic",
        "reset --hard HEAD",
        "--no-pager log",
        "-C sub log --oneline",
        "version",
    ],
)
def test_documented_workflows_still_run(command, tmp_path):
    (tmp_path / "sub").mkdir()
    assert refusal(command.split(), root=tmp_path) is None, command


@pytest.mark.parametrize(
    "command",
    [
        "maintenance start",
        "maintenance register",
        "credential-store get",
        "credential-cache store",
        "credential-cache--daemon x",
        "fsmonitor--daemon start",
        "help -w log",
        "help log",
        "remote add evil https://example.com/x",
        "submodule update",
        "config core.pager x",
        "filter-branch",
        "bisect run x",
        "difftool",
        "send-email x",
        "hook run pre-commit",
        "upload-pack .",
        "daemon",
        "instaweb",
        "worktree add ../x",
        "bundle create ../x.bundle HEAD",
        "apply --unsafe-paths x.patch",
    ],
)
def test_unlisted_subcommands_are_refused(command, tmp_path):
    assert refusal(command.split(), root=tmp_path, network=True, write_out=True), command


@pytest.mark.parametrize("token", ["-p", "--paginate", "--exec-path=/x", "-c", "--git-dir=x"])
def test_pager_and_configuration_globals_are_refused(token, tmp_path):
    assert refusal([token, "log"], root=tmp_path)


def test_dash_c_must_stay_inside_the_root(tmp_path):
    outside = tmp_path.parent
    (tmp_path / "inner").mkdir()
    link = tmp_path / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        link = None
    assert refusal(["-C", str(outside), "status"], root=tmp_path)
    assert refusal(["-C", "..", "status"], root=tmp_path)
    assert refusal(["-C", "inner", "-C", "../..", "status"], root=tmp_path)
    if link is not None:
        assert refusal(["-C", "escape", "status"], root=tmp_path)
    assert refusal(["-C", "inner", "status"], root=tmp_path) is None


def test_network_and_write_out_need_their_opt_ins(tmp_path):
    url = "https://example.com/repo.git"
    assert refusal(["fetch", "origin"], root=tmp_path)
    assert refusal(["fetch", "origin"], root=tmp_path, network=True) is None
    assert refusal(["init", "x"], root=tmp_path)
    assert refusal(["init", "x"], root=tmp_path, write_out=True) is None
    assert refusal(["clone", url, "x"], root=tmp_path, write_out=True)
    assert refusal(["clone", url, "x"], root=tmp_path, network=True, write_out=True) is None


def test_write_out_paths_are_contained(tmp_path):
    both = {"network": True, "write_out": True}
    assert refusal(["init", "../x"], root=tmp_path, **both)
    assert refusal(["init", str(tmp_path.parent / "x")], root=tmp_path, **both)
    assert refusal(["clone", "https://e.com/r.git", "../x"], root=tmp_path, **both)
    assert refusal(["archive", "--output=../x.tar", "HEAD"], root=tmp_path, **both)
    assert refusal(["archive", "-o", "../x.tar", "HEAD"], root=tmp_path, **both)
    assert refusal(["format-patch", "-o", "/tmp/x", "HEAD~1"], root=tmp_path, **both)
    assert refusal(["archive", "-o", "out.tar", "HEAD"], root=tmp_path, **both) is None
    assert refusal(["commit", "-F", "../msg"], root=tmp_path)
    assert refusal(["commit", "--file=../msg"], root=tmp_path)
    assert refusal(["add", "--pathspec-from-file=/etc/passwd"], root=tmp_path)
    assert refusal(["grep", "-f", "../patterns"], root=tmp_path)


@pytest.mark.parametrize(
    "source",
    ["./other", "../other", "/srv/repo", "file:///srv/repo", "ext::sh -c x", "fd::3", "x::y"],
)
def test_local_and_helper_clone_sources_are_refused(source, tmp_path):
    assert refusal(["clone", source, "x"], root=tmp_path, network=True, write_out=True)


@pytest.mark.parametrize("remote", ["/srv/repo", "file:///srv/repo", "ext::sh", "../x"])
def test_network_remotes_must_be_urls_or_names(remote, tmp_path):
    assert refusal(["push", remote, "main"], root=tmp_path, network=True)


def test_only_gits_own_merge_strategies(tmp_path):
    assert refusal(["merge", "-s", "evil", "topic"], root=tmp_path)
    assert refusal(["merge", "--strategy=evil", "topic"], root=tmp_path)
    assert refusal(["merge", "-sevil", "topic"], root=tmp_path)


def test_git_env_drops_the_environment_spellings_of_dash_c():
    hostile = {
        name: "x"
        for name in (
            "GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_GLOBAL", "GIT_EXEC_PATH",
            "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_ASKPASS", "GIT_TEMPLATE_DIR",
            "PAGER", "EDITOR", "VISUAL", "git_dir",
        )
    }  # fmt: skip
    env = git_env({**hostile, "PATH": "/usr/bin", "HOME": "/h"})
    assert env["PATH"] == "/usr/bin" and env["HOME"] == "/h"
    assert not {"GIT_DIR", "PAGER", "EDITOR", "VISUAL", "git_dir"} & env.keys()
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_PAGER"] == "cat" and env["GIT_EDITOR"] == "true"
    assert env["GIT_PROTOCOL_FROM_USER"] == "0"


def test_hardened_config_turns_off_hooks_pager_external_diff_and_transports():
    joined = " ".join(hardened_config())
    for setting in (
        f"core.hooksPath={os.devnull}",
        "core.pager=cat",
        "diff.external=",
        "protocol.allow=never",
        "core.fsmonitor=",
        "safe.bareRepository=explicit",
    ):
        assert setting in joined  # fmt: skip
    assert "protocol.https.allow=always" not in joined
    assert "protocol.https.allow=always" in " ".join(hardened_config(network=True))


@pytest.mark.parametrize(
    ("name", "family"),
    [("git-upload-pack", True), ("/usr/lib/git-core/git-shell", True), ("scalar", True),
     ("Scalar.exe", True), ("git", False), ("/usr/bin/git", False), ("gitk", False)],
)  # fmt: skip
def test_git_family_programs_are_recognised(name, family):
    assert is_git_family(name) is family


def test_shell_refuses_git_helpers_and_runs_the_resolved_program(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    spawned: list[tuple] = []
    monkeypatch.setattr(shell, "run_bounded", lambda *a, **k: spawned.append((a, k)))
    helper = ShellPolicy(enabled=True, executables=("git-upload-pack",), cwd_root=str(tmp_path))
    assert shell.run("git-upload-pack .", policy=helper).startswith("Error:")
    assert not spawned
    monkeypatch.setenv("GIT_DIR", "/elsewhere")
    monkeypatch.setenv("PAGER", "evil")
    policy = ShellPolicy(
        enabled=True, executables=("git",), cwd_root=str(tmp_path), inherit_env=True
    )
    monkeypatch.setattr(shell.shutil, "which", lambda name: f"/opt/bin/{name}")
    shell.run("git status", policy=policy)
    (argv,), kwargs = spawned[0]
    assert argv[0] == "/opt/bin/git" and "core.pager=cat" in argv
    assert "GIT_DIR" not in kwargs["env"] and "PAGER" not in kwargs["env"]
    assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"


def test_an_allowlisted_name_that_resolves_to_nothing_is_refused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(shell.shutil, "which", lambda name: None)
    policy = ShellPolicy(enabled=True, executables=("tool",), cwd_root=str(tmp_path))
    assert "not found" in shell.run("tool --help", policy=policy)


@pytest.mark.parametrize(
    ("part", "dotgit"),
    [(DOTGIT, True), (".GIT", True), (".git.", True), (".git ", True), (".git. . ", True),
     ("GIT~1", True), ("git~12", True), (".git::$INDEX_ALLOCATION", True),
     (".g‌it", True), ("﻿.git", True), (".gi‍t", True),
     (".gitignore", False), ("git", False), (".github", False), ("my.git", False)],
)  # fmt: skip
def test_dotgit_aliases(part, dotgit):
    assert is_dotgit(part) is dotgit


@pytest.mark.parametrize("name", [".git.", ".git ", "GIT~1", ".g‌it"])
def test_fs_refuses_writes_through_dotgit_aliases(name, tmp_path):
    policy = FilesystemPolicy(roots=(str(tmp_path),), write_roots=(str(tmp_path),))
    target = Path(tmp_path) / name / "config"
    with pytest.raises((PermissionError, ValueError, OSError)):
        fs.write(str(target), "[core]\n", policy=policy)


# --- 0.11 audit follow-ups: pathspecs and git's real working directory ----------


@pytest.mark.parametrize(
    "args",
    [
        ["rm", "-r", "../etc"],
        ["mv", "a", "../../x"],
        ["checkout", "HEAD", "--", "../x"],
        ["restore", "--source=HEAD", "../x"],
        ["add", ":(top)"],
        ["add", ":/"],
        ["reset", "HEAD", "--", "/etc/passwd"],
        ["stash", "push", "--", "../x"],
        ["diff", "HEAD", "--", "../secret"],
    ],
)
def test_pathspecs_must_stay_inside_the_root(tmp_path, args):
    assert refusal(args, root=tmp_path) is not None


@pytest.mark.parametrize(
    "args",
    [
        ["add", "src/app.py"],
        ["checkout", "main"],
        ["log", "--oneline", "HEAD~3..HEAD"],
        ["show", "HEAD:README.md"],
        ["diff", "HEAD", "--", "src"],
        ["restore", "--staged", "file.txt"],
    ],
)
def test_ordinary_pathspecs_still_work(tmp_path, args):
    assert refusal(args, root=tmp_path) is None


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privilege on Windows")
def test_paths_resolve_from_gits_real_working_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("s", encoding="utf-8")
    root = tmp_path / "root"
    sub = root / "sub"
    sub.mkdir(parents=True)
    os.symlink(outside, sub / "l")
    # From the root, "l/secret" names nothing outside; from sub it escapes.
    assert refusal(["commit", "-F", "l/secret"], root=root) is None
    assert refusal(["commit", "-F", "l/secret"], root=root, cwd=sub) is not None
    assert refusal(["add", "l/secret"], root=root, cwd=sub) is not None


# --- an option that takes no value must never hide the next token ----------


@pytest.mark.parametrize(
    "args",
    [
        ["log", "--pretty", "--output=out.txt"],
        ["show", "--pretty", "--output=../o"],
        ["log", "--unified", "--output=out.txt"],
        ["merge", "--squash", "--file=../secret"],
        ["merge", "--squash", "-s", "evil"],
        ["status", "--ignore-submodules", "--porcelain=v2", "--zz"],
        ["diff", "-U", "--output=../x"],
        ["branch", "-t", "--edit-description"],
    ],
)
def test_a_flag_is_not_read_as_taking_the_next_argument(tmp_path, args):
    assert refusal(args, root=tmp_path) is not None


@pytest.mark.parametrize(
    "args",
    [
        ["diff", "-U5"],
        ["log", "-M20", "--stat"],
        ["status", "-uno"],
        ["log", "--pretty=oneline", "-n", "3"],
        ["commit", "--squash", "HEAD", "-m", "x"],
        ["log", "-S", "needle"],
        ["switch", "--create", "topic"],
        ["blame", "-M20", "README.md"],
    ],
)
def test_attached_and_required_values_still_parse(tmp_path, args):
    assert refusal(args, root=tmp_path) is None


def _takes_next(subcommand: str, option: str) -> bool:
    from opentine.tools import _git_policy as policy

    if option.startswith("--"):
        named = option in policy.VALUE_LONG or option in policy.VALUE_LONG_FOR.get(subcommand, ())
        return named and option not in policy.OPTIONAL_VALUE_LONG
    letter = option[1]
    return letter in policy.VALUE_SHORT.get(
        subcommand, ""
    ) and letter not in policy.OPTIONAL_VALUE_SHORT.get(subcommand, "")


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_every_option_the_guard_reads_a_value_for_takes_one_in_git(tmp_path):
    """The guard skips the token after a value-taking option; git must agree.

    Asked of the installed git: ``git <sub> <option> --zzprobe`` reports
    ``--zzprobe`` as an unknown option exactly when ``<option>`` did not take it.
    """
    from opentine.tools import _git_policy as policy

    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_EDITOR": "true",
        "GIT_PAGER": "cat",
        "GIT_AUTHOR_NAME": "a",
        "GIT_AUTHOR_EMAIL": "a@example.invalid",
        "GIT_COMMITTER_NAME": "a",
        "GIT_COMMITTER_EMAIL": "a@example.invalid",
    }
    unknown = re.compile(
        r"(unknown option|unrecognized argument|unknown switch|invalid option)[^\n]{0,8}zzprobe"
    )
    tables = {**policy.SUBCOMMANDS, **policy.NETWORK, **policy.WRITE_OUT}
    disagree = []
    for number, (subcommand, (longs, shorts)) in enumerate(sorted(tables.items())):
        options = [name for name in sorted(longs) if _takes_next(subcommand, name)]
        options += [f"-{letter}" for letter in shorts if _takes_next(subcommand, f"-{letter}")]
        for count, option in enumerate(options):
            repo = tmp_path / f"r{number}-{count}"
            subprocess.run(["git", "init", "-q", str(repo)], env=env, check=True)
            (repo / "f").write_text("x\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "f"], env=env, check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "c"], env=env, check=True)
            probe = ["git", "-c", "protocol.allow=never", "-C", str(repo), subcommand, option]
            done = subprocess.run(
                [*probe, "--zzprobe"],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                stdin=subprocess.DEVNULL,
            )
            if unknown.search(done.stdout + done.stderr):
                disagree.append(f"{subcommand} {option}")
    assert disagree == []


# --- audit round 4 -----------------------------------------------------------


@pytest.mark.parametrize("subcommand", ["add", "reset", "commit"])
def test_pathspec_from_file_is_not_an_option_any_more(tmp_path, subcommand):
    # The file's pathspecs (":(top)x", "../x") were never checked.
    (tmp_path / "list").write_text(":(top)top.txt\n", encoding="utf-8")
    assert refusal([subcommand, "--pathspec-from-file=list"], root=tmp_path)
    assert refusal([subcommand, "--pathspec-from-file", "list"], root=tmp_path)


def _nested(tmp_path):
    """A shell root ``sub`` inside a larger repository rooted at ``tmp_path``."""
    (tmp_path / DOTGIT).mkdir()
    sub = tmp_path / "sub"
    sub.mkdir()
    return sub


WHOLE_TREE = [
    ["reset", "--hard"],
    ["reset", "--keep"],
    ["reset"],
    ["reset", "HEAD"],
    ["commit", "-a", "-m", "x"],
    ["commit", "-am", "x"],
    ["commit", "--all", "-m", "x"],
    ["add", "-A"],
    ["add", "--all"],
    ["add", "-u"],
    ["add", "--update"],
    ["stash"],
    ["stash", "push"],
    ["stash", "-u"],
    ["stash", "pop"],
    ["merge", "main"],
    ["switch", "main"],
    ["checkout", "main"],
]


@pytest.mark.parametrize("arguments", WHOLE_TREE)
def test_whole_tree_forms_are_refused_below_the_repository_top(tmp_path, arguments):
    assert refusal(arguments, root=_nested(tmp_path))


@pytest.mark.parametrize("arguments", WHOLE_TREE)
def test_whole_tree_forms_are_allowed_at_the_repository_top(tmp_path, arguments):
    (tmp_path / DOTGIT).mkdir()
    assert refusal(arguments, root=tmp_path) is None


@pytest.mark.parametrize(
    "arguments",
    [
        ["add", "-A", "f"],
        ["add", "f"],
        ["reset", "--", "f"],
        ["reset", "HEAD", "--", "f"],
        ["checkout", "HEAD", "--", "f"],
        ["commit", "-m", "x"],
        ["stash", "list"],
        ["status"],
        ["log", "-1"],
    ],
)
def test_contained_forms_still_work_below_the_repository_top(tmp_path, arguments):
    assert refusal(arguments, root=_nested(tmp_path)) is None


def test_a_repository_inside_the_root_is_not_whole_tree(tmp_path):
    inner = tmp_path / "inner"
    (inner / DOTGIT).mkdir(parents=True)
    assert refusal(["reset", "--hard"], root=tmp_path, cwd=inner) is None
