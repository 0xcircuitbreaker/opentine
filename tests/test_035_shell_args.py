"""0.35: allowlisted executables are checked at the argument level too."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from opentine.policies import ShellPolicy
from opentine.tools import shell


def _policy(tmp_path, *names):
    return ShellPolicy(enabled=True, executables=names, cwd_root=str(tmp_path))


@pytest.fixture
def ws(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.txt").write_text("hello\n")
    return tmp_path


@pytest.mark.parametrize(
    "command",
    [
        "find . -exec touch pwned ;",
        "find . -execdir touch pwned ;",
        "find . -delete",
        "find . -fprint out",
    ],
)
def test_find_cannot_run_or_delete(ws, command):
    out = shell.run(command, policy=_policy(ws, "find"))
    assert out.startswith("Error:")
    assert not (ws / "pwned").exists() and (ws / "a.txt").exists()


@pytest.mark.parametrize(
    "command",
    [
        "sed -i s/hello/bye/ a.txt",
        "sed -ni p a.txt",
        "sed --in-place=.bak s/x/y/ a.txt",
        "sed 1e\\ touch\\ pwned a.txt",
        pytest.param(
            "sed s/hello/touch\\ pwned/e a.txt",
            marks=pytest.mark.skipif(sys.platform == "win32", reason="posix shell quoting"),
        ),
        "sed s/hello/date/e a.txt",
        "sed s/x/y/w\\ out a.txt",
        "sed -n 1w\\ out a.txt",
    ],
)
def test_sed_cannot_execute_or_write(ws, command):
    out = shell.run(command, policy=_policy(ws, "sed"))
    assert out.startswith("Error:"), out
    assert (ws / "a.txt").read_text().strip() == "hello"
    assert not (ws / "pwned").exists() and not (ws / "out").exists()


@pytest.mark.parametrize(
    "command",
    [
        "tar --to-command=sh -xf x.tar",
        "tar --checkpoint=1 --checkpoint-action=exec=sh -cf x.tar a.txt",
        "tar -I sh -cf x.tar a.txt",
        "tar --use-compress-program=sh -cf x.tar a.txt",
    ],
)
def test_tar_cannot_run_commands(ws, command):
    assert shell.run(command, policy=_policy(ws, "tar")).startswith("Error:")


@pytest.mark.parametrize("wrapper", ["xargs", "env", "nice", "timeout", "sh"])
def test_program_runners_are_refused(ws, wrapper):
    out = shell.run(f"{wrapper} touch pwned", policy=_policy(ws, wrapper))
    assert out.startswith("Error:")
    assert not (ws / "pwned").exists()


@pytest.mark.parametrize(
    "command",
    ["cat /etc/passwd", "cat ../secret", "cat --file=/etc/passwd", "cat ~/x"],
)
def test_path_arguments_stay_inside_workspace(ws, command):
    out = shell.run(command, policy=_policy(ws, "cat"))
    assert "escapes shell policy root" in out


def test_symlink_out_of_workspace_is_refused(ws, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "secret"
    outside.write_text("secret")
    (ws / "link").symlink_to(outside)
    out = shell.run("cat link", policy=_policy(ws, "cat"))
    assert "escapes shell policy root" in out


@pytest.mark.skipif(shutil.which("sed") is None, reason="needs sed")
def test_ordinary_use_still_works(ws):
    (ws / "sub").mkdir()
    assert shell.run("cat a.txt", policy=_policy(ws, "cat")).strip() == "hello"
    assert "hello" in shell.run("cat sub/../a.txt", policy=_policy(ws, "cat"))
    assert shell.run("sed s/hello/bye/ a.txt", policy=_policy(ws, "sed")).strip() == "bye"
    if sys.platform != "win32":  # Windows' own FIND.EXE shadows GNU find on PATH
        assert "a.txt" in shell.run("find . -name *.txt", policy=_policy(ws, "find"))
    assert shell.run("python3 -c print(1)", policy=_policy(ws, "python3")).strip() == "1"


@pytest.mark.parametrize(
    "command",
    [
        "sed -ee date x.txt",
        "sed -n -e1e x.txt",
        "sed --expression=1e x.txt",
        "sed --expr=1e x.txt",
        "tar --use-compress=sh -cf o.tar x.txt",
        "tar --to-com=sh -xf o.tar",
        "tar cIf sh o.tar x.txt",
        "tar --rmt-command=sh -cf o.tar x.txt",
    ],
)
def test_abbreviated_attached_and_old_style_options_are_refused(command):
    from opentine.tools._shell_args import refusal

    parts = command.split()
    assert refusal(parts, root=Path.cwd(), cwd=Path.cwd()) is not None


def test_rooted_paths_without_a_drive_count_as_escapes(ws):
    from opentine.tools._shell_args import _escapes

    assert _escapes("/etc/passwd", ws, ws)
    assert _escapes("\\Windows\\win.ini", ws, ws) or sys.platform != "win32"
