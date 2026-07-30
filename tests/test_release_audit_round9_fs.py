"""Regressions for the v0.3.0 final-gate audit (group fs).

Round 8 (d3db14c) made fs.read() raw (newline="") to match fs.edit(), but left
fs.write() on Path.write_text(), whose newline=None text mode translates every
"\n" written to os.linesep. On Windows that turns the canonical agent flow
read -> transform -> write into silent, compounding corruption: every CRLF
becomes \r\r\n, one extra CR per round trip. The same class lives in
tools/python.py, which wrote model-authored code through newline=None handles.

On Linux the newline=None write translation is a no-op (os.linesep == "\n"),
so a naive byte test passes even against the bug. These tests therefore pin
the behavior at the io layer: `_windows_text_semantics` rewrites every
text-mode write opened with newline=None to newline="\r\n" - by CPython's
documented contract ("any '\\n' characters written are translated to the
system default line separator, os.linesep") that is *exactly* what
newline=None means on Windows, while writes opened with an explicit
newline="" are untouched on every platform. Under this patch the pre-fix
code fails on Linux too; code is only green if translation cannot occur.
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from opentine.policies import FilesystemPolicy, PythonPolicy
from opentine.tools import fs
from opentine.tools import python as pytool

_REAL_PATH_OPEN = pathlib.Path.open
_REAL_NAMED_TEMPFILE = tempfile.NamedTemporaryFile


def _win_open(self, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
    if "b" not in mode and any(m in mode for m in "wax+") and newline is None:
        newline = "\r\n"  # what newline=None resolves to on Windows (os.linesep)
    return _REAL_PATH_OPEN(self, mode, buffering, encoding, errors, newline)


def _win_write_text(self, data, encoding=None, errors=None, newline=None):
    with _win_open(self, "w", encoding=encoding, errors=errors, newline=newline) as handle:
        return handle.write(data)


def _win_named_tempfile(mode="w+b", *args, **kwargs):
    if "b" not in mode and kwargs.get("newline") is None:
        kwargs["newline"] = "\r\n"
    return _REAL_NAMED_TEMPFILE(mode, *args, **kwargs)


@pytest.fixture
def _windows_text_semantics(monkeypatch):
    monkeypatch.setattr(pathlib.Path, "open", _win_open)
    monkeypatch.setattr(pathlib.Path, "write_text", _win_write_text)
    monkeypatch.setattr(tempfile, "NamedTemporaryFile", _win_named_tempfile)


@pytest.mark.usefixtures("_windows_text_semantics")
def test_fs_write_stores_exact_bytes_under_windows_semantics(tmp_path):
    # write() must be byte-faithful like read()/edit(): "a\r\nb" stores those
    # exact bytes on ANY platform, never "a\r\r\nb".
    target = tmp_path / "crlf.txt"
    fs.write(str(target), "a\r\nb\r\nc\n", sandbox=str(tmp_path))
    assert target.read_bytes() == b"a\r\nb\r\nc\n"


@pytest.mark.usefixtures("_windows_text_semantics")
@pytest.mark.parametrize(
    "raw",
    [
        b"alpha\r\nbeta\r\ngamma\r\n",  # CRLF
        b"alpha\nbeta\ngamma\n",  # LF
        b"alpha\rbeta\rgamma\r",  # bare CR
        b"alpha\r\nbeta\ngamma\rdelta",  # mixed, no trailing newline
    ],
)
def test_fs_read_write_round_trip_is_byte_identical(tmp_path, raw):
    # The canonical agent flow: read a file, write it back. Two round trips
    # must be byte-identical for CRLF, LF, CR and mixed-endings files - the
    # pre-fix code compounded one CR per line per trip on Windows.
    path = tmp_path / "file.txt"
    path.write_bytes(raw)
    for _ in range(2):
        fs.write(str(path), fs.read(str(path), sandbox=str(tmp_path)), sandbox=str(tmp_path))
        assert path.read_bytes() == raw


@pytest.mark.usefixtures("_windows_text_semantics")
def test_fs_write_then_read_is_identity(tmp_path):
    # write(x) then read() must return x: pre-fix Windows returned "a\r\nb\r\n"
    # for a written "a\nb\n", so agents edited text they never wrote.
    path = tmp_path / "id.txt"
    fs.write(str(path), "a\nb\n", sandbox=str(tmp_path))
    assert fs.read(str(path), sandbox=str(tmp_path)) == "a\nb\n"


@pytest.mark.usefixtures("_windows_text_semantics")
def test_fs_write_then_edit_agrees_on_content(tmp_path):
    # An agent must be able to edit the exact text it just wrote; pre-fix
    # Windows silently converted LF to CRLF so multi-line `old` never matched.
    path = tmp_path / "edit.txt"
    fs.write(str(path), "one\ntwo\nthree\n", sandbox=str(tmp_path))
    fs.edit(str(path), "one\ntwo", "ONE\ntwo", sandbox=str(tmp_path))
    assert path.read_bytes() == b"ONE\ntwo\nthree\n"


@pytest.mark.usefixtures("_windows_text_semantics")
def test_fs_write_budget_matches_bytes_on_disk(tmp_path):
    # write() checks len(content.encode()) against max_file_bytes; the bytes
    # laid down must match, or write() creates files read() then refuses.
    policy = FilesystemPolicy(
        roots=(str(tmp_path),), write_roots=(str(tmp_path),), max_file_bytes=16
    )
    path = tmp_path / "budget.txt"
    content = "x\n" * 8  # exactly 16 bytes
    fs.write(str(path), content, policy=policy)
    assert path.stat().st_size == 16
    assert fs.read(str(path), policy=policy) == content


@pytest.mark.usefixtures("_windows_text_semantics")
def test_python_execute_writes_model_code_verbatim(tmp_path):
    # Model-authored code must land on disk byte-for-byte: pre-fix Windows
    # turned CRLF code into \r\r\n, corrupting embedded string literals.
    code = "import pathlib\r\nprint(pathlib.Path(__file__).read_bytes().hex())\r\n"
    output = pytool.execute(code, policy=PythonPolicy(enabled=True))
    assert bytes.fromhex(output.strip()) == code.encode("utf-8")


@pytest.mark.usefixtures("_windows_text_semantics")
def test_python_execute_unsafe_legacy_writes_model_code_verbatim(tmp_path):
    code = "import pathlib\r\nprint(pathlib.Path(__file__).read_bytes().hex())\r\n"
    output = pytool.execute_unsafe_legacy(code)
    assert bytes.fromhex(output.strip()) == code.encode("utf-8")


def test_fs_tools_are_byte_faithful_on_this_platform(tmp_path):
    # No emulation: on the real host (including Windows CI) write -> read ->
    # write must preserve bytes for content mixing every line-ending style.
    path = tmp_path / "native.txt"
    content = "a\r\nb\nc\rd"
    fs.write(str(path), content, sandbox=str(tmp_path))
    assert path.read_bytes() == content.encode("utf-8")
    round_tripped = fs.read(str(path), sandbox=str(tmp_path))
    assert round_tripped == content
    fs.write(str(path), round_tripped, sandbox=str(tmp_path))
    assert path.read_bytes() == content.encode("utf-8")
