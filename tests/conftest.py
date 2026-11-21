"""Shared pytest configuration and fixtures."""

import os

# Pin the terminal environment at conftest *import*, before anything imports
# opentine. ``pytest_plugins`` below imports tests._schema_guard, which imports
# the CLI modules and so builds the shared Rich ``console`` before
# pytest_configure runs. Rich decides the console's colour system (and so
# whether bold/italic/underline styles are emitted at all) once, in
# Console.__init__, from is_terminal: TTY_COMPATIBLE, FORCE_COLOR, then
# isatty() of the stream current at that moment. In an xdist worker that import
# happens on the worker's own stdio (on Windows runners a stream that reports a
# tty), so the console froze "terminal" and later wrote style codes into every
# captured output. NO_COLOR strips only colour, not styles; TTY_COMPATIBLE=0
# makes Rich treat the stream as a non-terminal regardless of the handle.
os.environ.pop("FORCE_COLOR", None)
os.environ["NO_COLOR"] = "1"
os.environ["TTY_COMPATIBLE"] = "0"
os.environ["COLUMNS"] = "200"

#: 0.45: every --json output a test drives must meet its published schema.
pytest_plugins = ("tests._schema_guard",)


def pytest_configure(config):
    """Neutralize ambient terminal colour for the whole test session.

    The CLI builds its Rich ``console`` at import and honours ``FORCE_COLOR`` /
    ``NO_COLOR`` then. A developer shell that exports ``FORCE_COLOR`` would inject
    ANSI codes into CLI output that the plain-text assertions — and the escape
    *sanitization* security test in test_cli.py — do not expect, so the suite
    would fail locally while passing in CI (which sets neither). Pin no-colour
    before opentine is imported so local runs match CI. No test asserts colour is
    present, so this only removes a confound; a colour-forcing test would set its
    own terminal and be unaffected.
    """
    os.environ.pop("FORCE_COLOR", None)
    os.environ["NO_COLOR"] = "1"
    os.environ["TTY_COMPATIBLE"] = "0"
    # 0.11 compresses .tine files and new repositories by default. Most tests
    # read or corrupt stored bytes directly, so they pin the plain form; the
    # compression tests (test_compression_0_11.py) turn it back on themselves.
    os.environ.setdefault("OPENTINE_COMPRESS", "0")
    # 0.17: a developer shell exporting OPENTINE_OUTPUT=json would turn every
    # --json-capable command's default output into JSON; the output-format tests
    # set it themselves.
    os.environ.pop("OPENTINE_OUTPUT", None)
    # 0.26: format v4 is the default writer; a shell exporting OPENTINE_FORMAT=2
    # would flip every save back to v2. Tests about the legacy writers set it.
    os.environ.pop("OPENTINE_FORMAT", None)
    # 0.41: new private keys are encrypted PKCS#8, and a non-interactive keygen
    # needs a passphrase source; the key-storage tests change or drop it.
    os.environ["OPENTINE_KEY_PASSPHRASE"] = "opentine-test-passphrase"
    os.environ.pop("OPENTINE_KEY_KEYRING", None)
    # Also pin a fixed, wide console WIDTH. The CLI's Rich console captures its
    # width at import: from the controlling terminal in an interactive dev shell
    # (wide), or 80 when stdout is not a tty (CI). A long message or temp path
    # then wraps differently between local and CI, so a substring assertion on
    # CLI output can pass locally and fail on CI (e.g. "Pass --force" split across
    # a wrap). Force one width everywhere so rendering is deterministic.
    os.environ["COLUMNS"] = "200"
    from opentine import _cli_common

    _cli_common.console._width = 200
    # The console may have been built before the pins above (see module top);
    # assert it is not a terminal so a regression fails loudly here, not as
    # stray ANSI in dozens of unrelated assertions.
    assert not _cli_common.console.is_terminal
    assert _cli_common.console.color_system is None, _cli_common.console.color_system


#: CI sets OPENTINE_TEST_TRACE_DIR: each process appends "start"/"end" lines per
#: test to its own file, flushed at once, so a test that hangs until the
#: per-test timeout kills its xdist worker is named in an uploaded artifact.
_TRACE_DIR = os.environ.get("OPENTINE_TEST_TRACE_DIR")


def _trace(line):
    if not _TRACE_DIR:
        return
    import time

    worker = os.environ.get("PYTEST_XDIST_WORKER", "main")
    os.makedirs(_TRACE_DIR, exist_ok=True)
    path = os.path.join(_TRACE_DIR, f"{worker}-{os.getpid()}.log")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{time.strftime('%H:%M:%S')} {line}\n")


def pytest_runtest_logstart(nodeid, location):
    _trace(f"start {nodeid}")


def pytest_runtest_logfinish(nodeid, location):
    _trace(f"end {nodeid}")


def pytest_addoption(parser):
    parser.addoption("--provider", default="anthropic", help="Provider name for live tests")
    parser.addoption(
        "--agent-harness",
        default="codex",
        help=(
            "Agent CLI harness for live harness tests: codex, claude-code, opencode, "
            "kimi-code, openclaw, hermes, pi, generic, or all"
        ),
    )
    parser.addoption(
        "--harness-command",
        default=None,
        help="Override command for --agent-harness live tests, for example 'your-agent run'",
    )
