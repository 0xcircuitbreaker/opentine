"""Shared pytest configuration and fixtures."""

import os


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
    # Also pin a fixed, wide console WIDTH. The CLI's Rich console captures its
    # width at import: from the controlling terminal in an interactive dev shell
    # (wide), or 80 when stdout is not a tty (CI). A long message or temp path
    # then wraps differently between local and CI, so a substring assertion on
    # CLI output can pass locally and fail on CI (e.g. "Pass --force" split across
    # a wrap). Force one width everywhere so rendering is deterministic.
    os.environ["COLUMNS"] = "200"
    from opentine import _cli_common

    _cli_common.console._width = 200


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
