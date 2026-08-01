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
