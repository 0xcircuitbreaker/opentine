"""Shared pytest configuration and fixtures."""


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
