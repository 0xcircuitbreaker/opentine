"""0.35: the MCP server is read-only unless writes are opted into; ``tine view``
re-redacts at render time and ships a strict Content-Security-Policy."""

from __future__ import annotations

import base64
import hashlib
import re
from types import SimpleNamespace

import pytest

from opentine import mcp_server
from opentine._mcp_readonly import ALLOW_WRITES_ENV, writes_allowed
from opentine._view_html import CSP, render_run
from opentine.core import RunStatus, StepKind

SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
WRITE_TOOLS = {"fork_run", "fork_run_v3", "resume_run_v3", "attest_run", "evaluate_run"}


class _FakeServer:
    def __init__(self, name):
        self.tools = {}

    def tool(self, *args, **kwargs):
        return lambda function: self.tools.setdefault(function.__name__, function)

    def resource(self, *args, **kwargs):
        return lambda function: function


@pytest.fixture
def fake(monkeypatch):
    monkeypatch.setattr(mcp_server, "server_class", lambda: _FakeServer)
    monkeypatch.delenv(ALLOW_WRITES_ENV, raising=False)


def test_mcp_server_is_read_only_by_default(fake, tmp_path):
    server = mcp_server.create_server(tmp_path / "runs", tmp_path)
    assert "list_runs" in server.tools
    assert not WRITE_TOOLS & set(server.tools)


def test_write_tools_need_an_explicit_opt_in(fake, tmp_path, monkeypatch):
    assert "fork_run" in mcp_server.create_server(tmp_path, tmp_path, read_only=False).tools
    monkeypatch.setenv(ALLOW_WRITES_ENV, "1")
    tools = mcp_server.create_server(tmp_path, tmp_path).tools
    assert "fork_run" in tools and "promote_run" not in tools


def test_command_line_flags(monkeypatch):
    monkeypatch.delenv(ALLOW_WRITES_ENV, raising=False)
    assert not writes_allowed([])
    assert writes_allowed(["--allow-writes"])
    assert not writes_allowed(["--allow-writes", "--read-only"])
    monkeypatch.setenv(ALLOW_WRITES_ENV, "1")
    assert not writes_allowed(["--read-only"])


def _run():
    step = SimpleNamespace(
        id="s" * 20,
        kind=StepKind.tool,
        model_info="",
        provider="",
        tool_info={},
        inputs={"name": "Bash", "arguments": {"command": f"export GH={SECRET}"}},
        outputs={"text": SECRET},
        usage={},
        error=None,
        duration=0,
    )
    return SimpleNamespace(
        id="r" * 20,
        metadata={},
        model_info="m",
        steps=[step],
        status=RunStatus.completed,
        created_at=0.0,
        total_duration=0.0,
        total_tokens=0,
        system_prompt="",
        user_prompt=f"token {SECRET}",
    )


def test_view_rescrubs_unredacted_content_at_render_time():
    page = render_run(_run(), cost="-")
    assert SECRET not in page
    assert "export GH=" in page


def test_view_page_has_a_strict_csp_matching_its_stylesheet():
    page = render_run(_run(), cost="-")
    meta = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', page)
    assert meta and meta.group(1) == CSP
    assert "default-src 'none'" in CSP and "unsafe-inline" not in CSP
    style = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(style.encode()).digest()).decode()
    assert f"'sha256-{digest}'" in CSP
    assert "<script" not in page
