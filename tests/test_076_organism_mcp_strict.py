"""Audit OT-1: the organism MCP gate never relays a frame it cannot parse strictly."""

from __future__ import annotations

import json

import pytest

from opentine import _organism_gate
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_072_organism import _key, _tag, repo  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

CALL = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "load", "arguments": {"path": "ckpt/sleeper.safetensors",
                                                 "note": "X"}}}  # fmt: skip
RAW = json.dumps(CALL).encode("utf-8") + b"\n"


@pytest.mark.parametrize("evil", [
    RAW.replace(b'"X"', b'"\xff"'),  # invalid UTF-8
    b"\xef\xbb\xbf" + RAW,  # a byte order mark
    RAW.replace(b'"X"', b'"\xed\xa0\x80"'),  # an encoded lone surrogate
    RAW.replace(b'"note"', b'"path": "a", "path"'),  # a duplicate key
])  # fmt: skip
def test_organism_mcp_guard_never_relays_an_unparseable_frame(repo, evil):  # noqa: F811
    _tag(repo)
    guard = _organism_gate.OrganismMcpGuard(repo, "run-1")
    assert guard.check(RAW)[0] is None
    forward, _back, _blocked = guard.check(evil)
    assert forward is None
    assert guard.check(b"\n")[0] == b"\n"  # an empty line still passes


def test_organism_mcp_guard_answers_an_unparseable_request_it_can_identify(repo):  # noqa: F811
    guard = _organism_gate.OrganismMcpGuard(repo, "run-1")
    forward, back, _ = guard.check(RAW.replace(b'"X"', b'"\xff"'))
    assert forward is None
    assert json.loads(back)["id"] == 1 and json.loads(back)["error"]["code"]
