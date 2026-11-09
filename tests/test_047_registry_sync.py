"""0.47: memory notes and prompt versions sync through a remote (SPEC 4.19-4.20).

Two repositories share one ``tine serve``-shaped remote: a note one adds
reaches the other only if it verifies under the reader's team, a prompt history
fast-forwards, and a diverged prompt history is reported, never merged.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _memory, _prompt
from opentine.repository import Repo
from opentine.repository import _registry_refs as refs
from opentine.repository._registry_sync import sync
from tests.test_046_tombstones import _remote

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
WHEN = "2026-11-09T00:00:00Z"


def _hex(key) -> str:
    return key.public_key().public_bytes_raw().hex()


def _note(text: str, key=KEY) -> dict:
    return _memory.sign(_memory.build("team", "testing", text, author="a", created_at=WHEN), key)


def _version(text: str, previous=None) -> dict:
    record = _prompt.build("review", text, previous=previous, created_at=WHEN)
    return _prompt.sign(record, KEY)


def test_notes_and_prompts_travel_and_a_strangers_note_is_refused(tmp_path, monkeypatch):
    _remote(tmp_path, monkeypatch)
    alice, bob = Repo.init(tmp_path / "alice"), Repo.init(tmp_path / "bob")
    refs.add_note(alice, _note("Use the venv python"))
    refs.add_note(alice, _note("A stranger's advice", OTHER))
    v1 = _version("Review {{diff}}")
    refs.push_prompt(alice, v1)
    refs.push_prompt(alice, _version("Review {{diff}} twice", v1))
    refs.set_label(alice, "review", "production", 1)
    pushed = sync(alice, "https://remote", tenant="acme", token="t")
    assert len(pushed["sent"]) == 4 and pushed["conflicts"] == []

    pulled = sync(bob, "https://remote", tenant="acme", token="t", team=[_hex(KEY)])
    assert [r["reason"] for r in pulled["refused"]] == ["memory.untrusted-signer"]
    assert len(pulled["received"]) == 3
    assert [n["record"]["text"] for n in refs.notes(bob)] == ["Use the venv python"]
    assert [r["version"] for r in refs.prompt_history(bob, "review")] == [1, 2]
    assert refs.labels(bob, "review") == {"production": 1}
    again = sync(bob, "https://remote", tenant="acme", token="t", team=[_hex(KEY)])
    assert again["sent"] == [] and again["received"] == []
    refs.push_prompt(alice, _version("Review {{diff}} thrice", refs.prompt_head(alice, "review")))
    sync(alice, "https://remote", tenant="acme", token="t")
    ahead = sync(bob, "https://remote", tenant="acme", token="t", team=[_hex(KEY)])
    assert ahead["received"] == ["prompts/review/head"]
    assert refs.prompt_head(bob, "review")["version"] == 3


def test_a_diverged_prompt_history_is_a_conflict(tmp_path, monkeypatch):
    _remote(tmp_path, monkeypatch)
    alice, bob = Repo.init(tmp_path / "alice"), Repo.init(tmp_path / "bob")
    v1 = _version("Review {{diff}}")
    for repo in (alice, bob):
        refs.push_prompt(repo, v1)
    refs.push_prompt(alice, _version("Alice's {{diff}}", v1))
    sync(alice, "https://remote", tenant="acme", token="t")
    refs.push_prompt(bob, _version("Bob's {{diff}}", v1))
    refs.push_prompt(bob, _version("Bob's {{diff}} again", refs.prompt_head(bob, "review")))
    result = sync(bob, "https://remote", tenant="acme", token="t")
    assert result["sent"] == [] and result["conflicts"] == ["prompts/review/head"]
    assert refs.prompt_head(bob, "review")["template"] == "Bob's {{diff}} again"
