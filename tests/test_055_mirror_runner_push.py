"""0.55: a mirror sync spools one review-runner push per moved ref."""

from __future__ import annotations

import json

from opentine._review_runner import check_trigger
from opentine.remote import _mirror_push, _mirror_store
from tests._mirror_fixture import call, fixture_repo, git, make_app, put_project

T = "/v1/tenants/acme/project/"


def _spooled(place):
    return [json.loads(p.read_text()) for p in _mirror_push.pending(place)]


def test_a_sync_spools_a_runner_push_per_moved_ref(tmp_path):
    shas = fixture_repo(tmp_path / "upstream")
    app = make_app(tmp_path)
    put_project(app)
    assert call(app, "PUT", T + "mirror", {"url": (tmp_path / "upstream").as_uri()}).status == 200
    place = _mirror_store.directory(app.service.objects.root, "acme")
    first = _spooled(place)
    assert {e["ref"] for e in first} == {"heads/main", "heads/feature", "tags/v1"}
    assert all(e["source"] == "mirror-sync" and "before" not in e for e in first)
    assert all(check_trigger(e) == e for e in first)

    upstream = tmp_path / "upstream"
    (upstream / "NEW.md").write_text("new\n")
    git(upstream, "add", ".")
    git(upstream, "commit", "-q", "-m", "Another", when=3)
    head = git(upstream, "rev-parse", "HEAD")
    state = _mirror_store.sync(app.service.objects.root, "acme",
                               _mirror_store.config({"allow_local": True}), force=True)  # fmt: skip
    assert state["status"] == "synced"
    moved = [e for e in _spooled(place) if e not in first]
    assert moved == [{"source": "mirror-sync", "ref": "heads/main", "before": shas["second"],
                      "after": head, "at": state["synced_at"]}]  # fmt: skip


def test_no_push_unless_the_sync_succeeded():
    before = {"refs": {"refs/heads/main": "a" * 40}}
    assert _mirror_push.pushes(before, {"status": "failed", "refs": {}}) == []
    gone = _mirror_push.pushes(before, {"status": "synced", "refs": {},
                                        "synced_at": "2026-11-18T09:00:00Z"})  # fmt: skip
    assert gone == [{"source": "mirror-sync", "ref": "heads/main", "before": "a" * 40,
                     "at": "2026-11-18T09:00:00Z"}]  # fmt: skip
