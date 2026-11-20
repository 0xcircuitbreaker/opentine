"""0.71: a mirror over the size limit pauses even when its partial copy cannot be deleted.

On Windows a just-killed git can hold pack files open past the delete's retries
(a sharing violation). The cleanup failure must be reported, not turned into an
error response that has no mirror ``state``.
"""

from __future__ import annotations

import logging

from opentine import _mirror_fetch
from tests._mirror_fixture import call, fixture_repo, make_app, put_project


def _locked(path, *args, **kwargs):
    exc = PermissionError(13, "The process cannot access the file", str(path))
    exc.winerror = 32  # what Windows raises while another process holds the file
    raise exc


def test_a_stuck_partial_mirror_still_pauses_and_is_reported(tmp_path, monkeypatch, caplog):
    fixture_repo(tmp_path / "upstream")
    app = make_app(tmp_path, max_repo_bytes=1)
    put_project(app)
    monkeypatch.setattr(_mirror_fetch.shutil, "rmtree", _locked)
    with caplog.at_level(logging.WARNING, logger="opentine.mirror"):
        linked = call(app, "PUT", "/v1/tenants/acme/project/mirror",
                      {"url": (tmp_path / "upstream").as_uri()})  # fmt: skip
    assert linked.status == 200, linked.body
    state = linked.json()["state"]
    assert state["status"] == "paused" and state["reasons"] == ["mirror.limit-exceeded"]
    assert any("could not delete" in r.getMessage() for r in caplog.records)
    assert call(app, "GET", "/v1/tenants/acme/project/code/refs").status == 404
