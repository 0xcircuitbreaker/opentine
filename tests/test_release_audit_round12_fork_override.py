"""Round-12 audit regression: the fork override text rule, on the leg not the caller.

Round 11 closed the v3 write path's Unicode rule everywhere a str becomes bytes --
except one. It put the guard for fork overrides on ``Recorder.fork``, a *caller* of
``repository/_fork_state.fork_payload``, so the raw ``applied["prompt"].encode()``
inside the leg itself stayed reachable through the public ``Repo.fork`` and through
MCP's ``fork_run_v3``, which calls it directly. A model-supplied prompt override
holding an unpaired ``\\udXXX`` escape -- what any JS-side ``JSON.stringify`` emits
for a string sliced mid-emoji -- therefore still surfaced a bare
``UnicodeEncodeError`` naming a codec and a byte offset in a fragment no caller
could locate, instead of the typed, path-bearing refusal every other leg produces.

The guard now sits in ``_overrides``, which is the first thing ``fork_payload``
does, so it covers *every* override value that reaches a write and refuses before
the closure walk, before any blob, and before any ref moves.

The half of this that is not about refusing: the check has to refuse exactly what
the writer beneath it would refuse and no more. The prompt is a raw blob --
redaction never sees it -- so it is checked verbatim. Everything else is written
through ``guarded_redaction``, so it is checked in that writer's own order
(``json_safe`` coercion, then ``_redact``); otherwise a credential-shaped policy
value whose secret is dropped before any encoder sees it would start being refused
here while ``.tine`` and ``put_run`` still accept it -- the same write-side
asymmetry this release keeps finding, pointed the other way.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine.mcp_repository import register_repository_tools
from opentine.repository import Repo
from opentine.trace.recorder import Recorder
from opentine.trace.schema import TraceEvent

LONE = json.loads('{"p": "done \\ud83d"}')["p"]
LONE_LOW = json.loads('{"p": "done \\udc00"}')["p"]
PAIR = json.loads('{"p": "done \\ud83d\\ude00"}')["p"]


class FakeMCP:
    """The registration double test_mcp_repository uses, so the tool is the real one."""

    def __init__(self):
        self.tools = {}

    def tool(self):
        def register(function):
            self.tools[function.__name__] = function
            return function

        return register

    def resource(self, uri):
        def register(function):
            return function

        return register


def _forkable(tmp_path: Path, name: str) -> tuple[Repo, str, str]:
    repo = Repo.init(tmp_path / name)
    recorder = Recorder.start(repo, capture=False)
    event = recorder.append(
        TraceEvent(kind="model", timestamp=1.0, trace_id="t" * 32, span_id="s" * 16)
    )
    recorder.append(
        TraceEvent(
            kind="model",
            timestamp=2.0,
            trace_id="t" * 32,
            span_id="u" * 16,
            outputs={"text": "later"},
        )
    )
    return repo, recorder.run_id, event


@pytest.mark.parametrize("text", [LONE, LONE_LOW])
@pytest.mark.parametrize(
    ("overrides", "path"),
    [
        ({"prompt": None}, "prompt"),
        ({"model": None}, "model"),
        ({"policy": {"rule": None}}, r"policy\.rule"),
        ({"policy": {"nested": [{"rule": None}]}}, r"policy\.nested\[0\]\.rule"),
    ],
)
def test_public_fork_refuses_every_override_it_cannot_encode(tmp_path, overrides, path, text):
    # Repo.fork, not Recorder.fork: the guard round 11 wrote covered the caller
    # only, and this is the entry point MCP fork_run_v3 uses.
    # The repo dir has a fixed, safe name (tmp_path is already unique per param); the
    # hostile surrogate is the *subject*, so it flows only into `applied` below --
    # naming the dir after it wrote a lone surrogate / backslash into a path that the
    # Windows filesystem rejects before the tested fork ever runs.
    repo, run_id, event = _forkable(tmp_path, "fork")
    applied = json.loads(json.dumps(overrides).replace("null", json.dumps(text)))
    before_oids, before_refs = repo.iter_oids(), repo.list_refs()
    with pytest.raises(
        ValueError, match=f"fork override holds an unpaired UTF-16 surrogate at {path}"
    ):
        repo.fork(run_id, event, overrides=applied, ref="heads/alt")
    # Fails closed all the way: _overrides runs before the closure walk, so not one
    # object was written and no ref -- not even a new one -- was created.
    assert repo.iter_oids() == before_oids
    assert repo.list_refs() == before_refs and "heads/alt" not in before_refs
    assert repo.fsck().ok


def test_the_offending_policy_key_is_named_as_an_escape(tmp_path):
    repo, run_id, event = _forkable(tmp_path, "key")
    with pytest.raises(ValueError, match=r"at policy\.done \\ud83d \(object key\)"):
        repo.fork(run_id, event, overrides={"policy": {LONE: "x"}}, ref="heads/alt")


def test_the_mcp_fork_tool_refuses_typed_rather_than_by_codec(tmp_path):
    # The reachable path: an MCP client's JSON arrives already decoded, so a prompt
    # sliced mid-emoji upstream reaches _fork_state as a str with no UTF-8 spelling.
    repo, run_id, event = _forkable(tmp_path, "mcp")
    mcp = FakeMCP()
    register_repository_tools(mcp, str(tmp_path / "mcp"))
    with pytest.raises(ValueError, match="fork override holds an unpaired UTF-16 surrogate"):
        mcp.tools["fork_run_v3"](run_id, event, "experiments/alt", prompt=LONE)
    assert repo.list_refs() == {"heads/main": repo.read_ref("heads/main")}

    forked = mcp.tools["fork_run_v3"](run_id, event, "experiments/alt", prompt=PAIR)
    assert repo.read_ref("experiments/alt") == forked["run_id"] and repo.fsck().ok


def test_a_well_formed_override_set_still_forks(tmp_path):
    # The reverse failure this round was told to watch for: a guard that refuses
    # what the previous build accepted. A surrogate *pair* is ordinary text.
    repo, run_id, event = _forkable(tmp_path, "pair")
    forked = repo.fork(
        run_id,
        event,
        overrides={"model": "m-" + PAIR, "prompt": PAIR, "policy": {"rule": PAIR}},
        ref="heads/alt",
    )
    payload = repo.get(forked).payload()
    assert repo.get(payload["prompt_blob"]).body.decode() == PAIR
    assert payload["model"] == "m-" + PAIR
    assert PAIR in repo.get(payload["manifests"]["policy"]).body.decode()
    assert payload["events"] == [event] and repo.fsck().ok


def test_a_credential_shaped_policy_value_is_redacted_not_refused(tmp_path):
    # _redact replaces a secret field's value outright without walking into it, so
    # the surrogate is gone before any encoder sees it and the blob writer accepts
    # the fork. Checking the raw override instead would refuse here what put_run and
    # .tine save both accept -- the same asymmetry, pointed the other way.
    repo, run_id, event = _forkable(tmp_path, "secret")
    forked = repo.fork(run_id, event, overrides={"policy": {"api_key": LONE}}, ref="heads/alt")
    policy = repo.get(repo.get(forked).payload()["manifests"]["policy"]).body
    assert json.loads(policy) == {"api_key": "[REDACTED]"}
    assert repo.fsck().ok


def test_a_policy_deeper_than_json_safe_keeps_is_still_forkable(tmp_path):
    # json_safe truncates at depth 100 rather than refusing, so a surrogate below
    # that line never reaches an encoder and the blob writer accepts it. The guard
    # runs on json_safe's own output for exactly this reason: reading the raw dict
    # would refuse a fork the writer beneath it completes.
    deep: dict[str, object] = {}
    cursor = deep
    for _ in range(140):
        child: dict[str, object] = {}
        cursor["n"] = child
        cursor = child
    cursor["leaf"] = LONE
    repo, run_id, event = _forkable(tmp_path, "deep")
    forked = repo.fork(run_id, event, overrides={"policy": deep}, ref="heads/alt")
    assert b"MAX_DEPTH" in repo.get(repo.get(forked).payload()["manifests"]["policy"]).body
    assert repo.fsck().ok


@pytest.mark.parametrize(
    "overrides", [None, {}, {"resume": True}, {"model": None, "policy": None, "prompt": None}]
)
def test_a_fork_without_text_overrides_is_untouched(tmp_path, overrides):
    # The guard walks the override mapping unconditionally; an empty or non-text one
    # must cost nothing and refuse nothing. `resume` is a bool the walk skips.
    # Fixed, safe dir name: the override mapping's repr (e.g. "{'resume': True}") holds
    # a colon, illegal in a Windows path; the overrides are the subject and reach the
    # code only through the `overrides=` argument below.
    repo, run_id, event = _forkable(tmp_path, "plain")
    forked = repo.fork(run_id, event, overrides=overrides, ref="heads/alt")
    payload = repo.get(forked).payload()
    assert payload["status"] == "running" and payload["events"] == [event]
    assert payload["fork_overrides"] == (
        {"resume": True} if (overrides or {}).get("resume") else {}
    )
    assert repo.fsck().ok


def test_the_shape_refusals_still_precede_the_text_one(tmp_path):
    # _overrides' existing type checks are the reason the text guard may assume a
    # str; a wrong shape must still report the wrong shape, not a Unicode path.
    repo, run_id, event = _forkable(tmp_path, "shape")
    for overrides, message in (
        ({"prompt": 5}, "fork prompt override must be a string"),
        ({"model": ""}, "fork model override must be a non-empty string"),
        ({"policy": [LONE]}, "fork policy override must be an object"),
        ({"resume": "yes"}, "fork resume override must be a boolean"),
        ({"promptt": LONE}, "unknown fork override"),
        # The container and its key names, the two shapes _overrides never
        # checked. Both are the same class as the value refusals above and both
        # raised a bare interpreter error out of the public Repo.fork: a
        # non-mapping died in the comprehension, and a non-str name died in the
        # join that was written to report it.
        (5, "fork overrides must be an object"),
        ("model", "fork overrides must be an object"),
        ([("model", "m")], "fork overrides must be an object"),
        ({5: "x"}, "fork override names must be strings"),
        ({5: "x", "zz": "y"}, "fork override names must be strings"),
    ):
        with pytest.raises(ValueError, match=message):
            repo.fork(run_id, event, overrides=overrides, ref="heads/alt")
    assert "heads/alt" not in repo.list_refs()


def test_a_mapping_that_is_not_a_dict_still_forks(tmp_path):
    # The reverse failure the container check must not cause: _overrides duck-types
    # on .items(), so any Mapping that forked before this release still forks. An
    # isinstance(dict) check would have refused these.
    from collections import OrderedDict
    from types import MappingProxyType

    repo, run_id, event = _forkable(tmp_path, "mapping")
    for index, overrides in enumerate(
        (
            MappingProxyType({"model": "m-1"}),
            OrderedDict((("model", "m-2"),)),
            {5: None, "model": "m-3"},  # a non-str name whose value is dropped first
        )
    ):
        forked = repo.fork(run_id, event, overrides=overrides, ref=f"heads/alt{index}")
        assert repo.get(forked).payload()["model"] == f"m-{index + 1}"
    assert repo.fsck().ok


def test_a_retained_model_from_the_source_run_is_not_re_encoded(tmp_path):
    # The other str in fork_payload: _retained_model reads a model name back out of
    # stored events. It was written through the guarded object writer, so it cannot
    # hold a surrogate, and forking must not start metering it as if it could.
    repo = Repo.init(tmp_path / "retained")
    recorder = Recorder.start(repo, capture=False)
    event = recorder.append(
        TraceEvent(
            kind="model",
            timestamp=1.0,
            trace_id="t" * 32,
            span_id="s" * 16,
            model="m-" + PAIR,
        )
    )
    forked = repo.fork(recorder.run_id, event, ref="heads/alt")
    assert repo.get(forked).payload().get("model") == "m-" + PAIR
    assert repo.fsck().ok
