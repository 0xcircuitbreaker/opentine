"""Round-13 audit regressions: two credential leaks and one false attestation.

All three are silent failures — the store, a remote, or an MCP model client
receives something that *looks* reviewed. A quoted credential survived beside a
false ``[REDACTED]`` marker; a re-saved migrated run kept republishing a legacy
signature verdict over bytes it no longer matched; and the legacy migration blob,
the one body written with ``redact=False``, was rendered verbatim to whoever
named its object id.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from opentine import Run, StepKind
from opentine._v3_guards import guarded_redaction
from opentine.mcp_repository import register_repository_tools
from opentine.redaction import redact_blob, redact_text
from opentine.repository import Repo

SECRET = "sk-ant-SUPERSECRET-LEGACY-0123"


class FakeMCP:
    """The registration double test_mcp_repository uses, so the tool is the real one."""

    def __init__(self):
        self.tools = {}
        self.resources = {}

    def tool(self):
        def register(function):
            self.tools[function.__name__] = function
            return function

        return register

    def resource(self, uri):
        def register(function):
            self.resources[uri] = function
            return function

        return register


def _migrated(tmp_path: Path) -> tuple[Repo, str]:
    """A repository holding one v2 run migrated with its credential-bearing bytes."""
    source = tmp_path / "legacy.tine"
    run = Run(id="legacy")
    run.add_step(StepKind.tool, {"cmd": "env"}, {"stdout": f"ANTHROPIC_API_KEY is {SECRET}"})
    run.save(source)
    repo = Repo.init(tmp_path / "repo")
    migrated = repo.migrate_v2(source)
    return repo, migrated.run_id


# --- finding 1: a quoted value walked out from under the [REDACTED] marker ---


def test_quoted_credential_values_are_redacted_inside_their_quotes():
    # The value class excluded quotes, so the separator's trailing \s* gave back a
    # space for the value to match and the scan wrote 'password:[REDACTED]"hunter2"'
    # — the secret intact, one marker to the left of it. Mid-line only: the
    # line-anchored rule already took the whole value on a line of its own.
    secret = "hunter2-LIVE-SECRET"
    for text in (
        f'the password: "{secret}" was rotated',
        f"the password: '{secret}' was rotated",
        f'run it with api_key = "{secret}" and retry',
        f'the api_key: "{secret}',  # truncated line: still a credential
    ):
        scrubbed = redact_text(text)
        assert secret not in scrubbed
        assert "[REDACTED]" in scrubbed


def test_redaction_leaves_a_json_object_parseable():
    # Why the quotes are kept rather than consumed: a value that swallows its
    # closing quote breaks every downstream reader of the blob.
    body = json.dumps({"api_key": "sk-live-0123456789abcdef", "user": "bob"})
    assert json.loads(redact_text(body)) == {"api_key": "[REDACTED]", "user": "bob"}


def test_guarded_redaction_scrubs_a_quoted_credential_in_free_text():
    # The writer's own path, and past the typed layer: ``_redact`` splits a string
    # on its *first* separator, so the earlier "config:" is what names this value
    # and only the regex pass below ever sees the assignment that matters.
    value = guarded_redaction(
        {"note": 'config: run it with api_key = "hunter2-LIVE-SECRET" now'},
        where="round-13 regression",
    )
    assert "hunter2-LIVE-SECRET" not in json.dumps(value)


def test_quoted_value_alternation_stays_linear():
    # The module's standing rule: no new way to split a run of whitespace or an
    # unterminated quote, or an ordinary indented blob turns quadratic.
    adversarial = (b"a-b_c-d_" * 1500) + b"secretz"
    unterminated = b'note api_key: "' + (b"a" * 200_000)
    indented = (b" " * 200) + b'{"note": "ok"}\n' * 2000
    started = time.monotonic()
    assert redact_blob(adversarial) == adversarial
    assert b"a" * 200_000 not in redact_blob(unterminated)
    assert redact_blob(indented) == indented
    assert time.monotonic() - started < 1.5


# --- finding 2: a re-saved migrated run kept the prior save's verdict -----------


def test_resaving_a_migrated_run_drops_the_stale_legacy_attestation(tmp_path):
    # _put_run builds on the run's stored payload, so the five migration fields
    # rode along into a save that attaches no legacy bytes: the new run still
    # claimed legacy_verification.signature over an artifact it no longer matches.
    repo, run_id = _migrated(tmp_path)
    migrated_payload = repo.get(run_id).payload()
    assert migrated_payload["legacy_verification"]["integrity"]["ok"] is True

    run = repo.load_run(run_id)
    run.add_step(StepKind.tool, {"cmd": "ls"}, {"stdout": "one more step"})
    resaved = repo.put_run(run)

    payload = repo.get(resaved.run_id).payload()
    assert payload["events"] != migrated_payload["events"]
    for field in (
        "legacy_blob",
        "legacy_format",
        "legacy_verification",
        "migration_map_blob",
        "signature_scope",
    ):
        assert field not in payload
    # The migrated run itself is immutable and still carries its own verdict.
    assert repo.get(run_id).payload() == migrated_payload


def test_the_fork_writer_and_run_writer_share_one_migration_field_list():
    from opentine.repository import _fork_state, _run_blobs

    assert _fork_state.LEGACY_MIGRATION_FIELDS is _run_blobs.LEGACY_MIGRATION_FIELDS


# --- finding 4: the legacy blob was rendered verbatim to an MCP client ----------


def test_inspecting_the_legacy_blob_by_id_returns_redacted_content(tmp_path):
    # inspect_object and the tine-object:// resource take any id a model asks for,
    # so "fetched by its own object id" is not the deliberate operator review the
    # unredacted legacy bytes were documented to require.
    repo, run_id = _migrated(tmp_path)
    legacy_blob = repo.get(run_id).payload()["legacy_blob"]

    assert SECRET in repo.raw(legacy_blob).decode()  # stored bytes stay byte-exact
    assert SECRET not in json.dumps(repo.inspect(legacy_blob))

    mcp = FakeMCP()
    register_repository_tools(mcp, str(tmp_path / "repo"))
    assert SECRET not in json.dumps(mcp.tools["inspect_object"](legacy_blob))
    assert SECRET not in json.dumps(mcp.resources["tine-object://{object_id}"](legacy_blob))


def test_inspecting_an_ordinary_blob_is_unchanged(tmp_path):
    repo = Repo.init(tmp_path)
    oid = repo.put("blob", b'{"note": "a benign tool result", "count": 3}')
    inspected = repo.inspect(oid)
    assert inspected["payload"]["text"] == '{"note": "a benign tool result", "count": 3}'
    assert inspected["payload"]["truncated"] is False


def test_resolving_a_blob_aliased_under_another_key_is_also_redacted(tmp_path):
    # _resolved skips only the field literally named legacy_blob; a run that points
    # at the same unredacted bytes under any other *_blob key bulk-resolved them
    # verbatim. Every resolved body now goes through the scrub too.
    repo, run_id = _migrated(tmp_path)
    payload = dict(repo.get(run_id).payload())
    legacy_blob = payload["legacy_blob"]
    payload["evil_blob"] = legacy_blob
    crafted = repo.put("run", payload)

    resolved = repo.inspect(crafted, resolve_blobs=True)
    assert SECRET not in json.dumps(resolved)
    assert SECRET in repo.raw(legacy_blob).decode()  # stored bytes untouched
