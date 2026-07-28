"""Regressions for the v0.3.0 pre-release audit.

Each test pins a defect that shipped-quality code had already passed review for,
so the assertions describe the *user-visible* failure rather than the mechanism.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import date
from pathlib import Path

import pytest
from rich.console import Console

from opentine import Run, StepKind
from opentine._artifact_io import parse_artifact_json
from opentine._canon import _redact
from opentine._cli_common import HARNESS_FACTORIES
from opentine.billing._values import as_date
from opentine.billing.catalog import catalog_paths, user_catalog_path
from opentine.harnesses import GeminiCLIHarness, GrokBuildHarness
from opentine.harnesses._types import cost_from_text, duration_seconds
from opentine.mcp_repository import _writable_ref
from opentine.models.compat import (
    GLM,
    DeepSeek,
    Grok,
    Groq,
    Hermes,
    Kimi,
    Ministral,
    Mistral,
    OpenRouter,
    Qwen,
    Together,
)
from opentine.redaction import redact_blob
from opentine.remote.security import OIDCIdentityProvider, RoleAuthorizationPolicy
from opentine.repo_cli import cmd_repo
from opentine.repository import Repo
from opentine.repository._paths import internal_path


def test_secret_with_a_colon_in_its_value_is_not_written_in_cleartext():
    # "api_key=sk-proj:abc" splits on ":" if presence rather than position picks
    # the separator, which puts "api_key" inside the label and hides the match.
    assert _redact("api_key=sk-proj:abc123") == "api_key= [REDACTED]"
    assert _redact("password=p:ssw0rd") == "password= [REDACTED]"
    # The colon-first forms must keep working.
    assert _redact("Authorization: Bearer sk-abc") == "Authorization: [REDACTED]"
    assert _redact("api_key: sk-plain") == "api_key: [REDACTED]"
    # Numeric usage dimensions are still never blanked.
    assert _redact("input_tokens=42") == "input_tokens=42"


def test_secret_survives_neither_a_diff_removal_line_nor_a_command_flag():
    # Both are ordinary ways a credential reaches a captured trace: a `git diff`
    # of a .env file, and a recorded argv.
    assert b"REDACTED" in redact_blob(b"-ANTHROPIC_API_KEY=sk-secret123")
    assert b"REDACTED" in redact_blob(b"--api-key=sk-secret123")
    assert b"REDACTED" in redact_blob(b"curl --api-key=sk-live-999 https://api.example.com")
    assert b"REDACTED" in redact_blob(b"run --client-secret=abc12345 --verbose")


def test_credential_name_matching_stays_linear_and_does_not_over_redact():
    # Widening the start boundary to accept a preceding "-" makes every hyphen a
    # candidate start position and turns matching quadratic.
    adversarial = (b"a-b_c-d_" * 1500) + b"secretz"
    started = time.monotonic()
    assert redact_blob(adversarial) == adversarial
    assert time.monotonic() - started < 1.5
    for benign in (b"input_tokens=42", b"public_key=ssh-rsa AAA", b"idempotency_key=req-1"):
        assert redact_blob(benign) == benign


def test_updating_a_ref_does_not_delete_a_sibling_refs_held_lock(tmp_path):
    # "tags/x" staged its write through "tags/x.new.lock", which is exactly the
    # guard lock of the legal sibling ref "tags/x.new": the update failed against
    # that lock and then deleted it on the way out, so a third writer could take a
    # lock another writer still believed it held.
    repo = Repo.init(tmp_path)
    first, second = repo.put("blob", b"one"), repo.put("blob", b"two")
    repo.update_ref("tags/x", first, expected_old=None)
    repo.update_ref("tags/x.new", first, expected_old=None)

    sibling_lock = internal_path(Path(repo.path), "refs", "tags", "x.new").with_name("x.new.lock")
    os.close(os.open(sibling_lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644))

    repo.update_ref("tags/x", second, expected_old=first)

    assert sibling_lock.exists(), "sibling ref's held guard lock was deleted"
    assert repo.read_ref("tags/x") == second
    assert repo.read_ref("tags/x.new") == first


def test_a_run_long_enough_to_save_is_still_long_enough_to_load(tmp_path):
    # A fixed structural-token cap rejected artifacts Run.save() had already
    # written, so a long run was persisted and then permanently unreadable.
    path = tmp_path / "long.tine"
    run = Run(id="long")
    parent = None
    for index in range(20_000):
        parent = run.add_step(
            StepKind.think, {"p": f"step {index}"}, {"o": "ok"}, parent_id=parent
        ).id
    run.save(path)

    assert len(Run.load(path).steps) == 20_000
    assert Run.verify_integrity(path).ok


def test_dense_structural_padding_is_still_refused():
    # The relative bound must not turn the amplification guard off: ~2 bytes of
    # "{}" per container becomes ~64 bytes once materialized.
    bomb = b'{"ignored":[' + b",".join([b"{}"] * 170_000) + b"]}"
    with pytest.raises(ValueError, match="structure is excessive"):
        parse_artifact_json(bomb)


def test_migrate_v3_refuses_a_tampered_artifact_without_a_traceback(tmp_path, monkeypatch, capsys):
    # SignatureError is the one opentine error not rooted in ValueError/OSError,
    # so the fail-closed path — the whole point of the check — surfaced as an
    # interpreter crash with an exit code no caller expects.
    source = tmp_path / "run.tine"
    run = Run(id="tampered")
    run.add_step(StepKind.think, {"p": "plan the work"}, {"o": "ok"})
    run.save(source)
    source.write_text(source.read_text().replace("plan the work", "HACK the work"))

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    Repo.init(repo_dir)
    monkeypatch.chdir(repo_dir)
    args = argparse.Namespace(
        command="migrate-v3",
        source=str(source),
        ref="heads/main",
        allow_unverified=False,
        repo=".",
    )

    with pytest.raises(SystemExit) as exit_info:
        cmd_repo(args, Console())

    assert exit_info.value.code == 1
    assert "refusing to migrate a tampered v2 artifact" in capsys.readouterr().err


def test_harness_millisecond_duration_is_stored_as_seconds():
    # Step.duration is seconds: it renders as "…s" and is compared against
    # Budget.max_duration, so a verbatim duration_ms inflates it 1000x and can
    # abort a run on a duration budget it never exceeded.
    assert duration_seconds({"duration_ms": 1500}) == 1.5
    assert duration_seconds({"latency_ms": 250}) == 0.25
    assert duration_seconds({"duration": 1.5}) == 1.5
    # An explicit seconds field still wins over the millisecond one.
    assert duration_seconds({"duration": 2, "duration_ms": 9999}) == 2
    assert duration_seconds({}) == 0.0


def test_inspect_does_not_resolve_the_unredacted_legacy_blob(tmp_path):
    # V2 migration stores legacy_blob with redact=False to keep the original bytes
    # verifiable, so it is the one blob that may still hold credentials.
    # inspect_object defaults to resolve_blobs=True and hands its result to an MCP
    # model client, which is not the "review before sharing" the docs require.
    secret = "sk-ant-SUPERSECRET-LEGACY"
    source = tmp_path / "legacy.tine"
    run = Run(id="legacy")
    run.add_step(StepKind.tool, {"cmd": "env"}, {"stdout": f"ANTHROPIC_API_KEY is {secret}"})
    run.save(source)

    repo = Repo.init(tmp_path / "repo")
    migrated = repo.migrate_v2(source)
    run_id = getattr(migrated, "run_id", None) or migrated["run_id"]

    inspected = repo.inspect(run_id, resolve_blobs=True)
    assert secret not in json.dumps(inspected)
    # Other blobs must still resolve, and the legacy bytes stay reachable when
    # asked for deliberately by their own object id.
    assert inspected["resolved_blobs"]
    assert secret in json.dumps(repo.inspect(inspected["payload"]["legacy_blob"]))


def test_mcp_fork_and_resume_cannot_move_mainline_or_promotion_refs():
    # A fork's ref update compare-and-swaps against the value it just read, i.e. it
    # is an unconditional overwrite. The content an MCP client reads from the
    # repository is untrusted, so an arbitrary writable ref makes "fork onto
    # heads/main" a one-step prompt-injection payload.
    for protected in ("heads/main", "promotions/prod", "tags/v1", "remotes/origin/main"):
        with pytest.raises(ValueError, match="may only write experiments/"):
            _writable_ref(protected)
    assert _writable_ref("experiments/policy") == "experiments/policy"


def test_openrouter_requests_usage_so_streamed_calls_are_priceable():
    # OpenRouter is priced from its own reported usage.cost rather than a rate
    # card, so a stream with no usage chunk has no fallback: it reports $0.00.
    assert OpenRouter()._include_usage is True


def test_every_hosted_openai_compatible_adapter_requests_stream_usage():
    # These endpoints send no usage chunk unless stream_options.include_usage is
    # set, so a streamed call yields no token counts and prices as "unknown" —
    # silently reporting $0.00 for real spend.
    for adapter in (
        GLM(),
        Together(),
        Mistral(),
        Ministral(),
        Hermes(),
        OpenRouter(),
        Kimi(),
        DeepSeek(),
        Qwen(),
        Grok(),
        Groq(),
    ):
        wants = adapter._include_usage or (
            adapter._include_usage is None and adapter._provider in adapter._stream_usage_providers
        )
        assert wants, f"{type(adapter).__name__} ({adapter._provider}) loses streamed usage"


def test_glm_china_endpoint_also_requests_stream_usage():
    # GLM picks its provider string at runtime, so covering only "glm" left the
    # China endpoint silently unpriced on streams.
    assert "glm-cn" in GLM._stream_usage_providers


def test_pricing_update_installs_where_the_loader_actually_reads(monkeypatch, tmp_path):
    # Hard-coding ~/.config in the writer made `tine pricing update` report success
    # while installing to a file load_catalogs() never opens.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert user_catalog_path() == tmp_path / "opentine" / "pricing.json"
    assert user_catalog_path() in catalog_paths()


def test_documented_harness_presets_build_their_documented_command():
    assert GrokBuildHarness().build_command("fix the tests") == ["grok", "exec", "fix the tests"]
    assert GeminiCLIHarness().build_command("fix the tests") == ["gemini", "-p", "fix the tests"]
    assert {"grok", "gemini"} <= set(HARNESS_FACTORIES)


def test_oidc_token_without_a_roles_claim_grants_nothing():
    # Defaulting an absent roles claim to "reader" is fail-open: a misconfigured
    # issuer, or one that stops emitting the claim, silently confers read access to
    # every run in the tenant.
    provider = OIDCIdentityProvider(lambda _token: {"sub": "u1", "tenant": "acme"})
    identity = provider.authenticate({"authorization": "Bearer t"})
    assert identity.roles == ()
    policy = RoleAuthorizationPolicy()
    assert not policy.authorize(identity, "search", "acme")
    assert not policy.authorize(identity, "fetch", "acme")

    # An operator can still opt into a standing role explicitly.
    lenient = OIDCIdentityProvider(
        lambda _token: {"sub": "u1", "tenant": "acme"}, default_roles=("reader",)
    )
    assert policy.authorize(lenient.authenticate({"authorization": "Bearer t"}), "search", "acme")


def test_effective_date_string_honours_its_utc_offset():
    # Truncating to the first 10 characters dropped the offset, so a timestamp that
    # is already the next day in UTC resolved to the previous day's rate card.
    assert as_date("2026-07-25T23:00:00-08:00") == date(2026, 7, 26)
    assert as_date("2026-07-26T01:00:00+05:00") == date(2026, 7, 25)
    assert as_date("2026-07-25") == date(2026, 7, 25)
    assert as_date("2026-07-25T12:00:00") == date(2026, 7, 25)


def test_harness_cost_scraping_requires_a_currency_marker():
    # "cost: 500" in an agent's prose about an approach it was weighing booked $500.
    assert cost_from_text("this approach has cost: 500 in complexity") == 0.0
    assert cost_from_text("estimated price = 42") == 0.0
    assert cost_from_text("cost: $0.12") == 0.12
    assert cost_from_text("price = 1.50 USD") == 1.50
