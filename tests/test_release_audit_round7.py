"""Regressions for the v0.3.0 pre-release audit.

Each test pins a defect that shipped-quality code had already passed review for,
so the assertions describe the *user-visible* failure rather than the mechanism.
"""

from __future__ import annotations

import argparse
import json
import os
import threading
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
from opentine.billing.catalog import (
    PricingCatalog,
    catalog_hash,
    catalog_paths,
    user_catalog_path,
)
from opentine.harnesses import GeminiCLIHarness, GrokBuildHarness
from opentine.harnesses._types import cost_from_text, duration_seconds
from opentine.mcp_repository import _writable_ref
from opentine.models.compat import (
    GLM,
    OpenRouter,
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


def test_mcp_ref_guard_decides_on_the_canonical_name():
    # The namespace test must run on the name that actually reaches the filesystem,
    # not the caller's string, so the two cannot disagree. Checking the raw input
    # also rejected the legitimate fully-qualified form.
    assert _writable_ref("refs/experiments/policy") == "experiments/policy"
    assert _writable_ref("experiments/policy") == "experiments/policy"
    for traversal in ("experiments/../heads/main", "experiments/a/../../heads/main"):
        with pytest.raises(ValueError):
            _writable_ref(traversal)


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


def test_credential_in_a_quoted_json_fragment_is_redacted():
    # Tool output routinely contains JSON. The v2 string path handled the bare
    # form (api_key: X) but not the quoted one, so the label stayed '"api_key"',
    # matched no credential name, and the secret was stored verbatim. The v3 blob
    # scrubber already covered this, so v2 was the inconsistent side.
    secret = "sk-ant-SUPERSECRET"
    for fragment in (
        f'"api_key": "{secret}"',
        f"'api_key': '{secret}'",
        f'"client_secret":"{secret}"',
        f'"access_token": "{secret}"',
        f'"token": "{secret}"',
    ):
        assert secret not in _redact(fragment), fragment


def test_quoted_redaction_still_spares_counters_and_prose():
    # A bare "token" must stay usable as a numeric counter name.
    for benign in (
        "token: 42",
        "input_tokens=42",
        '"total_tokens": 900',
        "elapsed: 12:30",
        '"note": "the answer is 42"',
        '"public_key": "ssh-rsa AAA"',
    ):
        assert "REDACTED" not in _redact(benign), benign
    assert _redact({"token": 42, "input_tokens": 7}) == {"token": 42, "input_tokens": 7}


def test_reading_a_ref_during_a_concurrent_update_is_not_corruption(tmp_path):
    # commit_ref replaces the path, unlinking the inode an open reader holds, so
    # fstat reports nlink == 0. Rejecting "!= 1" called that corruption and failed
    # readers and fsck on a healthy repository; only nlink > 1 (a hardlink) is wrong.
    repo = Repo.init(tmp_path)
    first, second = repo.put("blob", b"a"), repo.put("blob", b"b")
    repo.update_ref("tags/x", first, expected_old=None)
    failures: list[str] = []

    def read() -> None:
        for _ in range(2000):
            try:
                repo.read_ref("tags/x")
            except Exception as exc:  # noqa: BLE001 - the assertion is that none occur
                failures.append(f"{type(exc).__name__}: {exc}")
                return

    def write() -> None:
        current = repo.read_ref("tags/x")
        for _ in range(200):
            nxt = second if current == first else first
            try:
                repo.update_ref("tags/x", nxt, expected_old=current)
                current = nxt
            except ValueError:
                current = repo.read_ref("tags/x")

    threads = [threading.Thread(target=read) for _ in range(3)] + [threading.Thread(target=write)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not failures, failures[:3]


def test_a_stray_file_in_refs_does_not_blank_the_ref_listing(tmp_path):
    # A .DS_Store used to raise out of list_refs, so fsck reported a healthy repo
    # as broken with zero refs verified — masking every real error behind it.
    repo = Repo.init(tmp_path)
    blob = repo.put("blob", b"c")
    repo.update_ref("tags/good", blob, expected_old=None)
    (Path(repo.path) / "refs" / ".DS_Store").write_text("junk", encoding="utf-8")

    assert list(repo.list_refs()) == ["tags/good"]
    report = repo.fsck()
    assert report.ok and report.refs == 1


def test_empty_xdg_config_home_does_not_make_the_overlay_relative(monkeypatch):
    # os.environ.get(..., default) returns "" for a set-but-empty variable, and
    # Path("") is Path("."), which would make the overlay CWD-relative per process.
    monkeypatch.setenv("XDG_CONFIG_HOME", "")
    assert user_catalog_path().is_absolute()


def test_documented_overlay_recipe_produces_a_loadable_catalog(tmp_path):
    # PRICING.md told authors to store the bare hex; the loader wants the
    # "sha256:"-prefixed form, and a bare hex fails every load with a hash
    # mismatch — taking all billing down, not just the overlay.
    data = {
        "schema": "opentine-pricing/1",
        "cards": [
            {
                "id": "x:y:1",
                "provider": "x",
                "model": "y",
                "effective_from": "2026-01-01",
                "rates": {"input": "1", "output": "2"},
            }
        ],
    }
    data["catalog_id"] = f"sha256:{catalog_hash(data)}"
    good = tmp_path / "good.json"
    good.write_text(json.dumps(data), encoding="utf-8")
    assert PricingCatalog.load(good, require_signature=False).cards

    bare = {k: v for k, v in data.items() if k != "catalog_id"}
    bare["catalog_id"] = catalog_hash(bare)
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(bare), encoding="utf-8")
    with pytest.raises(ValueError, match="id/hash mismatch"):
        PricingCatalog.load(bad, require_signature=False)


def test_unterminated_private_key_never_leaks_key_bytes():
    # Requiring the whole remainder to be PEM data meant one trailing byte — the
    # closing quote of a JSON string — defeated the match, so the key was emitted
    # verbatim right after the marker: output that reads as redacted while leaking
    # every byte, which is worse than a plain miss because it survives review.
    key = b"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"
    for blob in (
        b'{"k": "-----BEGIN PRIVATE KEY-----' + key + b'"}',
        b"-----BEGIN PRIVATE KEY----- " + key,
        b"-----BEGIN RSA PRIVATE KEY-----" + key,
        b"key='-----BEGIN EC PRIVATE KEY-----" + key + b"'",
    ):
        out = redact_blob(blob)
        assert b"[REDACTED PRIVATE KEY]" in out
        assert key[:24] not in out, out

    # Surrounding content is preserved rather than swallowed.
    framed = b'{"note": "hello", "k": "-----BEGIN PRIVATE KEY-----' + key + b'", "after": "kept"}'
    assert b'"after": "kept"' in redact_blob(framed)


def test_redaction_stays_linear_in_line_indentation():
    # `[ \t]*[+>-]?[ \t]*` gives O(n) ways to split n leading spaces, so a failing
    # match backtracks through every split and the scan turns quadratic. Ordinary
    # indented JSON — exactly what a captured trace looks like — passed the budget.
    blob = b"\n".join(b" " * 24 + b'"field": "value",' for _ in range(8000))
    started = time.monotonic()
    redact_blob(blob)
    assert time.monotonic() - started < 1.5


def test_indented_and_diff_marked_credentials_still_redact():
    for line in (
        b"  - api_key=sk-secret",
        b"+ANTHROPIC_API_KEY=sk-secret",
        b"    export API_KEY=sk-secret",
        b"> authorization: Bearer sk-secret",
        b"      Cookie: a=b",
    ):
        assert b"REDACTED" in redact_blob(line), line
