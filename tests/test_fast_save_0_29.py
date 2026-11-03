"""0.29.0 fast saves: memoized redaction must not change a single output byte.

The digests below were generated with the 0.28.0 save path, before redaction was
memoized, so they pin the old bytes exactly (format v4 and the legacy v2 writer,
uncompressed).
"""

from __future__ import annotations

import contextlib
import hashlib
import sys
import time

import pytest

from opentine import Run, RunStatus, StepKind

_PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
_SECRETS = [
    "export OPENAI_API_KEY=sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4",
    "curl -H 'Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789' https://x.io",
    '{"password": "hunter2-very-secret", "user": "bob"}',
    "postgres://admin:s3cr3tpass@db.internal:5432/app",
    "https://api.example.com/v1?api_key=AKIAABCDEFGHIJKLMNOP&q=1",
    _PEM,
    "--password hunter2xyz",
]


def _build(kind: str, steps: int = 30) -> Run:
    policies = {"redaction": {"extra_secret_keys": ["customer_ssn"]}} if kind == "policy" else {}
    run = Run(run_id=f"fast-{kind}", created_at=1_700_000_000.0, model_info="mock-model")
    run.policies = policies
    for i in range(steps):
        secret = _SECRETS[i % len(_SECRETS)] if kind != "plain" else f"plain text {i}"
        if i % 3 == 0:
            run.add_step(
                StepKind.model,
                {"messages": [{"role": "user", "content": f"step {i}: {secret}"}]},
                outputs={"text": secret, "repeat": secret},
                usage={"input_tokens": 100 + i, "output_tokens": 7},
            )
        elif i % 3 == 1:
            inputs = {"command": ["cli", "--token", "tok-abc123xyz", f"f{i}"], "cwd": "/w"}
            if kind == "policy":
                inputs["customer_ssn"] = "corp-ssn-93f1c2"
            run.add_step(StepKind.tool, inputs, tool_info={"name": "bash"})
        else:
            run.add_step(
                StepKind.tool,
                {"path": f"src/m{i}.py", "env": {"API_KEY": "abc123def456", "HOME": "/h"}},
                outputs={"stdout": f"line {i}\n{secret}\n" * 3, "exit_code": 0},
            )
    for index, step in enumerate(run.steps):  # wall-clock stamps, pinned for the digest
        object.__setattr__(step, "timestamp", 1_700_000_000.0 + index)
    run.status = RunStatus.completed
    return run


GOLDEN = {
    ("plain", "4"): "a1f883c41171ef9ae2babd61e9fb47d6b56ee40f5bf0ec49018320529a2228ae",
    ("secrets", "4"): "c32473bc945dd3778b3be1a9db8f6a8776aa3939f069c8c8b08289b3cd136eae",
    ("policy", "4"): "ec8e860bd1a1fc47b1a1ac59c88f5135ab442737a819992bf3c9293e76524687",
    ("secrets", "2"): "dc0ec4df866a64b86373d6d1b5a20612b999252952bc2a5f8c2ac92f026a8eb4",
}


@pytest.mark.parametrize(("kind", "fmt"), sorted(GOLDEN))
def test_save_bytes_are_identical_to_0_28(tmp_path, monkeypatch, kind, fmt):
    monkeypatch.setenv("OPENTINE_FORMAT", fmt)
    monkeypatch.setenv("OPENTINE_COMPRESS", "0")  # zlib output is not pinned across builds
    path = tmp_path / "r.tine"
    _build(kind).save(path)
    data = path.read_bytes()
    if not (fmt == "2" and sys.platform == "win32"):  # the v2 writer's bytes vary by OS
        assert hashlib.sha256(data).hexdigest() == GOLDEN[(kind, fmt)]
    for needle in (b"sk-proj-a1b2", b"hunter2", b"s3cr3tpass", b"ghp_abcdef", b"MIIEvQIB"):
        assert needle not in data
    if kind == "policy":
        assert b"corp-ssn-93f1c2" not in data


def test_memo_is_scoped_to_one_save():
    from opentine._redact_memo import active, save_memo
    from opentine.redaction import redact_text

    assert active() is None
    assert redact_text("password=hunter2") == "password=[REDACTED]"
    with save_memo():
        assert redact_text("password=hunter2") == redact_text("password=hunter2")
        assert redact_text("password=hunter2") == "password=[REDACTED]"
        assert len(active()) == 1
    assert active() is None


def _best_save(tmp_path, steps: int) -> float:
    run = _build("secrets", steps)
    best = float("inf")
    for attempt in range(3):
        start = time.perf_counter()
        run.save(tmp_path / f"s{steps}-{attempt}.tine")
        best = min(best, time.perf_counter() - start)
    return best


def test_save_time_scales_linearly(tmp_path):
    # 8x the steps: linear is ~8x, quadratic ~64x. The bound is generous for noisy
    # runners, and the floor keeps a tiny small-run time from inflating the ratio.
    small = _best_save(tmp_path, 60)
    large = _best_save(tmp_path, 480)
    assert large < max(small, 0.05) * 24


@pytest.mark.parametrize(("kind", "fmt"), sorted(GOLDEN))
def test_memoized_and_unmemoized_saves_match_on_every_platform(tmp_path, monkeypatch, kind, fmt):
    import opentine._redact_memo as memo

    monkeypatch.setenv("OPENTINE_FORMAT", fmt)
    monkeypatch.setenv("OPENTINE_COMPRESS", "0")
    fast = tmp_path / "fast.tine"
    _build(kind).save(fast)
    monkeypatch.setattr(memo, "save_memo", contextlib.nullcontext)
    slow = tmp_path / "slow.tine"
    _build(kind).save(slow)
    assert fast.read_bytes() == slow.read_bytes()
