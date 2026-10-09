"""0.9.2 hardening of the tool sandbox, harnesses, providers and repository internals.

Each test pins one item of the 0.9.0 audit's hardening lists (slices B and D):
the redaction policy that nothing read, Windows batch-file argument injection,
API keys over cleartext HTTP, argv flag values in recorded commands, the
unbounded reflog, the repository descriptor's parser, blob-header parity and
the pack install's dependency ordering.
"""

from __future__ import annotations

import asyncio
import json
import os
import types
from pathlib import Path

import pytest

from opentine import Run
from opentine._canon import _redact
from opentine.graph import StepKind
from opentine.harnesses import GenericHarness
from opentine.kernel import KernelError, ObjectEnvelope
from opentine.models._compat_local import VLLM, OpenAICompatible
from opentine.models._endpoint_security import INSECURE_ENV, require_key_transport
from opentine.policies import PolicySet, RedactionPolicy
from opentine.redaction import redact_value
from opentine.repository import Repo, _reflog
from opentine.repository._blob_io import read_verified_blob_prefix
from opentine.repository._config import validate_config
from opentine.repository._pack_install import _dependency_order
from opentine.runtime import Agent
from opentine.tools import _batch_guard
from opentine.tools._process import run_bounded

# -- 1. RedactionPolicy is enforced ------------------------------------------------


def _policies(*names: str) -> dict:
    return PolicySet(redaction=RedactionPolicy(extra_secret_keys=names)).to_dict()


def _secret_run() -> Run:
    run = Run(run_id="policy", policies=_policies("tenantPin", "X-Internal-Sig"))
    run.add_step(
        StepKind.tool,
        {"tenant_pin": "4242-PIN", "x_internal_sig": "SIGVALUE", "query": "visible"},
        {"result": "fine"},
    )
    return run


def test_extra_secret_keys_are_redacted_in_a_saved_tine_file(tmp_path):
    path = _secret_run().save(tmp_path / "run.tine")
    text = Path(path).read_text(encoding="utf-8")
    assert "4242-PIN" not in text and "SIGVALUE" not in text
    assert "visible" in text
    # The policy itself survives the save, so every later save applies it too.
    reloaded = Run.load(path)
    assert reloaded.policies["redaction"]["extra_secret_keys"] == ["tenantPin", "X-Internal-Sig"]


def test_extra_secret_keys_are_redacted_in_a_repository(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    repo.put_run(_secret_run())
    stored = b"".join(repo.raw(oid) for oid in repo.iter_oids())
    assert b"4242-PIN" not in stored and b"SIGVALUE" not in stored
    assert b"visible" in stored


def test_an_agent_records_its_policy_set_on_the_run(tmp_path):
    class Echo:
        name = "echo"
        supports_tools = True
        supports_thinking = False

        async def complete(self, messages, tools=None, system=None, temperature=0.0):
            return {"text": "tenant_pin: 4242-PIN", "tool_calls": []}

    def lookup(tenant_pin: str) -> str:
        """Look a tenant up."""
        return "found"

    policies = PolicySet(redaction=RedactionPolicy(extra_secret_keys=("tenantPin",)))
    with pytest.raises(TypeError):
        Agent(model=Echo(), policies={"redaction": {}})
    run = asyncio.run(Agent(model=Echo(), tools=[lookup], policies=policies).run("go"))
    assert run.policies == policies.to_dict()
    saved = Path(run.save(tmp_path / "agent.tine")).read_text(encoding="utf-8")
    assert "4242-PIN" not in saved


@pytest.mark.parametrize(
    "kwargs",
    [
        {"redact_secrets": False},
        {"extra_secret_keys": ("steps",)},  # a format field: redacting it corrupts the run
        {"extra_secret_keys": ("",)},
        {"extra_secret_keys": "tenant_pin"},  # a string, not a tuple of names
        {"extra_secret_keys": ("x" * 129,)},
    ],
)
def test_a_redaction_policy_that_cannot_be_honoured_is_refused(kwargs):
    with pytest.raises(ValueError):
        RedactionPolicy(**kwargs)


def test_a_hostile_recorded_policy_cannot_redact_the_runs_structure(tmp_path):
    run = Run(run_id="hostile", policies={"redaction": {"extra_secret_keys": ["parent_ids"]}})
    run.add_step(StepKind.done, {"text": "ok"})
    path = run.save(tmp_path / "run.tine")
    assert Run.load(path).steps  # loads: the whole recorded list was ignored


# -- 2. Windows batch files: no argument cmd.exe would re-parse --------------------


@pytest.mark.parametrize(
    ("argv", "os_name", "refused"),
    [
        (["gemini.cmd", "-p", 'fix "x" & calc & "'], "nt", True),
        (["C:\\npm\\gemini.CMD", "a|b"], "nt", True),
        (["agent.bat", "100%"], "nt", True),
        (["agent.cmd. ", "x^y"], "nt", True),  # Windows drops the trailing dot and space
        (["agent.cmd", "line\nbreak"], "nt", True),
        (["agent.cmd", "plain words, (parens) and: colons"], "nt", False),
        (["agent.exe", 'fix "x" & calc'], "nt", False),  # no cmd.exe in between
        (["gemini.cmd", 'fix "x" & calc'], "posix", False),  # not Windows
    ],
)
def test_batch_file_arguments_cmd_would_reparse_are_refused(argv, os_name, refused):
    assert (_batch_guard.batch_refusal(argv, os_name=os_name) is not None) is refused


@pytest.fixture
def as_windows(monkeypatch):
    monkeypatch.setattr(_batch_guard, "os", types.SimpleNamespace(name="nt"))


def test_the_shell_and_python_launcher_refuses_before_starting(as_windows):
    with pytest.raises(ValueError, match="batch file"):
        run_bounded(["C:\\tools\\lint.cmd", 'x" & calc & "'], timeout=5, max_chars=100)


def test_a_harness_refuses_an_injected_task_before_starting(as_windows, tmp_path):
    harness = GenericHarness(command=("agent.cmd",), cwd=tmp_path)
    with pytest.raises(ValueError, match="batch file"):
        asyncio.run(harness.execute('summarise "notes" & del /q *'))


@pytest.mark.skipif(os.name != "nt", reason="cmd.exe re-parsing exists only on Windows")
def test_a_real_cmd_shim_is_never_handed_an_injected_argument(tmp_path):
    shim = tmp_path / "shim.cmd"
    shim.write_text("@echo %*\r\n", encoding="ascii")
    marker = tmp_path / "pwned.txt"
    with pytest.raises(ValueError, match="batch file"):
        run_bounded([str(shim), f'x" & echo hit > "{marker}" & "'], timeout=10, max_chars=100)
    assert not marker.exists()
    ok = run_bounded([str(shim), "plain", "words"], timeout=10, max_chars=100)
    assert "plain words" in ok.output(100)


# -- 3. No API key over cleartext HTTP to another machine ---------------------------


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("http://10.0.0.5:8000/v1", False),
        ("http://gpu-box.lan:8000/v1", False),
        ("HTTP://example.com/v1", False),
        ("https://gpu-box.lan/v1", True),
        ("http://localhost:8000/v1", True),
        ("http://127.0.0.1:8000/v1", True),
        ("http://[::1]:8000/v1", True),
        ("http://[::ffff:127.0.0.1]:8000/v1", True),
    ],
)
def test_a_key_travels_in_cleartext_only_to_loopback(url, allowed, monkeypatch):
    monkeypatch.delenv(INSECURE_ENV, raising=False)
    if allowed:
        require_key_transport(url, "sk-real")
    else:
        with pytest.raises(ValueError, match="cleartext"):
            require_key_transport(url, "sk-real")
    require_key_transport(url, "")  # no key, nothing to protect


def test_compatible_adapters_refuse_a_cleartext_remote_key(monkeypatch):
    monkeypatch.delenv(INSECURE_ENV, raising=False)
    remote = "http://10.0.0.5:8000/v1"
    with pytest.raises(ValueError, match="cleartext"):
        OpenAICompatible("m", base_url=remote, api_key="sk-real")
    with pytest.raises(ValueError, match="cleartext"):
        VLLM("m", host="http://10.0.0.5:8000", api_key="sk-real")
    VLLM("m", host="http://10.0.0.5:8000")  # the local server's placeholder key
    OpenAICompatible("m", base_url=remote, api_key="sk-real", allow_insecure=True)
    monkeypatch.setenv(INSECURE_ENV, "1")
    OpenAICompatible("m", base_url=remote, api_key="sk-real")


def test_anthropic_refuses_a_cleartext_remote_base_url(monkeypatch):
    pytest.importorskip("anthropic")
    from opentine.models.anthropic import Anthropic

    monkeypatch.delenv(INSECURE_ENV, raising=False)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://gateway.example:8080")
    with pytest.raises(ValueError, match="cleartext"):
        Anthropic(api_key="sk-ant-real")._get_client()


# -- 4. Flag values in a recorded command ---------------------------------------------


def test_secret_flag_values_in_a_recorded_command_are_redacted():
    command = [
        "codex",
        "--token=shortvalue",
        "--api-key=sk-x",
        "--password",
        "hunter2",
        "--auth",
        "user:pw",
        "--client-secret",
        "s3cr3t",
        "--max-tokens",
        "4096",
        "-p",
        "write the tests",
    ]
    recorded = redact_value(_redact({"command": command}))["command"]
    text = json.dumps(recorded)
    for secret in ("shortvalue", "sk-x", "hunter2", "user:pw", "s3cr3t"):
        assert secret not in text
    # A token *counter* and the prompt stay: -p is the prompt flag of most agent CLIs.
    assert recorded[-4:] == ["--max-tokens", "4096", "-p", "write the tests"]


# -- 5. The reflog is bounded ---------------------------------------------------------


def _churn(repo: Repo, count: int) -> list[str]:
    oids, previous = [], None
    for index in range(count):
        oid = repo.put("run", {"events": [], "manifests": {}, "roots": [], "tips": [], "n": index})
        repo.update_ref("experiments/churn", oid, expected_old=previous)
        oids.append(previous := oid)
    return oids


def test_a_reflog_keeps_its_newest_rows_within_the_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(_reflog, "MAX_REFLOG_BYTES", 4096)
    repo = Repo.init(tmp_path / "repo")
    oids = _churn(repo, 80)
    log = repo.path / "logs" / "experiments" / "churn"
    rows = [json.loads(row) for row in log.read_bytes().splitlines()]
    assert log.stat().st_size <= 4096
    assert [row["new"] for row in rows] == oids[-len(rows) :]
    assert all(row["old"] == oids[oids.index(row["new"]) - 1] for row in rows)


def test_an_oversized_reflog_from_an_older_version_is_cut_on_its_next_append(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "repo")
    first = _churn(repo, 1)
    log = repo.path / "logs" / "experiments" / "churn"
    log.write_bytes(log.read_bytes() * 400)  # an old, never-rotated log
    monkeypatch.setattr(_reflog, "MAX_REFLOG_BYTES", 2048)
    oid = repo.put("run", {"events": [], "manifests": {}, "roots": [], "tips": [], "n": 99})
    repo.update_ref("experiments/churn", oid, expected_old=first[0])
    rows = log.read_bytes().splitlines()
    assert log.stat().st_size <= 2048
    assert json.loads(rows[-1])["new"] == oid and all(json.loads(row) for row in rows)


# -- 6. The repository descriptor -----------------------------------------------------

_CANONICAL = b'{"format":3,"object_hash":"sha256","repository":"opentine","version":1}\n'


@pytest.mark.parametrize(
    ("raw", "accepted"),
    [
        (_CANONICAL, True),
        (b"\xef\xbb\xbf" + _CANONICAL, True),  # a BOM from an editor
        (_CANONICAL.replace(b"}", b',"future":true}'), True),  # SPEC 2.2: unknown keys pass
        (_CANONICAL.replace(b'"version":1', b'"version":true'), False),  # true is not 1
        (_CANONICAL.replace(b'"format":3', b'"format":3,"format":2'), False),  # which one?
        (_CANONICAL.replace(b'"format":3', b'"format":2,"format":3'), False),
        (_CANONICAL.replace(b"opentine", b"opentin\xe9"), False),  # not UTF-8
    ],
)
def test_the_repository_descriptor_has_one_reading(tmp_path, raw, accepted):
    path = tmp_path / "config.json"
    path.write_bytes(raw)
    if accepted:
        validate_config(path)
    else:
        with pytest.raises(ValueError):
            validate_config(path)


# -- 7. Both blob readers refuse the same headers -----------------------------------


@pytest.mark.parametrize(
    "header",
    [
        b'{"encoding": "raw","schema":1,"type":"blob"}',
        b'{"schema":1,"encoding":"raw","type":"blob"}',
        b'{"encoding":"raw","extra":1,"schema":1,"type":"blob"}',
        b'{"encoding":"json","schema":1,"type":"blob"}',
        b'{"encoding":"raw","schema":0,"type":"blob"}',
        b'{"encoding":"raw","schema":"1","type":"blob"}',
        b'{"encoding":"raw","schema":1.0,"type":"blob"}',
        b'{"encoding":"raw","encoding":"raw","schema":1,"type":"blob"}',
        '{"encoding":"raw","schema":1,"type":"blob"}'.encode("utf-16-le"),
        b'{"encoding":"raw","schema":1,"type":"blob"' + b" " * 260 + b"}",
    ],
)
def test_the_streamed_blob_reader_refuses_what_decode_refuses(tmp_path, header):
    repo = Repo.init(tmp_path / "repo")
    oid = repo.put("blob", b"hello blob")
    stored = header + b"\n" + b"hello blob"
    path = repo._object_path(oid)
    os.chmod(path, 0o644)
    path.write_bytes(stored)
    with pytest.raises(KernelError):
        ObjectEnvelope.decode(stored, oid)
    with pytest.raises(KernelError):
        read_verified_blob_prefix(repo, oid, prefix_limit=4, source_limit=1024)


# -- 8. Pack install ordering is linear in the objects --------------------------------


class _CountingLinks(dict):
    lookups = 0

    def get(self, key, default=None):
        type(self).lookups += 1
        return super().get(key, default)


@pytest.mark.parametrize("shape", ["chain-reversed", "star", "chain-shuffled"])
def test_dependency_order_expands_each_object_once(shape):
    count = 10_000
    oids = [f"event:sha256:{index:064x}" for index in range(count)]
    links = _CountingLinks()
    if shape == "star":
        links[oids[0]] = set(oids[1:])
    else:
        for index in range(1, count):
            links[oids[index]] = {oids[index - 1]}
    order = list(reversed(oids)) if shape != "chain-shuffled" else oids[::2] + oids[1::2]
    _CountingLinks.lookups = 0
    placed = _dependency_order([(oid, b"") for oid in order], links)
    assert _CountingLinks.lookups <= count  # one expansion per object, whatever the order
    position = {oid: index for index, (oid, _) in enumerate(placed)}
    assert len(position) == count
    assert all(position[link] < position[oid] for oid, targets in links.items() for link in targets)
