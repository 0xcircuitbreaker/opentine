"""V3 structured content is scrubbed before canonicalization and hashing."""

from __future__ import annotations

import json
from pathlib import Path

from opentine import Repo, Run, StepKind
from opentine.repository.runs import put_run
from opentine.trace import Recorder, TraceEvent

_SECRET_TEXT = (
    "+OPENAI_API_KEY=ordinary-secret-value\n"
    "+Authorization: Basic dXNlcjpwYXNz\n"
    "+Cookie: session=secret-cookie"
)


def _blob_json(repo: Repo, oid: str):
    return json.loads(repo.get(oid).body)


def _assert_scrubbed(value) -> None:
    rendered = json.dumps(value)
    assert "ordinary-secret-value" not in rendered
    assert "dXNlcjpwYXNz" not in rendered
    assert "secret-cookie" not in rendered
    assert "[REDACTED]" in rendered


def test_recorder_scrubs_code_patch_and_tool_payloads(tmp_path: Path):
    repo = Repo.init(tmp_path / "repo")
    recorder = Recorder.start(repo, code={"patch": _SECRET_TEXT}, capture=False)
    _assert_scrubbed(_blob_json(repo, recorder.payload["manifests"]["code"]))

    event_id = recorder.append(
        TraceEvent(
            kind="tool",
            timestamp=1,
            trace_id="trace",
            span_id="span",
            inputs={"request": _SECRET_TEXT},
            outputs={"response": _SECRET_TEXT},
            usage={"input_tokens": 7, "token": 9},
        )
    )
    event = repo.get(event_id).payload()
    _assert_scrubbed(_blob_json(repo, event["input_blob"]))
    _assert_scrubbed(_blob_json(repo, event["output_blob"]))
    assert event["usage"] == {"input_tokens": 7, "token": 9}


def test_compat_run_and_direct_structures_scrub_free_form_strings(tmp_path: Path):
    repo = Repo.init(tmp_path / "repo")
    run = Run(id="legacy", model_info="model")
    run.add_step(
        StepKind.tool,
        {"request": _SECRET_TEXT},
        outputs={"response": _SECRET_TEXT},
        usage={"input_tokens": 11, "token": 13},
    )
    result = put_run(repo, run)
    event = repo.get(repo.get(result.run_id).payload()["events"][0]).payload()
    _assert_scrubbed(_blob_json(repo, event["input_blob"]))
    _assert_scrubbed(_blob_json(repo, event["output_blob"]))
    assert event["usage"] == {"input_tokens": 11, "token": 13}

    oid = repo.put(
        "annotation",
        {"note": _SECRET_TEXT, "input_tokens": 17, "token": 19},
    )
    annotation = repo.get(oid).payload()
    _assert_scrubbed(annotation)
    assert annotation["input_tokens"] == 17 and annotation["token"] == 19

    secret_key = "OPENAI_API_KEY=ordinary-secret-value"
    keyed = repo.get(repo.put("annotation", {secret_key: "value"})).payload()
    assert "ordinary-secret-value" not in json.dumps(keyed)


def test_structured_redaction_handles_camel_case_and_plural_credentials(tmp_path: Path):
    repo = Repo.init(tmp_path / "repo")
    payload = {
        "accessToken": "ordinary-secret-value",
        "clientSecret": "ordinary-secret-value",
        "refreshToken": "ordinary-secret-value",
        "sessionToken": "ordinary-secret-value",
        "api_keys": ["ordinary-secret-value"],
        "passwords": ["ordinary-secret-value"],
        "XApiKey": "ordinary-secret-value",
        "xAPIKey": "ordinary-secret-value",
        "openAIApiKey": "ordinary-secret-value",
        "OpenAIAPIKeys": ["ordinary-secret-value"],
        "AWSAccessKey": "ordinary-secret-value",
        "JWTAccessToken": "ordinary-secret-value",
        "OIDCRefreshToken": "ordinary-secret-value",
        "oauthIdToken": "ordinary-secret-value",
        "oauthBearerToken": "ordinary-secret-value",
        "databasePassphrase": "ordinary-secret-value",
        "serviceCredential": "ordinary-secret-value",
        "sessionCookie": "ordinary-secret-value",
        "httpAuthorization": "ordinary-secret-value",
        "vendorSetCookie": "ordinary-secret-value",
        "vendorProxyAuthorization": "ordinary-secret-value",
        "inputTokens": 23,
        "publicKeys": ["public-value"],
        "authorizationStatus": "enabled",
        "cookieCount": 2,
    }
    stored = repo.get(repo.put("annotation", payload)).payload()
    rendered = json.dumps(stored)
    assert "ordinary-secret-value" not in rendered
    assert stored["inputTokens"] == 23
    assert stored["publicKeys"] == ["public-value"]
    assert stored["authorizationStatus"] == "enabled"
    assert stored["cookieCount"] == 2


def test_structured_redaction_scrubs_bare_token_header_shapes(tmp_path: Path):
    repo = Repo.init(tmp_path / "repo")
    payload = {
        "pair": ["token", "ordinary-secret-value"],
        "har": {"Name": "token", "Value": "ordinary-secret-value"},
        "headers": ["token: ordinary-secret-value"],
        "token": 29,
        "inputTokens": 31,
    }
    stored = repo.get(repo.put("annotation", payload)).payload()
    assert "ordinary-secret-value" not in json.dumps(stored)
    assert stored["token"] == 29 and stored["inputTokens"] == 31
