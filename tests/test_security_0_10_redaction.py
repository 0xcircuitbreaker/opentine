"""0.10 round-3 audit: credentials that still reached disk or a collector.

C3-4 -- common credential shapes, names and placements both writers kept (a
parametrized corpus, saved through ``Run.save`` and ``Repo.put_run``); C3-3 --
``tine export`` sending secrets a pre-0.9.1 ``.tine`` holds under field names in
the ``gen_ai.prompt`` kvlist; and the export hardening (query strings in printed
endpoints, foreign reserved ``opentine.*`` attributes). Every value is fake.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from opentine import Run, cli
from opentine.core import RunStatus
from opentine.graph import StepKind
from opentine.redaction import redact_text
from opentine.repository import Repo

_PEM = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEFAKEFAKEFAKEFAKEFAKE\n-----END RSA PRIVATE KEY-----\n"

# Vendor prefixes are split so the fake tokens below never trip push-time
# secret scanning; the joined strings are the real shapes under test.
_XOXE = "xo" + "xe"
_GL = "g" + "l"

#: (case, text carrying the secret, the secret)
LEAKS = [
    ("xai", "XAI key xai-FAKEFAKE0123456789abcdefABCDEF0123456789FAKE", "xai-FAKEFAKE0123"),
    ("groq", "gsk_FAKEFAKE0123456789abcdefABCDEF0123456789abcd", "gsk_FAKEFAKE0123"),
    ("replicate", "r8_FAKEFAKE0123456789abcdefABCDEF0123456", "r8_FAKEFAKE0123"),
    ("perplexity", "pplx-FAKEFAKE0123456789abcdefABCDEF0123456789abc", "pplx-FAKEFAKE0123"),
    ("google_oauth", "token ya29.a0FAKEFAKE0123456789abcdefABCDEF", "a0FAKEFAKE0123"),
    ("google_client", "GOCSPX-FAKEFAKE0123456789abcdefABCD", "GOCSPX-FAKEFAKE"),
    ("slack_app", "xapp-1-A0FAKE6789-1234567890123-abababababababab", "A0FAKE6789"),
    ("slack_refresh", _XOXE + "-1-FAKEFAKE0123456789abcdefABCDEF", _XOXE + "-1-FAKEFAKE"),
    ("stripe_webhook", "whsec_FAKEFAKE0123456789abcdefABCDEF0123456789", "whsec_FAKEFAKE"),
    ("gitlab_runner", _GL + "rt-FAKEFAKE0123456789ab", _GL + "rt-FAKEFAKE"),
    ("gitlab_deploy", _GL + "dt-FAKEFAKE0123456789ab", _GL + "dt-FAKEFAKE"),
    ("gitlab_trigger", _GL + "ptt-FAKEFAKE0123456789ab", _GL + "ptt-FAKEFAKE"),
    ("mysql_pwd_env", "export MYSQL_PWD=FAKEpw-hunter2-mysql", "FAKEpw-hunter2"),
    ("otel_pwd_attr", "app.db.pwd: FAKEdbPwd12345", "FAKEdbPwd12345"),
    ("azure_storage", "AZURE_STORAGE_KEY=FAKEazureStorageKey0123456789", "FAKEazureStorage"),
    (
        "auth_mid_line",
        "2026-10-14 12:00:01 DEBUG send: Authorization: Basic RkFLRTpGQUtFMTIz",
        "RkFLRTpGQUtFMTIz",
    ),
    (
        "auth_in_repr",
        "send: b'GET / HTTP/1.1\\r\\nAuthorization: Basic RkFLRTpSRVBSMTIz\\r\\n'",
        "RkFLRTpSRVBSMTIz",
    ),
    ("cookie_mid_line", "12:00:01 > Cookie: session=FAKEcookieVALUE123", "FAKEcookieVALUE"),
    ("wget_header", "wget --header=Authorization:FAKEheaderValue1 https://x", "FAKEheaderValue1"),
    ("docker_auth", 'cat config.json: {"auth": "RkFLRTpkb2NrZXItcGFzcw=="}', "RkFLRTpkb2NrZXIt"),
    (
        "kubeconfig_key_data",
        "client-key-data: " + base64.b64encode(_PEM).decode(),
        base64.b64encode(_PEM).decode()[:24],
    ),
    (
        "base64_private_key",
        "blob " + base64.b64encode(_PEM).decode(),
        base64.b64encode(_PEM).decode()[:24],
    ),
    ("netrc", "machine host login bob password FAKEnetrcPassw0rd", "FAKEnetrcPassw0rd"),
    ("netrc_line", "machine h\n  password FAKEnetrcLine01\n", "FAKEnetrcLine01"),
    ("curl_user", "curl -u bob:FAKEcurlPassw0rd https://x", "FAKEcurlPassw0rd"),
    ("mysql_short_flag", "mysql -ubob -pFAKEmysqlShortFlag db", "FAKEmysqlShortFlag"),
    ("redis_cli", "redis-cli -h h -a FAKEredisPassw0rd", "FAKEredisPassw0rd"),
    ("docker_login", "docker login -u bob -p FAKEdockerPassw0rd r.io", "FAKEdockerPassw0rd"),
    ("url_password_slash", "postgres://u:FAKE/pw0rd@db.example:5432/x", "FAKE/pw0rd"),
    ("xml_password", "<password>FAKExmlPassw0rd</password>", "FAKExmlPassw0rd"),
    ("query_key", "GET https://x.example/v1?key=FAKEqueryKey123", "FAKEqueryKey123"),
    ("query_code", "callback https://x.example/cb?code=FAKEoauthCode123", "FAKEoauthCode123"),
]

#: Text that must come back unchanged: no secret in it.
KEPT = [
    "PWD=/home/user/project",
    "https://registry.npmjs.org:443/@babel/core",
    "mkdir -p build && git push -u origin main",
    "input_tokens: 1234",
]


@pytest.mark.parametrize(("case", "text", "secret"), LEAKS, ids=[case for case, _, _ in LEAKS])
def test_credential_shapes_are_redacted_on_both_writers(tmp_path, case, text, secret):
    run = Run(run_id=f"leak-{case}")
    run.add_step(StepKind.tool, {"command": text}, outputs={"output": text})
    run.status = RunStatus.completed
    path = tmp_path / "run.tine"
    run.save(path)
    assert secret not in path.read_text(encoding="utf-8")

    repo = Repo.init(tmp_path / "repo")
    repo.put_run(run)
    for blob in (tmp_path / "repo").rglob("*"):
        if blob.is_file():
            assert secret.encode() not in blob.read_bytes(), blob


@pytest.mark.parametrize("text", KEPT)
def test_ordinary_text_is_not_redacted(text):
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "name", ["MYSQL_PWD", "ldap_bind_pw", "AZURE_STORAGE_KEY", "client-key-data", "key_data"]
)
def test_credential_field_names_are_redacted(tmp_path, name):
    run = Run(run_id="names")
    run.add_step(StepKind.tool, {"env": {name: "FAKEfieldSecret99"}})
    run.save(tmp_path / "r.tine")
    assert "FAKEfieldSecret99" not in (tmp_path / "r.tine").read_text(encoding="utf-8")


# --- C3-3: tine export of a .tine an older writer left secrets in ----------------- #


@pytest.fixture
def old_artifact(monkeypatch, tmp_path: Path) -> Path:
    """A ``.tine`` saved with the name pass skipped, as 0.9.0's writer did for these names."""
    from opentine import _graph_serde

    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(run_id="old-writer")
    run.add_step(
        StepKind.tool,
        {
            "connection_string": "Server=db;User=bob;Pwd=FAKEhunter2secret;",
            "github_token": "plainGithubTokenValue12345",
            "subscription_key": "plainSubscriptionKey67890",
        },
        outputs={"result": "ok"},
    )
    run.status = RunStatus.completed
    with monkeypatch.context() as patch:
        patch.setattr(_graph_serde, "_redact", lambda value: value)
        patch.setattr(_graph_serde, "redact_value", lambda value: value)
        path = tmp_path / "old.tine"
        run.save(path)
    assert "plainGithubTokenValue12345" in path.read_text(encoding="utf-8")
    return path


def test_export_redacts_secrets_kept_under_field_names(old_artifact, tmp_path, capsys):
    output = tmp_path / "export.json"
    cli.main(["export", str(old_artifact), "--output", str(output)])
    exported = output.read_text(encoding="utf-8")
    for secret in ("FAKEhunter2secret", "plainGithubTokenValue12345", "plainSubscriptionKey67890"):
        assert secret not in exported
    assert "gen_ai.prompt" in exported  # the step still exported


def test_printed_endpoints_lose_their_query_string():
    from opentine._cli_text import endpoint_for_display

    shown = endpoint_for_display("https://bob:pw@collector.example/v1/traces?token=SECRET#frag")
    assert shown == "https://collector.example/v1/traces"


def test_export_drops_reserved_attributes_the_event_does_not_derive():
    from opentine.trace.exporters import (
        BILLING_ATTRIBUTE,
        COST_ATTRIBUTE,
        KIND_ATTRIBUTE,
        to_otel_genai,
    )
    from opentine.trace.schema import TraceEvent

    event = TraceEvent(
        "tool",
        1,
        "trace",
        "span",
        attributes={
            COST_ATTRIBUTE: "999",
            BILLING_ATTRIBUTE: {"amount_usd": "999"},
            KIND_ATTRIBUTE: "model",
        },
    )
    keys = {item["key"] for item in to_otel_genai([event])[0]["attributes"]}
    assert COST_ATTRIBUTE not in keys and BILLING_ATTRIBUTE not in keys
    span = to_otel_genai([event])[0]
    kinds = [a["value"] for a in span["attributes"] if a["key"] == KIND_ATTRIBUTE]
    assert kinds in ([], [{"stringValue": "tool"}])


def test_export_document_has_no_secret_json_anywhere(old_artifact, tmp_path):
    output = tmp_path / "export.json"
    cli.main(["export", str(old_artifact), "--output", str(output)])
    document = json.loads(output.read_text(encoding="utf-8"))
    assert "plainSubscriptionKey67890" not in json.dumps(document)


# --- re-audit (0.10.0 round 2) -------------------------------------------------


def _wrapped(text: str, width: int) -> str:
    return "\n".join(text[i : i + width] for i in range(0, len(text), width)) + "\n"


@pytest.mark.parametrize("width", [64, 76])
def test_wrapped_base64_private_key_is_redacted_whole(width):
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from opentine._redact_forms import redact_forms

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    block = _wrapped(base64.b64encode(pem).decode(), width)
    out = redact_forms(("$ base64 key.pem\n" + block + "done\n").encode()).decode()
    assert [line for line in block.splitlines() if line in out] == []
    assert out.endswith("[REDACTED]\ndone\n")


def test_netrc_redaction_keeps_json_in_a_string_parseable():
    from opentine._redact_forms import redact_forms

    text = '{"cmd":"login h password hunter2xyz","n":1}'
    out = redact_forms(text.encode()).decode()
    assert json.loads(out) == {"cmd": "login h password [REDACTED]", "n": 1}


def test_prefixed_pw_and_rediscli_auth_are_redacted_in_command_text():
    from opentine._redact_forms import redact_forms

    out = redact_forms(b"export LDAP_BIND_PW=hunter2xyz REDISCLI_AUTH=s3cr3t PWD=/home/u")
    assert b"hunter2xyz" not in out and b"s3cr3t" not in out and b"PWD=/home/u" in out


def test_recorded_policy_with_a_refused_name_keeps_its_other_secret_keys(tmp_path):
    from opentine.policies import run_redaction

    policies = {"redaction": {"extra_secret_keys": ["root", "customer_ssn"]}}
    run = Run(run_id="policy")
    run.policies = policies
    run.add_step(StepKind.think, {"customer_ssn": "corp-ssn-93f1c2", "q": "x"})
    path = tmp_path / "r.tine"
    with pytest.warns(RuntimeWarning, match="extra_secret_keys"):
        with run_redaction(policies):
            pass
        run.save(path)
    assert "corp-ssn-93f1c2" not in path.read_text(encoding="utf-8")


# Round-2 regression corpus: every redaction fix of 0.10 checked through the full
# free-text pass, so one pattern's fix can never quietly undo another's.
def _wrapped_key_block(width):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return _wrapped(base64.b64encode(pem).decode(), width)


@pytest.mark.parametrize("width", [64, 76])
@pytest.mark.parametrize("form", ["real", "json", "json-crlf", "tool-args"])
def test_wrapped_base64_key_is_redacted_in_every_carrier(width, form):
    from opentine.redaction import redact_text

    block = _wrapped_key_block(width).rstrip("\n")
    carriers = {
        "real": block,
        "json": json.dumps(block),
        "json-crlf": json.dumps(block.replace("\n", "\r\n")),
        "tool-args": json.dumps({"path": "k.b64", "content": block}),
    }
    out = redact_text(carriers[form])
    assert [line for line in block.splitlines() if line in out] == []
    if form != "real":
        json.loads(out)


def test_a_wrapped_base64_certificate_is_not_a_secret():
    from opentine._redact_forms import redact_forms

    cert = b"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ" + b"A" * 40
    assert redact_forms(cert) == cert


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ('machine h login u password "p@ss w0rd"', "p@ss w0rd"),
        ('password "quotedSECRET"', "quotedSECRET"),
        ("machine h login u password Tr0ub4dor;3xyzSECRET", "3xyzSECRET"),
        ("machine h login u password ab,cdSECRET", "cdSECRET"),
        ("password abc;defSECRET\n", "defSECRET"),
    ],
)
def test_netrc_passwords_are_redacted_whole(text, secret):
    from opentine.redaction import redact_text

    assert secret not in redact_text(text)


@pytest.mark.parametrize(
    "value",
    [
        {"netrc": "machine h login u password X1secret", "k": 1},
        {"n": 'machine h login u password "qq secret"', "m": [1]},
    ],
)
def test_netrc_redaction_never_breaks_the_json_around_it(value):
    from opentine.redaction import redact_text

    out = json.loads(redact_text(json.dumps(value)))
    assert "secret" not in json.dumps(out) and set(out) == set(value)


@pytest.mark.parametrize(
    "text",
    [
        "https://example.pw:8443/api/v1/status",
        "admin@host.pw:22",
        "report.pw: section 3",
        "x.pwd:8443/api",
        "PWD=/home/u",
    ],
)
def test_pw_hosts_and_ports_are_not_credentials(text):
    from opentine._redact_forms import redact_forms

    assert redact_forms(text.encode()) == text.encode()


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("LDAP_BIND_PW=s3cretpw", "s3cretpw"),
        ("export MYSQL_PWD=12345", "12345"),
        ("app.db.pwd: hunter2", "hunter2"),
        ("my-service-pw: t0psecret", "t0psecret"),
    ],
)
def test_pw_assignments_are_still_redacted(text, secret):
    from opentine._redact_forms import redact_forms

    assert secret.encode() not in redact_forms(text.encode())


# Round-3: the host:port exemption is ":"-only after a dotted name, never an
# assignment; a quoted netrc token runs to its own closing quote through the other
# quote character and backslash escapes.
@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("MYSQL_PWD=2024/Summer!x", "Summer!x"),
        ("export LDAP_BIND_PW=12/abcSECRET", "abcSECRET"),
        ("spring.datasource.pwd: 7/Kq9SECRET", "Kq9SECRET"),
        ("MYSQL_PWD=8443", "8443"),
    ],
)
def test_digit_slash_passwords_in_assignments_are_redacted(text, secret):
    from opentine.redaction import redact_text

    assert secret not in redact_text(text)


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ('machine h login u password "it\'s my secret"', "s my secret"),
        ('machine h\nlogin u\npassword "it\'s my secret"\n', "s my secret"),
        ('machine h login u password "pa\\\\ss SECRET"', "ss SECRET"),
        ('machine h login u password "a\\"b SECRET"', "b SECRET"),
        ("machine h login u password 'single quoted SECRET'", "quoted SECRET"),
        ('password "x SECRET"  \n', "x SECRET"),
    ],
)
def test_quoted_netrc_tokens_are_redacted_whole(text, secret):
    from opentine.redaction import redact_text

    assert secret not in redact_text(text)


def test_quoted_netrc_in_json_keeps_the_json_parseable():
    from opentine.redaction import redact_text

    value = {"cmd": 'machine h login u password "it\'s a \\\\ SECRET"', "n": [1]}
    out = json.loads(redact_text(json.dumps(value)))
    assert "SECRET" not in json.dumps(out) and out["n"] == [1]
    unclosed = {"cmd": "machine h login u password 'abc", "b": 1}
    assert json.loads(redact_text(json.dumps(unclosed)))["b"] == 1


def test_prose_after_password_is_kept():
    from opentine._redact_forms import redact_forms

    assert redact_forms(b"password is required\n") == b"password is required\n"


# Round-4: redaction never turns valid JSON into invalid JSON (a quoted netrc or
# pwd value took the closing quote of a JSON string for an opening one), never eats
# prose, follows netrc's escaped quote inside a JSON string, and covers quoted and
# flag-form pwd assignments.
_ROUND4_SHAPES = [
    "machine h login u password ",
    "login root password ",
    "MYSQL_PWD=",
    "app.db.pwd: ",
    'machine h login u password "a\\"b SECRET"',
    'machine h login u password "pa\\\\ss SECRET"',
    "export MYSQL_PWD='hunter2'; mysql -u root",
    'export MYSQL_PWD="hunter2"',
    "--db-pwd hunter2xyz",
    'password "it\'s my secret"',
    "password 'abc",
    'password "abc',
    "MYSQL_PWD=C:\\path\\x",
]
_JSON_CORPUS = [text for _, text, _ in LEAKS] + list(KEPT) + _ROUND4_SHAPES


def _documents(text):
    yield {"a": text, "b": "x"}
    yield {"a": text, "b": 1, "c": [text, {"d": text}]}
    yield {text: text, "k": [1, 2]}
    yield [text, text, {"z": text}]


@pytest.mark.parametrize("text", _JSON_CORPUS)
def test_redaction_never_breaks_json(text):
    from opentine.redaction import redact_blob

    for doc in _documents(text):
        for separators in ((", ", ": "), (",", ":")):
            raw = json.dumps(doc, separators=separators).encode()
            json.loads(redact_blob(raw))


@pytest.mark.parametrize(
    "text",
    [
        'Password "must contain 8 chars" is the validation message',
        "password 'reset' links expire after 24h",
        'password "x" is the placeholder text',
    ],
)
def test_prose_with_a_quoted_word_after_password_is_kept(text):
    from opentine._redact_forms import redact_forms

    assert redact_forms(text.encode()) == text.encode()


def test_json_escaped_netrc_password_with_an_escaped_quote_is_redacted_whole():
    from opentine.redaction import redact_text

    value = {"cmd": 'machine h login u password "a\\"b SECRET"', "n": 1}
    out = redact_text(json.dumps(value))
    assert "SECRET" not in out and json.loads(out)["n"] == 1


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("export MYSQL_PWD='hunter2x'", "hunter2x"),
        ('export MYSQL_PWD="hunter2x"', "hunter2x"),
        ('mysql_pwd: "hunter2x"', "hunter2x"),
        ('spring.datasource.pwd="hunter2x"', "hunter2x"),
        ("--db-pwd=hunter2x", "hunter2x"),
        ("--db-pwd hunter2x", "hunter2x"),
        ("--mysql-pw=hunter2x", "hunter2x"),
        ("-db-pw hunter2x", "hunter2x"),
    ],
)
def test_quoted_and_flag_form_pwd_assignments_are_redacted(text, secret):
    from opentine.redaction import redact_text

    out = redact_text(text)
    assert secret not in out
    assert out.count('"') == text.count('"') and out.count("'") == text.count("'")


# Round-5: a JSON (or JSON Lines) blob is redacted string by string, so no byte
# pattern can ever cross a string boundary; quoted CLI passwords are redacted; and
# ``mysql -P<port>`` is a port, not a password.
_ROUND5_SHAPES = [
    'sh -c "mysql -u root -phunter2"',
    'sh -c "redis-cli -h h -a hunter2"',
    'sh -c "docker login -u me -p hunter2"',
    'sh -c "curl -u admin:hunter2"',
    "x <password>hunter2</password>",
    "the api_key: ",
    "the password:",
    "api_key=",
    "mysql -u root -p'hunter2'",
    'redis-cli -a "hunter2" ping',
]
_ALL_SHAPES = _JSON_CORPUS + _ROUND5_SHAPES
_NEEDLES = [(text, secret) for _, text, secret in LEAKS] + [
    ('sh -c "mysql -u root -phunter2"', "hunter2"),
    ('sh -c "redis-cli -h h -a hunter2"', "hunter2"),
    ('sh -c "docker login -u me -p hunter2"', "hunter2"),
    ('sh -c "curl -u admin:hunter2"', "hunter2"),
    ("x <password>hunter2</password>", "hunter2"),
    ("mysql -u root -p'hunter2'", "hunter2"),
]


@pytest.mark.parametrize("text", _ALL_SHAPES)
def test_redacted_json_always_parses_with_every_shape_in_every_position(text):
    from opentine.redaction import redact_blob

    for doc in _documents(text):
        for separators in ((", ", ": "), (",", ":")):
            raw = json.dumps(doc, separators=separators).encode()
            json.loads(redact_blob(raw))
            lines = raw + b"\n" + raw + b"\n"
            for line in redact_blob(lines).splitlines():
                json.loads(line)


@pytest.mark.parametrize(("text", "secret"), _NEEDLES)
def test_secrets_are_gone_from_json_in_every_position(text, secret):
    from opentine.redaction import redact_blob

    for doc in _documents(text):
        raw = json.dumps(doc).encode()
        out = redact_blob(raw)
        json.loads(out)
        assert secret.encode() not in out, (doc, out)


def test_a_clean_json_blob_is_returned_byte_identical():
    from opentine.redaction import redact_blob

    for raw in (
        b'{"b": 1, "a": "clean text", "n": [1.0, 2e5, true, null]}',
        b'{"z":1,"a":{"x":"\\u00e9 caf\\u00e9"}}\n',
        b'[\n  "one",\n  "two"\n]',
        b'{"x": 1}\n{"y": 2}\n',
    ):
        assert redact_blob(raw) is raw or redact_blob(raw) == raw


def test_redacted_json_keeps_its_layout_and_never_drops_members():
    from opentine.redaction import redact_blob

    pretty = json.dumps({"a": "api_key=abcdef123456", "b": 1}, indent=2).encode()
    out = redact_blob(pretty)
    assert out == json.dumps({"a": "api_key=[REDACTED]", "b": 1}, indent=2).encode()
    # Two keys that redact to the same text both survive.
    raw = json.dumps({"api_key=aaaaaaaa1": 1, "api_key=bbbbbbbb2": 2}).encode()
    decoded = json.loads(redact_blob(raw))
    assert sorted(decoded.values()) == [1, 2]
    assert not any("aaaaaaaa1" in key or "bbbbbbbb2" in key for key in decoded)


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("mysql -u root -p'hunter2'", "hunter2"),
        ('mysql -u root -p"hunter2"', "hunter2"),
        ("redis-cli -h h -a 'hunter2'", "hunter2"),
        ('redis-cli -a "hunter2" ping', "hunter2"),
        ("docker login -u me -p 'hunter2' reg", "hunter2"),
        ("docker login -u me --password 'hunter2'", "hunter2"),
        ("curl -u 'admin:hunter2' https://x", "hunter2"),
        ('curl -u "admin:hunter2" https://x', "hunter2"),
    ],
)
def test_quoted_cli_passwords_are_redacted_with_quotes_kept(text, secret):
    from opentine.redaction import redact_text

    out = redact_text(text)
    assert secret not in out
    assert out.count('"') == text.count('"') and out.count("'") == text.count("'")


def test_mysql_capital_p_is_a_port_not_a_password():
    from opentine.redaction import redact_text

    assert redact_text("mysql -h db -P3307 -u root") == "mysql -h db -P3307 -u root"
    assert "Secret1" not in redact_text("mysql -h db -P3307 -u root -pSecret1")


# --- round 6: the byte scan stays authoritative; JSON is repaired, not re-encoded ---

_CREDENTIAL_NAMES = (
    "password",
    "passwd",
    "api_key",
    "apikey",
    "Authorization",
    "Proxy-Authorization",
    "Cookie",
    "Set-Cookie",
    "X-Api-Key",
    "client_secret",
    "github_token",
    "access_token",
    "secret",
    "private_key",
    "dsn",
    "token",
    "auth",
)


def _cross_string_docs(name, value):
    yield {"headers": [{"name": name, "value": value}]}
    yield {"headers": [{"value": value, "name": name}]}
    yield {"pairs": [[name, value]]}
    yield {name: value}


@pytest.mark.parametrize("name", _CREDENTIAL_NAMES)
def test_cross_string_credentials_are_redacted_as_the_byte_scan_does(name):
    from opentine.redaction import _scan, redact_blob

    secret = "FAKEcrossString9876"
    for doc in _cross_string_docs(name, secret):
        for indent in (None, 2):
            raw = json.dumps(doc, indent=indent).encode()
            out = redact_blob(raw)
            json.loads(out)
            if secret.encode() not in _scan(raw):
                assert secret.encode() not in out, (doc, out)
            lines = raw.replace(b"\n", b"") + b"\n" + raw.replace(b"\n", b"") + b"\n"
            if secret.encode() not in _scan(lines):
                assert secret.encode() not in redact_blob(lines)


@pytest.mark.parametrize(("text", "secret"), _NEEDLES)
def test_nothing_the_byte_scan_redacts_survives_redact_blob(text, secret):
    from opentine.redaction import _scan, redact_blob

    for doc in _documents(text):
        raw = json.dumps(doc).encode()
        if secret.encode() not in _scan(raw):
            assert secret.encode() not in redact_blob(raw)


def test_a_dirty_json_blob_keeps_numbers_and_escapes_byte_for_byte():
    from opentine.redaction import redact_blob

    raw = (
        b'{"cmd": "sh -c \\"mysql -u root -phunter2\\"", "big": 1e400, '
        b'"f": 0.1000000000000000055511151231257827, "i": 123456789012345678901234567890, '
        b'"s": "\\ud800", "e": "caf\\u00e9"}'
    )
    out = redact_blob(raw)
    json.loads(out)
    assert b"hunter2" not in out
    for kept in (
        b"1e400",
        b"0.1000000000000000055511151231257827",
        b"123456789012345678901234567890",
        b'"\\ud800"',
        b'"caf\\u00e9"',
    ):
        assert kept in out
    out.decode("utf-8")


def test_a_quoted_assignment_in_an_ordinary_string_keeps_the_rest_of_the_string():
    from opentine.redaction import redact_blob

    raw = json.dumps({"x": 'sh -c "export API_KEY=abcdef123"'}).encode()
    out = json.loads(redact_blob(raw))
    assert "abcdef123" not in out["x"] and out["x"].startswith("sh -c")


@pytest.mark.parametrize(
    "raw",
    [
        b"[" * 5000 + b'"api_key=abcdef123456"' + b"]" * 5000,
        b"[" * 2000 + b"]" * 2000,
        json.dumps({"k": "api_key=" + "é" * 600}).encode(),
        b'{"a": "\xff\xfe api_key=abc"}',
        b'{"a": 1, "a": "api_key=abcdef123456"}',
    ],
)
def test_redact_blob_never_raises_and_keeps_json_valid(raw):
    from opentine.redaction import redact_blob

    out = redact_blob(raw)
    try:
        json.loads(raw)
    except (ValueError, RecursionError):
        return
    try:
        json.loads(out)
    except RecursionError:
        pass


# Round 7: when the byte scan breaks a JSON document, the rebuilt document must
# still redact everything the scan removes -- across members, elements and lines,
# in any container size -- stay valid, and cost linear time.
_BREAKER = 'api_key="x" tail'
_SECRET = "Zq9secretVALUE77"


def _breaker_docs(name, value):
    # The >64 KiB containers of round 7 are in test_the_round7_shapes_do_not_leak.
    pad = "a" * 2_000
    yield {"name": name, "value": value, "comment": _BREAKER}
    yield {"value": value, "name": name, "comment": _BREAKER}
    yield [name, value, _BREAKER]
    yield {name: value, "comment": _BREAKER}
    yield {"h": {"name": name, "value": value, "pad": pad}, "other": _BREAKER}
    yield {"h": [name, value, *(["a" * 100] * 20)], "other": _BREAKER}
    yield {"h": {name: value, "pad": pad}, "other": 'password: "q'}


def _jsonl(doc):
    line = json.dumps(doc).encode()
    return line + b"\n" + json.dumps({"comment": _BREAKER}).encode() + b"\n"


@pytest.mark.parametrize("name", _CREDENTIAL_NAMES)
def test_a_broken_scan_never_lets_what_it_removes_survive(name):
    from opentine.redaction import _scan, redact_blob

    for doc in _breaker_docs(name, _SECRET):
        for raw in (json.dumps(doc).encode(), json.dumps(doc, indent=2).encode(), _jsonl(doc)):
            out = redact_blob(raw)
            for line in out.splitlines() if raw.endswith(b"\n") else [out]:
                if line.strip():
                    json.loads(line)
            if _SECRET.encode() not in _scan(raw):
                assert _SECRET.encode() not in out, (name, doc)


def test_the_round7_shapes_do_not_leak():
    from opentine.redaction import redact_blob

    shapes = [
        {"name": "X-Api-Key", "value": _SECRET, "comment": _BREAKER},
        {"value": _SECRET, "name": "Authorization", "comment": _BREAKER},
        ["X-Api-Key", _SECRET, _BREAKER],
        ["Cookie", "sid=" + _SECRET, _BREAKER],
        {"h": {"name": "X-Api-Key", "value": _SECRET, "pad": "a" * 70_000}, "other": _BREAKER},
        {"h": ["Cookie", "sid=" + _SECRET, *(["a" * 100] * 700)], "other": _BREAKER},
    ]
    for doc in shapes:
        out = redact_blob(json.dumps(doc).encode())
        json.loads(out)
        assert _SECRET.encode() not in out, doc
    line = json.dumps({"name": "X-Api-Key", "value": _SECRET, "comment": 'password: "q'}).encode()
    out = redact_blob(line + b"\n" + line + b"\n")
    assert _SECRET.encode() not in out
    for part in out.splitlines():
        json.loads(part)


@pytest.mark.parametrize(("text", "secret"), _NEEDLES)
def test_secrets_are_gone_with_a_breaker_in_the_document(text, secret):
    from opentine.redaction import redact_blob

    for doc in _documents(text):
        for wrapped in ({"x": doc, "b": _BREAKER}, [doc, _BREAKER]):
            out = redact_blob(json.dumps(wrapped).encode())
            json.loads(out)
            assert secret.encode() not in out, (wrapped, out)


def test_a_broken_scan_keeps_other_tokens_byte_for_byte():
    from opentine.redaction import redact_blob

    raw = (
        b'{"comment": "api_key=\\"x\\" tail", "big": 1e400, "s": "\\ud800", '
        b'"e": "caf\\u00e9", "n": [1, 2.50, -0e3]}'
    )
    out = redact_blob(raw)
    json.loads(out)
    for kept in (b"1e400", b'"\\ud800"', b'"caf\\u00e9"', b"[1, 2.50, -0e3]"):
        assert kept in out


def _timed(build):
    import time

    from opentine.redaction import _scan, redact_blob

    def best(fn, raw):
        result = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            fn(raw)
            result = min(result, time.perf_counter() - start)
        return result

    # 1x and 4x input, best of three each: linear grows ~4x, quadratic ~16x.
    return [(best(redact_blob, build(size)), best(_scan, build(size))) for size in (1, 4)]


@pytest.mark.parametrize(
    "build",
    [
        lambda k: b'{"a": "' + b"\\\\" * (20_000 * k) + b"api_key=x",  # truncated
        lambda k: b'["' + b'\\"' * (20_000 * k),  # unterminated string
        lambda k: b'{"a": "x\x01' + b"y" * (40_000 * k) + b'"}',  # raw control char
        lambda k: b"[" * (20_000 * k) + b'"api_key=\\"x\\" t"' + b"]" * (20_000 * k),
        lambda k: json.dumps([{"comment": _BREAKER, "v": "x" * 40}] * (1_000 * k)).encode(),
        lambda k: json.dumps([["Cookie", "sid=abc", _BREAKER]] * (1_000 * k)).encode(),
    ],
)
def test_json_redaction_is_linear(build):
    # Linear in the input, and within a small multiple of the byte scan itself (the
    # rebuild runs every step once more over the document, plus one check round).
    (small, _), (large, scan) = _timed(build)
    assert large < max(small, 0.02) * 8
    assert large < 6 * scan + 0.1


def test_duplicate_member_names_stay_parseable_and_redacted():
    from opentine.redaction import redact_blob

    raw = b'{"a": "api_key=\\"x\\" t", "a": "api_key=' + _SECRET.encode() + b'", "a": 1}'
    out = redact_blob(raw)
    json.loads(out)
    assert _SECRET.encode() not in out


# --- round 8: PEM order, rescans checked against the scan, linear renames, UTF-8
# boundaries, BOM / NaN / scalar-first JSON Lines.

_R8_BODY = "MIIEpAIBAAKCAQEAFAKEKEYBODYzz9QmFrZUtleUJvZHlMaW5lVHdvFAKE"
_R8_ARMORS = ("RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY")
_R8_PREFIXES = (
    "MYSQL_PWD=x",
    "DB_PWD=x",
    "LDAP_BIND_PW=x",
    "REDISCLI_AUTH=x",
    "--db-pwd=x",
    "app.db.pwd: x",
    "mysql -u root -px",
    "redis-cli -a x",
    "docker login -u me -p x",
    "curl -u me:x",
    "https://h/x?token=abc",
    "--password hunter",
    "x",
)


def _r8_pem(armor: str) -> str:
    if armor == "PGP PRIVATE KEY BLOCK":
        return f"-----BEGIN {armor}-----\n\n{_R8_BODY}\n-----END {armor}-----\n"
    return f"-----BEGIN {armor}-----\n{_R8_BODY}\n-----END {armor}-----\n"


@pytest.mark.parametrize("armor", (*_R8_ARMORS, "PGP PRIVATE KEY BLOCK"))
@pytest.mark.parametrize("prefix", _R8_PREFIXES)
def test_a_value_pattern_never_eats_the_begin_marker_of_the_key_below_it(prefix, armor):
    from opentine.redaction import redact_blob

    text = prefix + "\n" + _r8_pem(armor)
    document = json.dumps({"stdout": text}).encode()
    lines = document + b"\n" + document + b"\n"
    for raw in (text.encode(), document, lines):
        out = redact_blob(raw)
        assert b"FAKEKEYBODY" not in out, (prefix, armor, raw[:40])
    json.loads(redact_blob(document))


def test_a_key_after_a_form_value_does_not_reach_disk(tmp_path):
    secret = "MYSQL_PWD=hunter2xx\n" + _r8_pem("RSA PRIVATE KEY")
    run = Run(id="r8")
    run.add_step(StepKind.tool, {"cmd": "x"}, outputs={"output": json.dumps({"stdout": secret})})
    run.status = RunStatus.completed
    path = tmp_path / "r8.tine"
    run.save(path)
    repo = Repo.init(tmp_path / "repo")
    repo.put_run(run)
    for file in [path, *(tmp_path / "repo").rglob("*")]:
        if file.is_file():
            assert b"FAKEKEYBODY" not in file.read_bytes(), file


@pytest.mark.parametrize(
    "raw",
    [
        json.dumps(
            {"msg": 'sent {"name": "Authorization", "value": "PASSWORD=\'Hunter2Secret99"} ok'}
        ).encode(),
        b'"\\"name\\":\\"apikey\\",\\"value\\":\\"PASSWORD=\'Hunter2Secret99"',
    ],
)
def test_a_rebuilt_string_never_keeps_what_the_byte_scan_removed(raw):
    from opentine.redaction import redact_blob

    out = redact_blob(raw)
    json.loads(out)
    assert b"Hunter2Secret99" not in out


def test_many_member_names_that_redact_alike_are_renamed_in_linear_time():
    from opentine.redaction import redact_blob

    def build(k):
        return b"{" + b",".join(b'"password: %06d":1' % i for i in range(1500 * k)) + b"}"

    (small, _), (large, _) = _timed(build)
    assert large < max(small, 0.02) * 8
    out = json.loads(redact_blob(build(1)))
    assert len(out) == 1500


@pytest.mark.parametrize(
    "text",
    [
        "MYSQL_PWD=" + "a" * 511 + "é tail",
        "x cookie: " + "a" * 4095 + "é",
        "--password " + "a" * 511 + "é tail",
        "--db-pwd=" + "a" * 511 + "\U0001f600 tail",
    ],
)
def test_a_bounded_value_never_splits_a_character(text):
    from opentine.redaction import redact_blob, redact_value

    for shift in range(4):
        value = "é" * shift + text
        assert "a" * 100 not in redact_text(value)
        redact_value({"cmd": value})
        document = json.dumps({"cmd": value}, ensure_ascii=False).encode()
        assert "a" * 100 not in json.loads(redact_blob(document))["cmd"]


def test_a_bounded_value_never_splits_a_character_end_to_end(tmp_path):
    run = Run(id="r8u")
    run.add_step(StepKind.tool, {"command": "--password " + "a" * 511 + "é tail"}, outputs={})
    run.status = RunStatus.completed
    run.save(tmp_path / "u.tine")
    Repo.init(tmp_path / "repo").put_run(run)


_R8_DOC = json.dumps({"note": 'api_key="x" tail', "b": "keep", "c": 'password: x" y'})


@pytest.mark.parametrize(
    "raw",
    [
        ("0\n" + _R8_DOC + "\n").encode(),
        ("null\n" + _R8_DOC + "\n").encode(),
        ("true\n" + _R8_DOC).encode(),
        b"\xef\xbb\xbf" + _R8_DOC.encode(),
        _R8_DOC.replace('"keep"', "NaN").encode(),
        _R8_DOC.replace('"keep"', "-Infinity").encode(),
    ],
)
def test_bom_nan_and_scalar_first_json_lines_stay_valid(raw):
    from opentine.redaction import redact_blob

    out = redact_blob(raw)
    assert out.startswith(b"\xef\xbb\xbf") == raw.startswith(b"\xef\xbb\xbf")
    body = out[3:] if out.startswith(b"\xef\xbb\xbf") else out
    for line in body.splitlines():
        if line.strip():
            json.loads(line)
    assert b'x\\" tail' not in out and b'x\\" y' not in out


# --- final pass: linear survivor checks and span sweep, no BOM recursion.


def _best(build, size):
    import time

    from opentine.redaction import redact_blob

    raw = build(size)
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        redact_blob(raw)
        best = min(best, time.perf_counter() - start)
    return best


def _access_log(n):
    lines = (
        f"2026-10-15T10:00:{i % 60:02d} INFO GET /v1/items?page={i} HTTP/1.1 200 "
        f"Authorization: Bearer tok{i:010d} ua=curl/8.4"
        for i in range(n)
    )
    return json.dumps({"stdout": "\n".join(lines), "exit_code": 0}).encode()


@pytest.mark.parametrize(
    "build",
    [
        lambda k: _access_log(300 * k),  # a header per line in one escaped string
        lambda k: json.dumps({"s": "\n".join(f"sk-{i:020d}" for i in range(600 * k))}).encode(),
        lambda k: b"{" + b",".join(b'"password: %06d":1' % i for i in range(600 * k)) + b"}",
        lambda k: json.dumps(
            {"brk": 'api_key="x" tail', "l": [f"sk-{i:020d}" for i in range(600 * k)]}
        ).encode(),
        lambda k: ("﻿" * (3000 * k) + "hello").encode(),
        lambda k: json.dumps({"a": "﻿" * (3000 * k)}).encode(),
        lambda k: b"\xef\xbb\xbf" * (3000 * k) + b"{}",
    ],
)
def test_redaction_grows_linearly_with_many_removals(build):
    small, large = _best(build, 1), _best(build, 4)
    assert large < max(small, 0.02) * 8, (small, large)


def test_many_removed_words_are_found_wherever_they_survive():
    from opentine._redact_survive import any_left

    words = {b"tok%010d" % i for i in range(5000)}
    after = b" ".join(b"x" * 20 for _ in range(5000))
    assert not any_left(words, after)
    assert any_left(words, after + b" prefixtok0000004321suffix")
    assert not any_left({b"PRIVATE"}, b"[REDACTED PRIVATE KEY]")
    assert any_left({b"Hunter2"}, b"[REDACTED] Hunter2")


def test_a_run_of_byte_order_marks_never_recurses(tmp_path):
    from opentine.redaction import redact_blob

    assert redact_text("﻿" * 5000 + "hello").endswith("hello")
    assert redact_blob(b"\xef\xbb\xbf" * 1000 + b"{}").endswith(b"{}")
    out = redact_blob(json.dumps({"a": "﻿" * 1200 + "api_key=" + _SECRET}).encode())
    assert _SECRET.encode() not in out
    json.loads(out)
    run = Run(id="bom")
    run.add_step(StepKind.tool, {"cmd": "x"}, outputs={"output": "﻿" * 5000 + "hello"})
    run.status = RunStatus.completed
    run.save(tmp_path / "bom.tine")
    Repo.init(tmp_path / "repo").put_run(run)


# Final pass 2 #1: the rebuild path dropped every span with no letter or digit, so
# an all-symbol password beside a breaker string was copied to disk verbatim.
_SYMBOLS = "!@#$%^&*()_+"


@pytest.mark.parametrize(
    "doc",
    [
        {"db_user": "app", "db_password": _SYMBOLS, "log": _BREAKER},
        {"user": "deploy", "password": _SYMBOLS, "note": _BREAKER},
        {"user": "deploy", "password": "[REDA!!!!", "note": _BREAKER},
        {"cmd": f"mysql -u root -p'{_SYMBOLS}' db", "note": _BREAKER},
        {"netrc": f"machine h login u password {_SYMBOLS}", "note": _BREAKER},
        {"hdr": "Authorization: Basic !!!!@@@@####", "note": _BREAKER},
        {"env": f"DB_PASSWORD={_SYMBOLS}", "note": _BREAKER},
    ],
)
def test_a_symbol_only_secret_beside_a_breaker_is_redacted(tmp_path, doc):
    secret = next(
        v.split("-p'")[-1].split("'")[0] if "-p'" in v else v.split()[-1].split("=")[-1]
        for k, v in doc.items()
        if k not in {"db_user", "user", "log", "note"}
    )
    out = redact_text(json.dumps(doc))
    json.loads(out)
    assert secret not in out
    run = Run(id="sym")
    run.add_step(StepKind.tool, {"cmd": "x"}, outputs={"output": json.dumps(doc)})
    run.status = RunStatus.completed
    path = tmp_path / "sym.tine"
    run.save(path)
    repo = Repo.init(tmp_path / "repo")
    repo.put_run(run)
    assert secret.encode() not in path.read_bytes()
    for blob in (tmp_path / "repo").rglob("*"):
        if blob.is_file():
            assert secret.encode() not in blob.read_bytes()


def test_a_structural_only_removal_does_not_redact_a_string():
    import re

    from opentine._redact_edits import changed, sub_step

    swallow = sub_step(re.compile(rb'x\\"'), b"x")
    assert changed(b'x\\" y', [swallow]) == []
    label = sub_step(re.compile(rb"password=\]"), b"password=[REDACTED]")
    assert changed(b"password=]", [label]) == [(0, 10)]
