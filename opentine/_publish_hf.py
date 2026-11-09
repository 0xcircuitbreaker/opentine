"""``tine publish hf``: a redacted, signed run bundle as a Hugging Face Hub dataset (0.49).

Only a run's redacted public copy is published (:mod:`opentine._redacted_derive`,
the same bundle as ``tine bundle create --redacted-public``), signed by the
caller's key, and only after the derived objects pass the push gate's scan.
There is no override: a Hub dataset is public by default.

The upload uses the Hub's HTTP API directly: optionally create the dataset
repository, upload the bundle through the Git LFS batch API (the bundle is
binary), then one commit that adds the LFS pointer and a dataset card
(``README.md``) tagged ``agent-traces`` so the Hub lists it with agent trace
datasets. The token (``HF_TOKEN`` or ``--token-env``) goes only to the Hub API
host; an LFS upload URL on another host (object storage) gets only the headers
the Hub's batch answer names for it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any
from urllib.parse import quote

from opentine._publish_common import PublishError, expect, same_host

HUB = "https://huggingface.co"
TOKEN_ENV = "HF_TOKEN"
_LFS = "application/vnd.git-lfs+json"


def dataset_id(value: str) -> str:
    parts = value.split("/")
    if len(parts) != 2 or not all(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", p) and ".." not in p for p in parts
    ):
        raise PublishError("--dataset must be OWNER/NAME")
    return value


def card(dataset: str, entry: dict[str, Any]) -> str:
    """The dataset card: YAML front matter the Hub reads, then how to verify the bundle."""
    name = dataset.split("/")[1]
    return (
        "---\n"
        f"pretty_name: {json.dumps(name)}\n"
        "license: other\n"
        "tags:\n- agent-traces\n- opentine\n- provenance\n"
        "configs: []\n"
        "---\n\n"
        f"# {name}\n\n"
        "Redacted, signed OpenTine agent run bundles. Each file under `runs/` is a\n"
        "public copy of one run with every secret-shaped value redacted, linked to\n"
        "the private run by a signed `opentine.redacted-copy` record.\n\n"
        "| File | Public run | Bundle digest | Signature |\n|---|---|---|---|\n"
        f"| `{entry['path']}` | `{entry['public_run']}` | `{entry['digest']}` "
        f"| {entry['algorithm']} |\n\n"
        "Verify offline: `tine bundle verify FILE --pubkey KEY.pub` (or\n"
        "`python tine-verify.pyz`), then `tine bundle import FILE` to read it.\n"
    )


def plan(entry: dict[str, Any], create: bool) -> list[dict[str, str]]:
    steps = [{"method": "POST", "path": "/api/repos/create"}] if create else []
    return steps + [
        {"method": "POST", "path": "/datasets/{dataset}.git/info/lfs/objects/batch"},
        {"method": "PUT", "path": "{lfs upload href}"},
        {"method": "POST", "path": "/api/datasets/{dataset}/commit/{revision}"},
    ]


def _create(session: Any, base: str, auth: dict, dataset: str, private: bool) -> None:
    org, name = dataset.split("/")
    body = {"type": "dataset", "name": name, "organization": org, "private": private}
    expect(session.post(f"{base}/api/repos/create", json=body, headers=auth), "create", (200, 409))


def _lfs(session: Any, base: str, auth: dict, dataset: str, data: bytes) -> str:
    oid = hashlib.sha256(data).hexdigest()
    batch = {
        "operation": "upload",
        "transfers": ["basic"],
        "hash_algo": "sha256",
        "objects": [{"oid": oid, "size": len(data)}],
    }
    headers = {**auth, "Accept": _LFS, "Content-Type": _LFS}
    url = f"{base}/datasets/{dataset}.git/info/lfs/objects/batch"
    answer = expect(session.post(url, json=batch, headers=headers), "lfs batch")
    objects = answer.get("objects") if isinstance(answer, dict) else None
    if not isinstance(objects, list) or not objects or not isinstance(objects[0], dict):
        raise PublishError("lfs batch failed: the answer names no object")
    if objects[0].get("error"):
        raise PublishError("lfs batch failed: the Hub refused the object")
    actions = objects[0].get("actions") or {}
    upload, verify = actions.get("upload"), actions.get("verify")
    if isinstance(upload, dict):  # absent: the Hub already holds these bytes
        href = upload.get("href")
        if not isinstance(href, str) or not href.startswith("https://"):
            raise PublishError("lfs upload failed: the Hub named no https upload URL")
        given = {str(k): str(v) for k, v in (upload.get("header") or {}).items()}
        expect(session.put(href, content=data, headers=given), "lfs upload", (200, 201))
    if isinstance(verify, dict):
        href = same_host(verify.get("href"), base, "lfs verify")
        given = {str(k): str(v) for k, v in (verify.get("header") or {}).items()}
        body = {"oid": oid, "size": len(data)}
        expect(session.post(href, json=body, headers={**auth, **given}), "lfs verify")
    return oid


def upload(
    session: Any,
    base: str,
    token: str,
    dataset: str,
    *,
    revision: str,
    entry: dict[str, Any],
    data: bytes,
    create: bool,
    private: bool,
) -> dict[str, Any]:
    """Upload the bundle and its card in one commit; returns ``{commit, url}``."""
    auth = {"Authorization": f"Bearer {token}"}
    if create:
        _create(session, base, auth, dataset, private)
    oid = _lfs(session, base, auth, dataset, data)
    readme = card(dataset, entry).encode("utf-8")
    lines = [
        {
            "key": "header",
            "value": {
                "summary": f"Add OpenTine run bundle {entry['path']}",
                "description": f"Bundle {entry['digest']}",
            },
        },
        {
            "key": "lfsFile",
            "value": {"path": entry["path"], "algo": "sha256", "oid": oid, "size": len(data)},
        },
        {
            "key": "file",
            "value": {
                "path": "README.md",
                "content": base64.b64encode(readme).decode("ascii"),
                "encoding": "base64",
            },
        },
    ]
    body = "\n".join(json.dumps(line, sort_keys=True) for line in lines).encode("utf-8")
    url = f"{base}/api/datasets/{dataset}/commit/{quote(revision, safe='')}"
    headers = {**auth, "Content-Type": "application/x-ndjson"}
    done = expect(session.post(url, content=body, headers=headers), "commit")
    done = done if isinstance(done, dict) else {}
    commit, link = done.get("commitOid"), done.get("commitUrl")
    return {
        "commit": commit if isinstance(commit, str) else None,
        "url": link if isinstance(link, str) and link.startswith("https://") else None,
    }


__all__ = ["HUB", "TOKEN_ENV", "card", "dataset_id", "plan", "upload"]
