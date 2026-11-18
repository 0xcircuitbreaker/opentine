"""The 0.55 code mirror's rows of the v1 route table (``caps.project.mirror``).

Served only when ``tine serve --mirror`` (or a hosted service) turns the
mirror on; until then each is the uniform ``404``. The reads answer over the
frozen ``opentine-project/1`` manifest and the mirror's state, and every one is
labelled with the upstream, the last-sync time and ``computed_by: "host"``.
The refusal rows document what the mirror never does: push, git smart HTTP,
archive downloads and LFS answer ``403`` with a ``mirror.*-refused`` code.
Rows are plain tuples of ``_api_routes.Route`` fields.
"""

from __future__ import annotations

T = "/tenants/{tenant}/project"
_ERR = (("401", "Error"), ("403", "Error"), ("404", "Error"), ("429", "Error"))
_READ = (("400", "Error"), *_ERR)
_REFUSE = (("403", "Error"), ("401", "Error"), ("404", "Error"), ("429", "Error"))
RAW = "application/octet-stream"

MIRROR_ROUTES: tuple[tuple, ...] = (
    ("GET", T + "/mirror", "getMirror", "The mirror's link and last sync (a host statement)",
     "project", "stable", "read_ref", None, (("200", "MirrorStatus"), *_ERR)),
    ("PUT", T + "/mirror", "linkMirror",
     "Link the mirror to a slot of the current manifest and sync it",
     "project", "stable", "update_ref", "MirrorLink",
     (("200", "MirrorStatus"), ("400", "Error"), *_ERR)),
    ("DELETE", T + "/mirror", "unlinkMirror", "Unlink: delete the mirror, its state and caches",
     "project", "stable", "update_ref", None, (("200", "MirrorUnlinked"), *_ERR)),
    ("POST", T + "/mirror/sync", "syncMirror",
     "Webhook-triggered sync (429 inside min_interval_seconds)",
     "project", "stable", "update_ref", None, (("200", "MirrorStatus"), *_ERR)),
    ("GET", T + "/code/refs", "codeRefs", "Mirrored heads and tags",
     "project", "stable", "read_ref", None, (("200", "CodeRefs"), *_READ)),
    ("GET", T + "/code/tree", "codeTree", "A directory of a mirrored commit",
     "project", "stable", "read_ref", None, (("200", "CodeTree"), *_READ)),
    ("GET", T + "/code/blob", "codeBlob", "A file of a mirrored commit, as JSON",
     "project", "stable", "read_ref", None, (("200", "CodeBlob"), *_READ)),
    ("GET", T + "/code/raw", "codeRaw", "A file's bytes, labelled in X-OpenTine-* headers",
     "project", "stable", "read_ref", None, (("200", RAW), *_READ)),
    ("GET", T + "/code/history", "codeHistory", "Commits newest first, paged",
     "project", "stable", "read_ref", None, (("200", "CodeHistory"), *_READ)),
    ("GET", T + "/code/compare", "codeCompare", "Commits in base..head and the files changed",
     "project", "stable", "read_ref", None, (("200", "CodeCompare"), *_READ)),
    ("GET", T + "/code/search", "codeSearch", "Hybrid code search, scoped to the tenant",
     "project", "stable", "read_ref", None, (("200", "CodeSearch"), *_READ)),
    ("GET", T + "/code/info/refs", "refuseGitDiscovery",
     "Refused: the mirror does not speak git smart HTTP",
     "project", "stable", "read_ref", None, _REFUSE),
    ("POST", T + "/code/git-receive-pack", "refusePush", "Refused: the mirror is read-only",
     "project", "stable", "read_ref", None, _REFUSE),
    ("POST", T + "/code/git-upload-pack", "refuseUploadPack",
     "Refused: the mirror does not serve git clones", "project", "stable", "read_ref", None,
     _REFUSE),
    ("GET", T + "/code/archive", "refuseArchive", "Refused: no archive downloads",
     "project", "stable", "read_ref", None, _REFUSE),
    ("POST", T + "/code/info/lfs/objects/batch", "refuseLfs", "Refused: no LFS",
     "project", "stable", "read_ref", None, _REFUSE),
)  # fmt: skip

#: Query parameters of the code reads (``_openapi._QUERY``).
MIRROR_QUERY: dict[str, list[tuple[str, str]]] = {
    **{op: [("ref", "Branch, tag, full ref or commit id; the default branch when absent."),
            ("path", "Path inside the commit; the root when absent.")]
       for op in ("codeTree", "codeBlob", "codeRaw")},
    "codeHistory": [("ref", "Branch, tag, full ref or commit id."), ("path", "Only this path."),
                    ("cursor", "Opaque cursor from next_cursor.")],
    "codeCompare": [("base", "Base ref or commit."), ("head", "Head ref or commit.")],
    "codeSearch": [("q", "Search words."), ("limit", "At most this many hits, 1-50.")],
}  # fmt: skip
