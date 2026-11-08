# OpenTine API v1 conformance suite

Black-box HTTP tests for the v1 API described by
[`docs/api/openapi-v1.yaml`](../../docs/api/openapi-v1.yaml). Any implementation
(`tine serve`, the hosted service) runs the same suite against a base URL.
Every JSON response is validated against the document's component schemas.

With no environment set, the suite starts a reference `tine serve` on loopback
and runs against it (the main test run does this):

    .venv/bin/python -m pytest tests/api_conformance

Against another implementation, give it a base URL, a tenant and four tokens
(`TINE_API_OTHER_TOKEN` is an admin of a *different* tenant):

    TINE_API_BASE_URL=https://tine.example TINE_API_TENANT=acme \
    TINE_API_WRITER_TOKEN=... TINE_API_READER_TOKEN=... \
    TINE_API_ADMIN_TOKEN=... TINE_API_OTHER_TOKEN=... \
    .venv/bin/python -m pytest tests/api_conformance

The suite pushes a few small runs into the tenant and registers, then removes,
one webhook. Checks for a capability the server does not advertise in
`GET /v1/capabilities` are skipped, never failed. The auth-throttle check
(`429` with `Retry-After`) locks the client address out for a while, so against
a remote it runs only with `TINE_API_THROTTLE=1`.
