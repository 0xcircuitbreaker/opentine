# Security review: OTLP/gRPC ingest (0.48)

**Scope.** `tine serve --otlp --otlp-protocol grpc|both`: the OTLP/gRPC
receiver in `opentine/_otlp_grpc.py` and `opentine/_otlp_serve.py`, the
protobuf decoders it shares with OTLP/HTTP (`opentine/trace/_protobuf_wire.py`,
`_otlp_proto.py`, `_otlp_logs_proto.py`) and the collector it feeds
(`opentine/_otlp_collect.py`). Written before the receiver shipped, as the
0.48 roadmap requires; the tests named below hold each control.

**Reviewer.** The OpenTine maintainers (internal review). No external
penetration test has been done. **Fuzzing status:** the harness and a scaled
CI run ship with 0.48 (below); the 72-hour acceptance run has **not** been run
yet and must be before 0.48 is tagged.

## Threat model

The receiver is an ingest endpoint for telemetry an agent process sends about
itself. An attacker is anyone who can open a TCP connection to the port: on
loopback, any local process (and, via DNS rebinding, a browser page -- gRPC
needs HTTP/2 with trailers, which a page cannot send, see "Browsers" below);
off loopback, the network. Assets: the availability of the receiving process,
the integrity of the run repository it writes to, and the secrecy of values
in other agents' telemetry (redaction runs before a run is saved, as for
OTLP/HTTP).

## Transport and dependencies

* gRPC comes from `grpcio` (the `opentine[grpc]` extra, `>=1.66`), the
  reference C-core implementation. No generated stubs and no `protobuf`
  runtime: the two unary `Export` methods take raw bytes and the stdlib
  decoders parse them. That keeps the attack surface on the message body to
  code this repository owns and fuzzes.
* `>=1.66` is newer than the grpc releases that fixed the HTTP/2 "rapid
  reset" stream-cancellation flood (CVE-2023-44487) and the 2023 HPACK
  accounting issues (CVE-2023-33953), all fixed in 2023 patch releases of
  the 1.5x lines. Dependabot tracks the lock file; the version in `uv.lock`
  was 1.85.1 when this was written.

## Message size limits

* `grpc.max_receive_message_length` is `--max-body-mb` (default 16 MiB), the
  same bound as an OTLP/HTTP body. A larger message is refused by grpc core
  with `RESOURCE_EXHAUSTED` before the handler runs
  (`tests/test_048_otlp_grpc.py::test_grpc_refuses_malformed_and_oversized_messages`).
* `grpc.max_send_message_length` is 64 KiB: replies are an empty or
  `partial_success` message.
* `grpc.max_metadata_size` is 16 KiB, so headers cannot carry the payload.
* After decoding, the HTTP path's item caps apply unchanged: at most
  100,000 spans plus log records per request and 1,000 attributes per item
  (413 on HTTP, `RESOURCE_EXHAUSTED` on gRPC), and the wire reader's caps:
  64 MiB per message, 2,000,000 fields per decode, nesting depth 32 (a
  `WireError`, `INVALID_ARGUMENT`).

## Decompression bombs

gRPC message compression (`grpc-encoding: gzip`/`deflate`) is decoded by grpc
core, which applies `max_receive_message_length` to the **decompressed**
message and stops inflating when it is exceeded. A 1 MiB message that gzips
to under 8 KiB is refused with `RESOURCE_EXHAUSTED` against a 64 KiB limit
(`test_grpc_bounds_the_decompressed_size`). The receiver never inflates
anything itself on this path. (OTLP/HTTP gzip bodies are inflated by
`opentine._otlp_http.inflate` under the same bound, unchanged since 0.21.)

## Resource exhaustion

* A fixed pool of 8 handler threads; `maximum_concurrent_rpcs=64`, so the
  65th concurrent call is refused with `RESOURCE_EXHAUSTED` instead of
  queueing without bound.
* `grpc.max_concurrent_streams=16` per HTTP/2 connection; idle connections are
  closed after 5 minutes (`grpc.max_connection_idle_ms`); keepalive pings
  without data are limited (`grpc.http2.max_pings_without_data=2`,
  `min_ping_interval_without_data_ms=10000`,
  `keepalive_permit_without_calls=0`).
* Pending spans and log records are held by the collector until their trace
  ends or goes idle; the collector's overflow flush (shared with OTLP/HTTP)
  bounds what one group may hold.
* **Open:** grpcio's Python server has no cap on the number of TCP
  connections. Off loopback, put the receiver behind a proxy or firewall that
  limits connections per peer, or bind it to loopback and forward to it.

## Authentication

* `--otlp-token-file FILE`: every call must carry
  `authorization: Bearer <token>`; the comparison is `hmac.compare_digest`
  over the whole header value. The token is 16..4096 printable ASCII bytes
  without spaces, read once at start. A missing or wrong token is
  `UNAUTHENTICATED`, and the body is never decoded
  (`test_grpc_requires_the_bearer_token`).
* Without a token file the receiver is unauthenticated, which is allowed only
  on loopback.
* The token is a shared secret, not an identity: every holder can write runs.
  Runs saved from OTLP are imports (assurance tier T0, SPEC Part 8): nothing
  a sender says raises the tier.

## TLS

* `--cert PEM --key PEM` serve gRPC over TLS (`grpc.ssl_server_credentials`,
  server authentication only; grpc core negotiates TLS 1.2+ with its own
  cipher list). Both or neither must be given.
* **Off loopback, TLS and a token are both required, with no override**
  (`--insecure-dev-any-host` does not apply to gRPC):
  `test_serve_refuses_grpc_off_loopback_without_tls_and_token`. A bearer
  token over plaintext off loopback would be readable on the path.
* Client certificates (mTLS) are not offered in 0.48.

## Malformed input

The decoders treat every input as hostile: a truncated varint, a length past
the end, group wire types, field number 0, a wrong wire type for a known
field, invalid UTF-8 in a string field and over-deep nesting are all a
`ValueError` (`INVALID_ARGUMENT`), never another exception. Unknown fields are
skipped as protobuf requires. A handler that raises anything else would be a
gRPC `UNKNOWN` error; the fuzzer below treats that as a crash.

## Browsers

On loopback, the HTTP receiver refuses an `Origin` header and a non-loopback
`Host` (DNS rebinding). gRPC needs HTTP/2 with trailers and the `te: trailers`
header, which `fetch` cannot produce, and the receiver does not speak
gRPC-Web, so a page cannot reach the gRPC methods.

## Fuzzing

* Harness: `opentine/_otlp_fuzz.py`, a stdlib mutation fuzzer (bit flips,
  insertions, deletions, boundary varints, splices, re-wrapped lengths and
  deep nesting) over valid traces and logs export requests. The target is
  exactly the gRPC handler's work: `decode_protobuf` (decoder plus item caps)
  and the GenAI span or log importer. The oracle: an import, or a
  `ValueError`/`RecursionError`/413 refusal; anything else, or one input
  taking more than 5 s, is a crash.
* `scripts/fuzz_otlp.py --iterations N --seed S` (CI: the `fuzz-otlp` job,
  1,000,000 inputs per run, seeded by the run id; crash inputs are uploaded as
  an artifact), `--hours 72` for the acceptance run, `--atheris` for
  coverage-guided fuzzing when `atheris` is installed.
* `tests/test_048_otlp_ingest.py::test_the_scaled_fuzz_run_finds_no_crash`
  runs 3,000 inputs on every test run.
* Results so far: 1,000,000 inputs (seed 4801) during development, no crash,
  slowest input about 10 ms. **The 72-hour run is outstanding.**

## Residual risks and follow-ups

1. Run `scripts/fuzz_otlp.py --hours 72` (and, where available, `--atheris
   --hours 72`) and record the result here before tagging 0.48.
2. Connection-count limiting is left to the deployment (see above).
3. No mTLS and no per-sender identity; runs from OTLP stay T0.
4. Memory per request is bounded by the message limit times the decode
   expansion (a dict per field); at the 16 MiB default that is hundreds of
   MiB in the worst case for one in-flight call. Lower `--max-body-mb` on
   small hosts.
