# Keyless signing for runs (0.74)

`tine sign --keyless` signs a run without a long-lived key. A CI job or runner
proves who it is with an OIDC identity token. A Fulcio-style certificate
authority binds that identity to an ephemeral ECDSA P-256 key for a few
minutes. The key signs the run's in-toto statement, and the signature is
logged to a Rekor-style transparency log. The key is then discarded.

`tine keyless verify` checks the result offline and maps the signer's identity
to an assurance tier. A keyless identity is **never trusted by default**. It is
trusted only when an owner-pinned trust bundle names its issuer and its exact
identity.

## Signing (CI and runner mode)

```console
$ export SIGSTORE_ID_TOKEN=...        # or run in a GitHub Actions job with id-token: write
$ tine sign RUN --keyless [--rekor URL] [--fulcio-url URL] [--output FILE] [--overwrite] [--json]
```

* The token comes from the environment only: `SIGSTORE_ID_TOKEN`, else the
  GitHub Actions ambient token for audience `sigstore`. There is no argv flag,
  so the token never appears in process listings or shell history. The token is
  sent only in the Fulcio request body. It is never printed or written, and it
  is removed from error messages.
* The run must pass its integrity check before it is signed.
* The output is `RUN.sigstore.json` by default, written owner-readable only.
  An existing file is replaced only with `--overwrite`.
* Without `--keyless`, `--rekor`, `--fulcio-url` and `--output` are refused
  (exit 1, naming the flag). With `--keyless`, the key flags (`--key-env`, `--key-file`,
  `--ed25519-key-file`, `--key-id`, `--signer`, `--save`, `--algorithm`) are
  refused.

`--json` prints `{"command": "sign", "schema": "tine-cli-keyless/1", "mode":
"keyless", "run", "bundle", "log_index"}`.

## Where the evidence lives (no new kind)

The output is the existing Sigstore bundle v0.3 that
`tine export --format intoto --keyless` already writes (SPEC 8.12). No new object
kind and no new `tine verify` code is involved:

| Evidence | Bundle field |
|---|---|
| DSSE envelope over the run's in-toto statement | `dsseEnvelope` |
| Leaf certificate, then intermediates (never the root) | `verificationMaterial.x509CertificateChain.certificates` |
| Log entry (canonicalized body, log id, index, integrated time) | `verificationMaterial.tlogEntries[0]` |
| Signed entry timestamp | `tlogEntries[0].inclusionPromise.signedEntryTimestamp` |
| Merkle inclusion proof | `tlogEntries[0].inclusionProof.{logIndex,treeSize,rootHash,hashes}` |
| Signed tree head | `tlogEntries[0].inclusionProof.checkpoint.envelope` (a signed note) |

`tine export --format intoto --keyless` keeps writing the leaf alone
(`verificationMaterial.certificate`); both shapes verify with both commands.

## Verifying offline

```console
$ tine keyless verify RUN.sigstore.json --fulcio-root ROOTS.pem --rekor-key LOG.pem \
      [--run RUN] [--trust-bundle FILE] [--json]
```

Nothing is fetched. The checks run in this order and fail closed:

1. **Receipt.** The log entry must be signed by `--rekor-key` (SET). The
   inclusion proof must recompute, from the logged body, the root hash that the
   signed tree head names, and the tree head must be signed by the same log key.
   The logged body must be this envelope, signed by the leaf's key. This gives
   the *integrated time*. Failure: `fail:keyless-receipt`.
2. **Signature.** The DSSE signature must verify under the leaf certificate's
   key (`fail:keyless-signature`).
3. **Chain.** The leaf must be a code-signing certificate and must chain,
   signature by signature, through the bundled intermediates to a self-signed
   certificate in `--fulcio-root`. A root carried in the bundle is never a
   trust anchor (`fail:keyless-chain`).
4. **Window.** Every certificate on the path must be valid at the log's
   integrated time. If not, the result is `caveat:keyless-outside-window`. The
   signature is real, but it is **not trusted**.
5. **Identity.** Trusted (`keyless.trusted`) only when a pin names the exact
   OIDC issuer **and** an exact SAN identity of the leaf. Otherwise the result
   is `caveat:keyless-unpinned`. A pin is never matched by prefix, and a pin
   that names only one of the two fields names nobody.

With `--run RUN`, the statement's subject must also be that run
(`fail:keyless-subject`). Malformed input is `fail:keyless-malformed`, and a
bundle without a certificate is `fail:keyless-not-keyless`.

The exit status is 0 only for `keyless.trusted`, 1 for any `caveat:` or `fail:`,
and 2 for a usage error. These codes belong to this command only. They are not
`tine verify` codes.

`tine verify RUN --attestation RUN.sigstore.json --rekor-key ... --fulcio-root
... --cert-identity ... --cert-oidc-issuer ...` reads the same bundle with its
existing checks and codes (`attestation`, `receipt`, `certificate`, `sct`).
Since 0.75 a passing `certificate` check names the identity's assurance tier
in its detail. Unless the owner-pinned trust bundle names the exact issuer and
identity, the detail reads `caveat:keyless-unpinned` and neither check
establishes authorship (`authorship` is null): the `--cert-identity` flags are
the caller's expectation, not an owner pin. A missing or rolled-back bundle
pins nothing here, so the result stays a caveat. No new `tine verify` codes.

## Pinning identities (owner trust bundle)

Pins come from the owner-signed trust bundle (SPEC 8.26, `tine trust bundle
create`). This is the same bundle and the same owner pin that grant key roles:

* the owner verifier key comes from `$OPENTINE_TRUST_OWNER`, or else from the
  config file `$XDG_CONFIG_HOME/opentine/trust-owner`. It is outside the
  repository, so a loop that can write the repository cannot pin itself;
* the bundle comes from `--trust-bundle`, `$OPENTINE_TRUST_BUNDLE`, or
  `.tine/trust-bundle.note`;
* the pinned identity is the bundle's `trust_policy.cert_oidc_issuer` together
  with `trust_policy.cert_identity`. These portable fields already exist.

If no owner is pinned, nothing is trusted and the result is
`caveat:keyless-unpinned`. If an owner is pinned but the bundle is missing,
unsigned, expired or older than the last serial seen (rollback), the command
exits 2: it fails closed.

## Assurance tiers

The tier describes the identity. It never grants trust.

| Tier | When |
|---|---|
| `keyless-workflow` | A CI workload identity: a URI SAN, plus the build signer URI (1.3.6.1.4.1.57264.1.9) and the source repository URI (.1.12) |
| `keyless-person` | Only email SANs: a person at an OIDC provider |
| `keyless-unbound` | Anything else |

The verifier also reports the issuer (.1.8, or legacy .1.1), the runner
environment (.1.11), the source repository digest and ref (.1.13, .1.14), the
build signer digest (.1.10) and the trigger (.1.20) when the certificate
carries them.

## Trust roots

Tests use a throwaway Fulcio-like CA and Rekor-like log (`tests/_sigstore_fakes.py`,
`tests/_keyless_fixtures.py`). OpenTine does not bundle the Sigstore
public-good trusted root, because no installed package provides it offline.
To verify against public-good Sigstore:

* run `tine trust root update --root root.json` once, with a TUF `root.json`
  obtained out of band (docs/SECURITY_MODEL.md). `tine verify --attestation`
  then uses the installed `trusted_root.json`; or
* pass the Fulcio root and intermediates as `--fulcio-root` and the Rekor key
  as `--rekor-key` (for example, extracted from
  `sigstore-python`'s bundled `trusted_root.json` if that package is installed).

## Gaps

* `tine keyless verify` takes PEM roots and a log key. It does not yet take a
  `trusted_root.json`, which `tine verify --attestation --trusted-root` does.
* The TS verifier already checks keyless bundles (`ts/verifier/src/keyless.ts`).
  The tier mapping and the pin rule above are Python-only for now.
