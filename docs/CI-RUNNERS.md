# CI runners

OpenTine CI runs on GitHub-hosted runners by default. From 0.54 the Linux jobs of
`ci.yml` can also run on the owner's own ephemeral runners ("home runners"). They
are **off** until the owner turns them on, and pull requests never use them.

This page covers how CI is laid out, how runner selection works, and how to set
up the home runners.

## How CI is laid out (0.54)

| Job | What it does | Runs on |
|---|---|---|
| `prep` (Lint, build and inventory) | ruff check, ruff format, `check_architecture.py`, `check_copy.py`, build, release inventory, twine, wheel smoke | once per run |
| `package-os` | build and release inventory on Windows and macOS (CRLF checkouts) | once per OS |
| `plan` | `scripts/ci_plan.py`: chooses the test matrix and whether it runs | once per run |
| `test` | pytest only: a parallel pass (`-n auto --dist loadgroup`) and a serial pass (`-m serial -p no:xdist`) | the matrix |
| `Python tests` | one stable result for branch protection | once per run |

Test matrix:

- **push to main, schedule, workflow_dispatch**: Ubuntu, macOS and Windows x
  Python 3.11, 3.12, 3.13 and 3.14 (12 cells). Nothing is filtered by path.
- **pull request**: Ubuntu 3.11 and 3.14, Windows 3.12, macOS 3.13.
- **pull request that changes only `ts/`, `ide/` and prose**: one Ubuntu 3.14 cell,
  because many Python tests read files under `ts/` and `ide/`.
- **pull request that changes only Markdown under `docs/` or at the root**: the
  matrix is skipped. `prep` still runs the copy lint.

Every Windows cell is split into 4 shards by `pytest-split`, using the committed
`tests/test_durations.json`. Refresh it when the suite's shape changes:

```bash
uv run pytest tests -m "not live and not live_harness" -p no:xdist \
  --store-durations --durations-path tests/test_durations.json
uv run python scripts/scrub_durations.py
```

The scrub step drops test ids shaped like credentials (the redaction tests use
fake tokens as parameters), so the committed file never trips secret scanning.

A test that cannot run beside others (it changes the working directory, a
process-wide setting, or a fixed port) is marked `@pytest.mark.serial`. Prefer
fixing the test (`tmp_path`, `monkeypatch`, port 0) over adding the marker.

**Branch protection:** require the `Python tests` check and the gate jobs
(`Python / TS / pyz vector parity`, `0.34 peer compatibility`, `Audit kit offline
(...)`, `Leave the hosted service (...)`, `TS verifier (Node 20)`). Do not require
the individual `Test (...)` cells: their names change with the matrix, and a
skipped matrix reports one skipped entry.

## Runner selection

Linux jobs that may use home runners (`prep`, the Ubuntu `test` cells,
`fuzz-otlp`, `peer-compat-034`) pick their label with this expression:

```yaml
runs-on: ${{ (vars.USE_HOME_RUNNERS == 'true' && ((github.event_name == 'push' && github.ref == 'refs/heads/main') || github.event_name == 'workflow_dispatch')) && 'opentine-home' || 'ubuntu-latest' }}
```

- The home label `opentine-home` is used only when the repository variable
  `USE_HOME_RUNNERS` is exactly the string `true` **and** the run is a push to
  `main` or a `workflow_dispatch`.
- Every other case resolves to the hosted label. A `pull_request` run, from a
  branch of this repository or from a fork, always runs hosted.
- To turn home runners off, delete the variable or set it to anything else. The
  next run is fully hosted. This is also the fallback if the home box is down:
  queued jobs wait for a runner, so cancel the run, clear the variable and re-run.

These jobs always stay hosted:

- `bench.yml`: the criterion-6 bench gate compares against a baseline measured on
  hosted `ubuntu-24.04`; moving it would need a new baseline.
- `publish.yml`, `codeql.yml`, `scorecard.yml`, `supply-chain.yml`: they use OIDC,
  attestations or security scanning and must not run on the home box.
- `audit-kit` (needs `sudo unshare --net`), `fips` (a privileged container),
  `parity`, `ts-verifier`, `browser-verifier`, and the macOS and Windows cells.

`tests/test_054_ci_runner_policy.py` evaluates every `runs-on` in
`.github/workflows` for every pull-request event, both switch settings and every
matrix OS, and fails if any can resolve to a non-hosted label. It also checks that
the switch is off by default.

## Setting up the home runners

The design is ephemeral, just-in-time runners: every job gets a fresh pod that is
destroyed afterwards, so no state is shared between jobs.

### 1. Host and network

- A dedicated host or VM (Ubuntu 24.04), for example 16+ cores, 64-128 GB RAM and a
  dedicated NVMe disk for runner work directories and caches. That gives 4-6
  concurrent runners at 4 vCPU / 8 GB each.
- Put it on its own VLAN. It may reach only the internet (GitHub, PyPI, npm, the
  Playwright CDN, the sigstore TUF CDN) and the cache proxy. It has **no route** to
  the home LAN, NAS or router admin interface: deny RFC 1918 ranges on the router
  except the cache proxy.
- No inbound ports. Runners only make outbound long-poll connections to GitHub.
- Unattended security upgrades on, and a UPS if available.

### 2. k3s and actions-runner-controller (ARC)

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable traefik" sh -
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
# install helm 3 from its release page, then:
helm install arc --namespace arc-systems --create-namespace \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller \
  --version <pinned version>
```

### 3. GitHub App (the only credential on the box)

1. Settings > Developer settings > GitHub Apps > New GitHub App.
2. Repository permissions: Administration read/write (needed for repository-level
   runners), Metadata read. Nothing else.
3. Install it on this repository only. Note the App ID and installation ID and
   download the private key.
4. Store the key as a Kubernetes secret and delete the downloaded file:

```bash
kubectl create namespace arc-runners
kubectl -n arc-runners create secret generic gh-app \
  --from-literal=github_app_id=<APP_ID> \
  --from-literal=github_app_installation_id=<INSTALLATION_ID> \
  --from-file=github_app_private_key=<key.pem>
```

Rotate the key every quarter. Do not use a personal access token.

### 4. Runner scale set

```bash
helm install opentine-home --namespace arc-runners \
  --set githubConfigUrl=https://github.com/<owner>/opentine \
  --set githubConfigSecret=gh-app \
  --set minRunners=0 --set maxRunners=6 \
  --set runnerGroup=opentine-home \
  -f values.yaml \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --version <pinned version>
```

The scale-set name, `opentine-home`, is the `runs-on` label. In `values.yaml`:

- `template.spec.containers[0].image`: the runner image (step 5);
- resources `cpu: 4`, `memory: 8Gi`;
- `securityContext`: `runAsNonRoot: true`, `runAsUser: 1001`,
  `allowPrivilegeEscalation: false`;
- no Docker socket mount and no docker-in-docker.

### 5. Runner image

Build `ghcr.io/<owner>/opentine-runner:<date>` from the ARC runner base image with
uv 0.11.12, Python 3.11-3.14, Node 20 and the Playwright browsers. Build it in a
hosted workflow, pin it by digest in `values.yaml`, and rebuild it monthly. A
pre-built image saves 1-3 minutes per job.

### 6. Caches

Jobs are ephemeral, so use read-through caching proxies on the runner VLAN rather
than a shared writable cache volume, which a job could poison:

- PyPI: `devpi` or `proxpi`; npm: `verdaccio`; apt: `apt-cacher-ng`.
- Point the runners at them through the runner pod environment
  (`UV_INDEX_URL`, `npm_config_registry`).
- If a uv cache volume is shared at all, mount it read-only into job pods and fill
  it only from a trusted main-branch job.
- `actions/cache` keeps working from self-hosted runners.

### 7. Network policy

Apply a default-deny egress `NetworkPolicy` in `arc-runners` that blocks
`10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16`, allowing only DNS and the cache
proxy address. Keep the router rules from step 1 as the outer layer.

### 8. Repository settings

1. Settings > Actions > General > "Fork pull request workflows from outside
   collaborators": **Require approval for all outside collaborators**.
2. Settings > Actions > Runners > Runner groups: the `opentine-home` group is
   limited to this repository and to the selected workflow `ci.yml` on `main`.
3. Workflows keep `permissions: contents: read` and pass no secrets to jobs that
   can run on the home box.
4. Settings > Secrets and variables > Actions > Variables: add `USE_HOME_RUNNERS`
   with the value `true` only after the checks below pass.

### 9. Before turning it on

1. `uv run pytest tests/test_054_ci_runner_policy.py` passes.
2. Open a pull request from a throwaway fork and confirm every job ran on a hosted
   runner (the job log's "Runner name" and "Machine name").
3. Run `ci.yml` by `workflow_dispatch` on `main` with the variable set and confirm
   the Linux jobs ran on `opentine-home` and passed.

### Windows (optional)

Only if the hosted Windows shards are still the slowest part of CI: a Windows
Server 2022 VM template (Git, uv, Node, Build Tools, Defender exclusion on the
work drive), cloned per job and destroyed after it, running the runner with a
just-in-time configuration (`generate-jitconfig`) and its own label. The same
selection rule applies: never for pull requests, only with the switch on.
