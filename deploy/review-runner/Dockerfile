# OpenTine review runner (0.55): `tine review runner` on every push, hosted or self-hosted.
#
# Build (from the repository root, so the image runs exactly this tree):
#   docker build -f deploy/review-runner/Dockerfile -t opentine-review-runner .
# Dockerfile.dockerignore (BuildKit) limits the context to the package sources.
# Run: see docs/REVIEW-RUNNERS.md. The same image serves both modes; only
# RUNNER_MODE differs, and the findings it signs do not depend on it.
#
# No secret is baked in. The runner's own key is mounted read-only at
# /run/secrets/review-runner.key; model credentials arrive as the environment
# variables .tine/runner.toml names. This repository does not publish the
# image; build it yourself.
FROM docker.io/library/python:3.15.1-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10002 --home-dir /var/lib/runner --create-home runner

COPY . /src
RUN python -m pip install --no-cache-dir /src && rm -rf /src

COPY deploy/review-runner/entrypoint.sh /usr/local/bin/review-runner
RUN chmod 0555 /usr/local/bin/review-runner

USER 10002:10002
ENV XDG_CONFIG_HOME=/var/lib/runner/config \
    RUNNER_MODE=self-hosted \
    RUNNER_REPO=/work \
    RUNNER_OUT=/out
VOLUME ["/work", "/out"]

ENTRYPOINT ["/usr/local/bin/review-runner"]
