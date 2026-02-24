# syntax=docker/dockerfile:1

# Stage 1: Builder (install Python deps into a clean prefix)
FROM python:3.11-alpine@sha256:303398d5c9f110790bce60d64f902e51e1a061e33292985c72bf6cd07960bf09 AS builder

RUN set -eux; \
    apk add --no-cache \
      build-base=0.5-r3 \
      libffi-dev=3.5.2-r0 \
      openssl-dev=3.5.5-r0 \
      cargo=1.91.1-r0 \
    && python -m pip install --upgrade pip wheel

WORKDIR /tmp
COPY requirements.lock.txt /tmp/requirements.lock.txt

RUN python -m pip install --no-cache-dir --prefix=/install --require-hashes -r /tmp/requirements.lock.txt

# Stage 2: Runtime (runs as root in ephemeral container)
FROM python:3.11-alpine@sha256:303398d5c9f110790bce60d64f902e51e1a061e33292985c72bf6cd07960bf09 AS runtime

RUN set -eux; \
    apk add --no-cache \
      ca-certificates=20251003-r0 \
      libstdc++=15.2.0-r2 \
      nodejs=24.13.0-r1 \
      npm=11.6.3-r0 \
      git=2.52.0-r0

# Install Codex CLI (pinned). Latest as of 2026-02-08: 0.98.0
RUN npm install -g @openai/codex@0.98.0 \
    && npm cache clean --force

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    NODE_ENV=production

COPY --from=builder /install /usr/local
COPY src /app/src
COPY prompts /app/prompts
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

# Run as root. GitHub Actions mounts /github/workspace, /github/file_commands,
# and other paths owned by the host runner UID. Dropping to a non-root user
# breaks post-step writes (GITHUB_OUTPUT, GITHUB_STEP_SUMMARY) because the
# runner process loses access to its own file_commands directory after our step.
# This is an ephemeral container — it is destroyed after the job step.
# omargate:allow-root-user

ENTRYPOINT ["/app/entrypoint.sh"]
