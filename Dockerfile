# syntax=docker/dockerfile:1

# Stage 1: Builder (install Python deps into a clean prefix)
FROM python:3.11-alpine@sha256:303398d5c9f110790bce60d64f902e51e1a061e33292985c72bf6cd07960bf09 AS builder

RUN set -eux; \
    pin_pkg() { \
      pkg="$1"; \
      ver="$(apk search -x "$pkg" | sed -n "s/^${pkg}-//p" | head -n1)"; \
      test -n "$ver"; \
      printf '%s=%s\n' "$pkg" "$ver"; \
    }; \
    apk add --no-cache \
      "$(pin_pkg build-base)" \
      "$(pin_pkg libffi-dev)" \
      "$(pin_pkg openssl-dev)" \
      "$(pin_pkg cargo)" \
    && python -m pip install --upgrade pip wheel

WORKDIR /tmp
COPY requirements.lock.txt /tmp/requirements.lock.txt

RUN python -m pip install --no-cache-dir --prefix=/install --require-hashes -r /tmp/requirements.lock.txt

# Stage 2: Runtime (runs as root in ephemeral container)
FROM python:3.11-alpine@sha256:303398d5c9f110790bce60d64f902e51e1a061e33292985c72bf6cd07960bf09 AS runtime

RUN set -eux; \
    pin_pkg() { \
      pkg="$1"; \
      ver="$(apk search -x "$pkg" | sed -n "s/^${pkg}-//p" | head -n1)"; \
      test -n "$ver"; \
      printf '%s=%s\n' "$pkg" "$ver"; \
    }; \
    apk add --no-cache \
      "$(pin_pkg ca-certificates)" \
      "$(pin_pkg libstdc++)" \
      "$(pin_pkg nodejs)" \
      "$(pin_pkg npm)" \
      "$(pin_pkg git)"

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
