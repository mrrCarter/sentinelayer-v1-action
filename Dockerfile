# syntax=docker/dockerfile:1

# Stage 1: Builder (install Python deps into a clean prefix)
FROM python:3.11-alpine AS builder

RUN apk add --no-cache \
        build-base \
        libffi-dev \
        openssl-dev \
        cargo \
    && python -m pip install --upgrade pip wheel

WORKDIR /tmp
COPY requirements.txt /tmp/requirements.txt

RUN python -m pip install --no-cache-dir --prefix=/install -r /tmp/requirements.txt

# Stage 2: Runtime (minimal, non-root)
FROM python:3.11-alpine AS runtime

RUN apk add --no-cache \
        ca-certificates \
        libstdc++ \
        nodejs \
        npm \
        git

# Install Codex CLI (pinned). Latest as of 2026-02-08: 0.98.0
RUN npm install -g @openai/codex@0.98.0 \
    && npm cache clean --force

RUN addgroup -S app && adduser -S -G app -u 10001 app

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    NODE_ENV=production

COPY --from=builder /install /usr/local
COPY --chown=app:app src /app/src
COPY --chown=app:app entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

USER app

ENTRYPOINT ["/app/entrypoint.sh"]
