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

# Stage 2: Runtime (runs as root in ephemeral container)
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

ENTRYPOINT ["/app/entrypoint.sh"]
