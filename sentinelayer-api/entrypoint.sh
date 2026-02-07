#!/bin/sh
set -eu

# Construct DATABASE_URL/TIMESCALE_URL from rotating RDS credentials (injected as DB_USERNAME/DB_PASSWORD)
# so we don't bake static passwords into a long-lived "runtime secret" value.
#
# Expected inputs:
# - DB_USERNAME (secret)
# - DB_PASSWORD (secret)
# - DB_HOST (env, typically the RDS Proxy endpoint)
# - DB_PORT (env, default 5432)
# - DB_NAME (env)
# - DB_SCHEME (env, default postgresql+asyncpg)
#
# Outputs:
# - DATABASE_URL
# - TIMESCALE_URL (defaults to DATABASE_URL)

DB_PORT="${DB_PORT:-5432}"
DB_SCHEME="${DB_SCHEME:-postgresql+asyncpg}"

# Ensure the app package (`src.*`) is importable for both uvicorn and alembic.
export PYTHONPATH="/app:${PYTHONPATH:-}"

if [ -n "${DB_USERNAME:-}" ] && [ -n "${DB_PASSWORD:-}" ] && [ -n "${DB_HOST:-}" ] && [ -n "${DB_NAME:-}" ]; then
  # URL-encode credentials (master passwords often contain reserved characters)
  ENC_USER="$(python -c 'import os,urllib.parse; print(urllib.parse.quote_plus(os.environ["DB_USERNAME"]))')"
  ENC_PASS="$(python -c 'import os,urllib.parse; print(urllib.parse.quote_plus(os.environ["DB_PASSWORD"]))')"

  export DATABASE_URL="${DB_SCHEME}://${ENC_USER}:${ENC_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}"

  # If you truly need a second DB, set TIMESCALE_URL explicitly via task definition env vars.
  export TIMESCALE_URL="${DATABASE_URL}"

  # Reduce accidental exposure (the app reads DATABASE_URL/TIMESCALE_URL, not these raw creds).
  unset DB_PASSWORD
  unset DB_USERNAME
fi

exec "$@"
