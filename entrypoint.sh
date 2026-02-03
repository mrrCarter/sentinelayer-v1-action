#!/bin/sh
set -eu

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

required_envs="GITHUB_EVENT_PATH GITHUB_REPOSITORY GITHUB_OUTPUT GITHUB_TOKEN"
for name in $required_envs; do
  value="$(printenv "$name" || true)"
  if [ -z "$value" ]; then
    echo "Missing required env var: $name" >&2
    exit 2
  fi
done

export PYTHONPATH="/app/src:${PYTHONPATH:-}"

exec python -m omargate.main
