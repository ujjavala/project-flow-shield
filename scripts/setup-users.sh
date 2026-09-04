#!/usr/bin/env bash
set -euo pipefail

cat <<'MESSAGE'
Demo users are created idempotently by the Docker Compose migration service.

Start the stack with:
  make demo

Display the random per-install credentials explicitly with:
  make demo-credentials

Do not copy generated credentials into source control or automated logs.
MESSAGE