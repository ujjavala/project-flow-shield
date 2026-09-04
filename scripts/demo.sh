#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

if [ "${1:-}" = "--ai" ]; then
  export VITE_AI_ENABLED=true
  export RISK_POLICY_AI_SHADOW_ENABLED=true
  export PRIVILEGED_ACCESS_AGENT_AI_ENABLED=true
  docker compose --profile ai up --build --wait
else
  docker compose up --build --wait
fi

docker compose ps
cat <<'EOF'

FlowShield local demo is ready:
  App:          http://localhost:3000
  API docs:     http://localhost:8000/docs
  Temporal UI: http://localhost:8081
  Mailpit:      http://localhost:8025
  Prometheus:   http://localhost:9090
  Grafana:      http://localhost:3001 (admin / flowshield-local-only)
EOF
