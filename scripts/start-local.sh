#!/bin/bash
# ── Start ExoEth Platform Locally ──────────────────────────────
# Brings up all services via Docker Compose
#
# Usage:
#   ./scripts/start-local.sh          # Start all services
#   ./scripts/start-local.sh --build  # Rebuild and start
#   ./scripts/start-local.sh --down   # Stop all services

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_DIR="$REPO_ROOT/infra/compose"

cd "$COMPOSE_DIR"

if [ "${1:-}" = "--down" ]; then
  echo "🛑 Stopping all services..."
  docker compose down
  exit 0
fi

BUILD_FLAG=""
if [ "${1:-}" = "--build" ]; then
  BUILD_FLAG="--build"
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ExoEth Platform — Local Development Stack                  ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  PostgreSQL:          localhost:5432                         ║"
echo "║  Gateway API:         http://localhost:3000                  ║"
echo "║  0dentity:            http://localhost:3001                  ║"
echo "║  LiveSafe Consent:    http://localhost:3002                  ║"
echo "║  Governance Engine:   http://localhost:3003                  ║"
echo "║  Decision Forge:      http://localhost:3004                  ║"
echo "║  CrossChecked:        http://localhost:3005                  ║"
echo "║  Provenance Writer:   http://localhost:3006                  ║"
echo "║  Audit API:           http://localhost:3007                  ║"
echo "║  Notifications:       http://localhost:3008                  ║"
echo "║  LegalDyne Policy:    http://localhost:3009                  ║"
echo "║  Syntaxis:            http://localhost:3010                  ║"
echo "║  CAIP Engine:         http://localhost:3011                  ║"
echo "║  Dashboard:           http://localhost:8080                  ║"
echo "║  Syntaxis Builder:    http://localhost:8081                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

docker compose up $BUILD_FLAG -d

echo ""
echo "⏳ Waiting for services to become healthy..."
sleep 5

# Health checks
SERVICES=(
  "3000:gateway-api"
  "3001:identity-service"
  "3002:consent-service"
  "3003:governance-engine"
  "3004:decision-forge"
  "3005:crosscheck-adapter"
  "3006:provenance-writer"
  "3007:audit-api"
  "3008:notification-service"
  "3009:policy-distribution"
  "3010:syntaxis-orchestrator"
  "3011:caip-engine"
)

echo ""
echo "🏥 Service Health:"
for svc in "${SERVICES[@]}"; do
  PORT="${svc%%:*}"
  NAME="${svc##*:}"
  if curl -sf "http://localhost:$PORT/health" > /dev/null 2>&1; then
    echo "  ✅ $NAME (:$PORT)"
  else
    echo "  ⏳ $NAME (:$PORT) — starting..."
  fi
done

echo ""
echo "🎉 Platform is running! Open http://localhost:8081 for Syntaxis Builder"
