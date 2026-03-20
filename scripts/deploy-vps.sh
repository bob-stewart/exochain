#!/bin/bash
# ── Deploy ExoEth Platform to VPS ──────────────────────────────
# Deploys the full ExoChain governance stack to a VPS with
# Nginx reverse proxy and Let's Encrypt SSL for cto.systems.
#
# Usage:
#   ./scripts/deploy-vps.sh user@your-vps.com            # Full deploy + SSL
#   ./scripts/deploy-vps.sh user@your-vps.com --build     # Force rebuild
#   ./scripts/deploy-vps.sh user@your-vps.com --sync-only # Just rsync, no restart
#
# Prerequisites on VPS:
#   - Docker Engine 24+ with Compose plugin
#   - SSH access with key-based auth
#   - DNS: cto.systems A record → VPS IP

set -euo pipefail

DOMAIN="cto.systems"

if [ -z "${1:-}" ]; then
  echo "Usage: $0 user@host [--build|--sync-only]"
  exit 1
fi

VPS_HOST="$1"
MODE="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
REMOTE_DIR="/opt/exochain"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ExoEth Platform — VPS Deployment                           ║"
echo "║  Target: $VPS_HOST → https://$DOMAIN                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# ── Step 1: Build Syntaxis frontend locally ────────────────────
echo ""
echo "── Building Syntaxis Builder frontend ─────────────────────"
if [ -d "$REPO_ROOT/apps/syntaxis-builder/node_modules" ]; then
  (cd "$REPO_ROOT/apps/syntaxis-builder" && npm run build)
else
  (cd "$REPO_ROOT/apps/syntaxis-builder" && npm install && npm run build)
fi

# ── Step 2: Sync project to VPS ────────────────────────────────
echo ""
echo "── Syncing project files to VPS ───────────────────────────"
ssh "$VPS_HOST" "mkdir -p $REMOTE_DIR"

rsync -avz --delete \
  --exclude 'node_modules' \
  --exclude '.git' \
  --exclude '.claude' \
  --exclude 'target' \
  --exclude 'crates' \
  --exclude 'contracts' \
  --exclude 'agents' \
  --exclude '.turbo' \
  "$REPO_ROOT/" "$VPS_HOST:$REMOTE_DIR/"

if [ "$MODE" = "--sync-only" ]; then
  echo "Sync complete. Exiting (--sync-only)."
  exit 0
fi

# ── Step 3: Install Docker if needed ──────────────────────────
echo ""
echo "── Ensuring Docker is installed ───────────────────────────"
ssh "$VPS_HOST" 'command -v docker &>/dev/null || {
  echo "Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
}'

# ── Step 4: Obtain SSL certificate (first time only) ──────────
echo ""
echo "── Setting up SSL for $DOMAIN ─────────────────────────────"
ssh "$VPS_HOST" "
  if [ ! -d /etc/letsencrypt/live/$DOMAIN ]; then
    echo 'Obtaining SSL certificate...'

    # Start a temporary Nginx for the ACME challenge
    mkdir -p /tmp/certbot-www
    docker run -d --name certbot-nginx -p 80:80 \
      -v /tmp/certbot-www:/var/www/certbot:ro \
      nginx:alpine sh -c 'echo \"server { listen 80; location /.well-known/acme-challenge/ { root /var/www/certbot; } location / { return 444; } }\" > /etc/nginx/conf.d/default.conf && nginx -g \"daemon off;\"' 2>/dev/null || true

    sleep 2

    # Run certbot
    docker run --rm \
      -v /etc/letsencrypt:/etc/letsencrypt \
      -v /tmp/certbot-www:/var/www/certbot \
      certbot/certbot certonly --webroot \
      -w /var/www/certbot \
      -d $DOMAIN \
      --non-interactive --agree-tos \
      --email admin@$DOMAIN \
      --no-eff-email

    # Stop temp Nginx
    docker rm -f certbot-nginx 2>/dev/null || true

    echo 'SSL certificate obtained!'
  else
    echo 'SSL certificate already exists.'
  fi
"

# ── Step 5: Start the full stack ───────────────────────────────
echo ""
echo "── Starting ExoEth platform ───────────────────────────────"
BUILD_FLAG=""
if [ "$MODE" = "--build" ]; then
  BUILD_FLAG="--build"
fi

ssh "$VPS_HOST" "
  cd $REMOTE_DIR/infra/compose

  # Map host SSL certs into the certbot-conf volume
  # Create a docker volume with the certs if needed
  docker compose -f docker-compose.yml -f docker-compose.prod.yml down 2>/dev/null || true

  # Ensure the certbot-conf volume has the real certs
  docker volume create --name exoeth_certbot-conf 2>/dev/null || true
  docker run --rm \
    -v /etc/letsencrypt:/source:ro \
    -v exoeth_certbot-conf:/dest \
    alpine sh -c 'cp -rL /source/* /dest/' 2>/dev/null || true

  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d $BUILD_FLAG
"

# ── Step 6: Wait and verify ────────────────────────────────────
echo ""
echo "── Waiting for services to start ──────────────────────────"
sleep 15

echo ""
echo "── Health checks ──────────────────────────────────────────"
SERVICES=(
  "3000:Gateway API"
  "3001:0dentity"
  "3002:LiveSafe Consent"
  "3003:Governance Engine"
  "3004:Decision Forge"
  "3005:CrossCheck"
  "3006:Provenance Writer"
  "3007:Audit API"
  "3008:Notifications"
  "3009:LegalDyne Policy"
  "3010:Syntaxis"
  "3011:CAIP Engine"
)

for svc in "${SERVICES[@]}"; do
  PORT="${svc%%:*}"
  NAME="${svc##*:}"
  if ssh "$VPS_HOST" "curl -sf http://localhost:$PORT/health" > /dev/null 2>&1; then
    echo "  ✅ $NAME (:$PORT)"
  else
    echo "  ⏳ $NAME (:$PORT) — starting..."
  fi
done

# Check Nginx
if ssh "$VPS_HOST" "curl -sf -o /dev/null -w '%{http_code}' https://$DOMAIN" 2>/dev/null | grep -q "200\|301\|302"; then
  echo "  ✅ Nginx (https://$DOMAIN)"
else
  echo "  ⏳ Nginx — may need a moment..."
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Deployment complete!                                       ║"
echo "║                                                             ║"
echo "║  Syntaxis Builder:  https://$DOMAIN                         ║"
echo "║  Dashboard:         https://$DOMAIN/dashboard/              ║"
echo "║  Gateway API:       https://$DOMAIN/api/                    ║"
echo "║  Governance:        https://$DOMAIN/api/governance/         ║"
echo "║  CAIP Engine:       https://$DOMAIN/api/caip/               ║"
echo "║  Syntaxis API:      https://$DOMAIN/api/syntaxis/           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
