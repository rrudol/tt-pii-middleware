#!/usr/bin/env bash
# Deploy / refresh the tailnet-only PII demo on radium-226-ovh.
set -euo pipefail

HOST="${DEPLOY_HOST:-radium-226-ovh}"
REMOTE_DIR="${REMOTE_DIR:-/home/rocky/apps/tt-pii-middleware}"
REPO_URL="${REPO_URL:-https://github.com/rrudol/tt-pii-middleware.git}"
REF="${REF:-main}"

echo "==> deploy to $HOST ($REMOTE_DIR @ $REF)"

ssh -o BatchMode=yes "$HOST" bash -s << REMOTE
set -euo pipefail
mkdir -p "$(dirname "$REMOTE_DIR")"
if [ -d "$REMOTE_DIR/.git" ]; then
  cd "$REMOTE_DIR"
  git fetch origin
  git checkout "$REF"
  git pull --ff-only origin "$REF"
else
  git clone --branch "$REF" "$REPO_URL" "$REMOTE_DIR"
  cd "$REMOTE_DIR"
fi

TS_IP=\$(tailscale ip -4)
echo "TAILSCALE_IP=\$TS_IP"
export TAILSCALE_IP="\$TS_IP"

docker compose -f deploy/tailnet/docker-compose.yml up -d --build

echo "==> waiting for health"
for i in \$(seq 1 40); do
  if curl -fsS "http://127.0.0.1:7860/" >/dev/null 2>&1; then
    echo "healthy"
    break
  fi
  sleep 5
  if [ "\$i" -eq 40 ]; then
    echo "timeout waiting for demo" >&2
    docker compose -f deploy/tailnet/docker-compose.yml logs --tail 80
    exit 1
  fi
done

echo "==> listen check (must NOT be 0.0.0.0)"
ss -lntp 2>/dev/null | grep 7860 || netstat -lntp 2>/dev/null | grep 7860 || true

echo ""
echo "Demo URLs (tailnet only):"
echo "  http://\$TS_IP:7860"
echo "  http://radium-226-ovh:7860"
echo "  http://radium-226-ovh.taila403e3.ts.net:7860"
REMOTE
