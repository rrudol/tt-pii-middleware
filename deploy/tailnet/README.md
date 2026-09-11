# Tailnet demo (no Hugging Face Spaces)

Interactive **redact-only** FastAPI UI, reachable only on the Tailscale tailnet
via HTTPS at **https://guard.rudol.dev**.

## Live

| | |
|---|---|
| **Primary** | https://guard.rudol.dev |
| Direct IP | http://100.87.100.111:7860 |
| MagicDNS | http://radium-226-ovh.taila403e3.ts.net:7860 |
| Host | radium-226-ovh Docker `pl-pii-demo` |
| Ingress | k8s ns `guard` (radium-226 GitOps) → EndpointSlice host IP:7860 |
| DNS | Cloudflare A DNS-only → 100.87.100.111 (not proxied) |
| TLS | cert-manager LE DNS-01 (`guard-rudol-dev-tls`) |
| ACL | ingress whitelist `100.64.0.0/10` (+ CNI); public NIC firewalled |
| Guardrails | max 2000 chars, 30 req/IP/min, redact-only, synthetic examples |

## Deploy / update

From a machine with SSH to the host:

```bash
./deploy/tailnet/deploy.sh
```

Or on the host:

```bash
cd ~/apps/tt-pii-middleware
git pull
export TAILSCALE_IP=$(tailscale ip -4)
docker compose -f deploy/tailnet/docker-compose.yml up -d --build
```

## Local Mac (optional)

```bash
export TAILSCALE_IP=$(tailscale ip -4)   # e.g. 100.70.108.84
docker compose -f deploy/tailnet/docker-compose.yml up --build
# open http://$TAILSCALE_IP:7860 from any tailnet device
```

## Security notes

- Port published only on `100.x` — confirm with `ss -lntp | grep 7860` (should not show `0.0.0.0:7860`).
- Do not paste real production PII; demo logs entity **types/counts** only.
- Redaction ≠ GDPR compliance.
