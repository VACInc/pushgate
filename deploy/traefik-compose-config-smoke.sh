#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp)"
CANONICAL_OUT="$(mktemp)"
trap 'rm -f "$OUT" "$CANONICAL_OUT"' EXIT INT TERM

# Keep caller dotenv files and production service URLs out of rendered smoke
# output. The fixed values below are non-secret test fixtures.
export PUSHGATE_DATABASE_URL=
export PUSHGATE_REDIS_URL=
export PUSHGATE_APP_BIND=127.0.0.1

PUSHGATE_PROXY_ADMIN_GROUPS= \
PUSHGATE_HOST=pushgate.example.com \
PUSHGATE_PROXY_FORWARD_AUTH_URL=https://identity.example.com/verify \
PUSHGATE_PROXY_AUTH_SECRET=compose-config-smoke-proxy-secret \
PUSHGATE_BOOTSTRAP_TOKEN=compose-config-smoke-token-0123456789 \
PUSHGATE_POSTGRES_PASSWORD=compose-config-smoke-password \
docker compose \
  --env-file /dev/null \
  -f "$ROOT/deploy/docker-compose.yml" \
  -f "$ROOT/deploy/docker-compose.traefik.yml" \
  config > "$OUT"

# Keep the internal Compose service key stable for in-place upgrades.
grep -q '^  server:$' "$OUT"
if grep -q '^  pushgate:$' "$OUT"; then
  echo "Compose application service key must remain server for upgrade compatibility" >&2
  exit 1
fi
grep -q "pushgate-public" "$OUT"
grep -q "PathPrefix(\`/api/v1\`)" "$OUT"
grep -q "pushgate-admin" "$OUT"
grep -q "forwardauth.address" "$OUT"
grep -q "PUSHGATE_TRUSTED_PROXY_AUTH_ENABLED: \"true\"" "$OUT"
grep -q "PUSHGATE_TRUSTED_PROXY_AUTH_ADMIN_GROUPS: pushgate-admins" "$OUT"
grep -q '^PUSHGATE_PROXY_ADMIN_GROUPS=pushgate-admins$' "$ROOT/deploy/traefik.env.example"
grep -q "PUSHGATE_TRUSTED_PROXY_AUTH_SECRET: compose-config-smoke-proxy-secret" "$OUT"
grep -q "X-PushGate-Proxy-Secret: compose-config-smoke-proxy-secret" "$OUT"
grep -q "pushgate-strip-auth-headers@docker,pushgate-proxy-secret@docker,pushgate-secure-headers@docker" "$OUT"
grep -q "pushgate-strip-auth-headers@docker,pushgate-proxy@docker,pushgate-proxy-secret@docker,pushgate-secure-headers@docker" "$OUT"
grep -q "pushgate-proxy.forwardauth.authRequestHeaders: Cookie" "$OUT"
grep -q "pushgate-proxy.forwardauth.trustForwardHeader: \"false\"" "$OUT"
for header in \
  X-proxy-username X-proxy-groups X-proxy-entitlements \
  X-proxy-email X-proxy-name X-proxy-uid X-proxy-jwt \
  X-proxy-meta-jwks X-proxy-meta-outpost X-proxy-meta-provider \
  X-proxy-meta-app X-proxy-meta-version X-PushGate-Proxy-Secret
do
  grep -q "pushgate-strip-auth-headers.headers.customRequestHeaders.$header: \"\"" "$OUT"
done
grep -q "pushgate-secure-headers.headers.contentSecurityPolicy: default-src" "$OUT"
grep -q "script-src 'self'; style-src 'self'; img-src 'self'" "$OUT"
if grep -q "unsafe-inline" "$OUT"; then
  echo "CSP must not allow inline scripts or styles" >&2
  exit 1
fi
grep -q "pushgate-secure-headers.headers.stsSeconds: \"31536000\"" "$OUT"
if grep -q "pushgate-secure-headers.headers.stsIncludeSubdomains" "$OUT" || \
   grep -q "pushgate-secure-headers.headers.stsPreload" "$OUT"; then
  echo "HSTS must not cover unverified subdomains or advertise preload" >&2
  exit 1
fi
if grep -q "pushgate-proxy.forwardauth.authRequestHeaders:.*Authorization" "$OUT"; then
  echo "ForwardAuth must not receive the admin bearer Authorization header" >&2
  exit 1
fi
grep -q 'host_ip: 127.0.0.1' "$OUT"

# Honor an explicit administrator group override.
PUSHGATE_PROXY_ADMIN_GROUPS=pushgate-operators \
PUSHGATE_HOST=pushgate.example.com \
PUSHGATE_PROXY_FORWARD_AUTH_URL=https://identity.example.com/verify \
PUSHGATE_PROXY_AUTH_SECRET=compose-config-smoke-proxy-secret \
PUSHGATE_BOOTSTRAP_TOKEN=compose-config-smoke-token-0123456789 \
PUSHGATE_POSTGRES_PASSWORD=compose-config-smoke-password \
docker compose \
  --env-file /dev/null \
  -f "$ROOT/deploy/docker-compose.yml" \
  -f "$ROOT/deploy/docker-compose.traefik.yml" \
  config > "$CANONICAL_OUT"
grep -q "PUSHGATE_TRUSTED_PROXY_AUTH_ADMIN_GROUPS: pushgate-operators" "$CANONICAL_OUT"

echo "Traefik/Identity proxy compose config checks passed"
