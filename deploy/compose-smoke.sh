#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/deploy/docker-compose.yml"
PROJECT="${PUSHGATE_COMPOSE_SMOKE_PROJECT:-pushgate-smoke}"
SERVER_URL="${PUSHGATE_COMPOSE_SMOKE_SERVER:-http://127.0.0.1:8000}"
WEB_URL="${PUSHGATE_COMPOSE_SMOKE_WEB:-http://127.0.0.1:8000}"
TOKEN="${PUSHGATE_COMPOSE_SMOKE_TOKEN:-pushgate-compose-smoke-token-0123456789}"

fail() {
  echo "error: $*" >&2
  exit 2
}

# This harness tears down its project with volumes. Keep overrides inside an
# unmistakable smoke-test namespace so a typo cannot target a live deployment.
case "$PROJECT" in
  pushgate-smoke) ;;
  pushgate-smoke-*)
    case "$PROJECT" in
      *[!a-z0-9_-]*) fail "smoke project names may contain only lowercase letters, digits, underscores, and hyphens" ;;
    esac
    ;;
  *) fail "refusing non-smoke Compose project: $PROJECT" ;;
esac

validate_loopback_url() {
  url="$1"
  case "$url" in
    http://127.0.0.1:*) authority="${url#http://127.0.0.1:}" ;;
    http://localhost:*) authority="${url#http://localhost:}" ;;
    *) fail "smoke endpoints must use loopback HTTP URLs: $url" ;;
  esac
  port="${authority%%/*}"
  case "$port" in
    ''|*[!0-9]*) fail "smoke endpoints must include a numeric loopback port: $url" ;;
  esac
  [ "$authority" = "$port" ] || fail "smoke endpoints must be bare loopback origins without paths: $url"
}

for url in "$SERVER_URL" "$WEB_URL"; do
  validate_loopback_url "$url"
done

command -v docker >/dev/null 2>&1 || fail "docker is required"
if [ -n "${DOCKER_HOST:-}" ]; then
  docker_endpoint="$DOCKER_HOST"
else
  docker_context="${DOCKER_CONTEXT:-$(docker context show)}"
  docker_endpoint="$(docker context inspect --format '{{.Endpoints.docker.Host}}' "$docker_context")" ||
    fail "cannot inspect Docker context: $docker_context"
fi
case "$docker_endpoint" in
  unix://*|npipe://*) ;;
  *) fail "refusing destructive Compose smoke against non-local Docker endpoint: $docker_endpoint" ;;
esac

# Do not let a caller's production service URLs or bind address leak into this
# destructive, disposable Compose project.
export PUSHGATE_DATABASE_URL=
export PUSHGATE_REDIS_URL=
export PUSHGATE_APP_BIND=127.0.0.1
export PUSHGATE_BOOTSTRAP_TOKEN="$TOKEN"
export PUSHGATE_POSTGRES_PASSWORD="${PUSHGATE_COMPOSE_SMOKE_POSTGRES_PASSWORD:-pushgate-compose-smoke-password}"

cleanup() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

cleanup
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --build

wait_for() {
  name="$1"
  url="$2"
  limit="${3:-90}"
  i=0
  while [ "$i" -lt "$limit" ]; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  echo "timed out waiting for $name at $url" >&2
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" ps >&2 || true
  return 1
}

wait_for "server health" "$SERVER_URL/healthz"
wait_for "admin web" "$WEB_URL"
curl -fsS "$WEB_URL" | grep -q "PushGate Admin"

curl -fsS \
  -H "Authorization: Bearer $TOKEN" \
  "$SERVER_URL/api/admin/settings/global" >/dev/null
if curl -fsS \
  -H "Authorization: Bearer ${TOKEN}x" \
  "$SERVER_URL/api/admin/settings/global" >/dev/null 2>&1; then
  echo "Admin API accepted an invalid smoke token" >&2
  exit 1
fi

echo "Compose smoke checks passed"
