#!/usr/bin/env sh
set -eu

usage() {
  cat <<'EOF'
Usage:
  sh deploy/migrate-postgres-password.sh \
    --project-name NAME --env-file PATH [--apply]

Without --apply, this validates the private env file and prints the action that
would be required. With --apply, it changes only the retained PostgreSQL role
password. The PushGate application service must already be stopped and remains
stopped so the operator controls the service interruption and restart.

The env file must:
  - be a regular, non-symlink file owned by the invoking user
  - have no group or world permission bits
  - use simple KEY=VALUE syntax, with no Compose dotenv extensions
  - contain one unquoted PUSHGATE_POSTGRES_PASSWORD assignment
    of exactly 64 hex characters
  - not override PUSHGATE_DATABASE_URL
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

project_name=""
env_file=""
apply=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --project-name)
      [ "$#" -ge 2 ] || fail "--project-name requires a value"
      project_name="$2"
      shift 2
      ;;
    --env-file)
      [ "$#" -ge 2 ] || fail "--env-file requires a value"
      env_file="$2"
      shift 2
      ;;
    --apply)
      apply=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[ -n "$project_name" ] || fail "--project-name is required"
case "$project_name" in
  [a-z0-9]*) ;;
  *) fail "--project-name must start with a lowercase letter or digit" ;;
esac
case "$project_name" in
  *[!a-z0-9_-]*) fail "--project-name may contain only lowercase letters, digits, underscores, and hyphens" ;;
esac

[ -n "$env_file" ] || fail "--env-file is required"
case "$env_file" in
  /*) ;;
  *) env_file="$(pwd)/$env_file" ;;
esac
[ -f "$env_file" ] || fail "env file is not a regular file: $env_file"
[ ! -L "$env_file" ] || fail "env file must not be a symlink: $env_file"

if file_uid="$(stat -c %u -- "$env_file" 2>/dev/null)"; then
  file_mode="$(stat -c %a -- "$env_file")" || fail "cannot inspect env-file mode"
elif file_uid="$(stat -f %u "$env_file" 2>/dev/null)"; then
  file_mode="$(stat -f %Lp "$env_file")" || fail "cannot inspect env-file mode"
else
  fail "cannot inspect env-file ownership and permissions"
fi
[ "$file_uid" = "$(id -u)" ] || fail "env file must be owned by the invoking user"
case "$file_mode" in
  *[!0-7]*) fail "cannot validate env-file permissions" ;;
esac
[ $((0$file_mode & 077)) -eq 0 ] || fail "env file must not grant group or world permissions"

# Compose accepts several dotenv extensions, including whitespace around the
# delimiter. Restrict this security-sensitive file to one auditable grammar so
# a second spelling cannot bypass the checks below while still affecting Compose.
if ! awk '
  /^[[:space:]]*$/ { next }
  /^[[:space:]]*#/ { next }
  /^[A-Za-z_][A-Za-z0-9_]*=.*/ { next }
  { exit 1 }
' "$env_file"; then
  fail "env file must use simple KEY=VALUE assignments without leading whitespace or dotenv extensions"
fi

password_count="$(grep -c '^PUSHGATE_POSTGRES_PASSWORD=' "$env_file" || true)"
[ "$password_count" -eq 1 ] || fail "env file must contain exactly one PUSHGATE_POSTGRES_PASSWORD assignment"
new_password="$(sed -n 's/^PUSHGATE_POSTGRES_PASSWORD=//p' "$env_file")"
[ "${#new_password}" -eq 64 ] || fail "PUSHGATE_POSTGRES_PASSWORD must be exactly 64 hexadecimal characters"
case "$new_password" in
  *[!0-9A-Fa-f]*) fail "PUSHGATE_POSTGRES_PASSWORD must be exactly 64 hexadecimal characters" ;;
esac

if grep -Eq '^PUSHGATE_DATABASE_URL=' "$env_file"; then
  fail "database URL overrides are not supported by this helper; migrate that credential manually"
fi

root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
compose_file="$root/deploy/docker-compose.yml"

if [ "$apply" != true ]; then
  echo "Validation passed. No Docker connection was made and no state was changed."
  echo "The apply step will target Compose project '$project_name', require service 'server' to be stopped, and rotate only role 'pushgate'."
  echo "Re-run with --apply only during the documented maintenance procedure."
  exit 0
fi

command -v docker >/dev/null 2>&1 || fail "docker is required for --apply"
command -v python3 >/dev/null 2>&1 || fail "python3 is required for client-side SCRAM generation"

# Prevent caller environment variables from silently overriding the reviewed
# private env file when Compose resolves the application database URL.
unset PUSHGATE_POSTGRES_PASSWORD
unset PUSHGATE_DATABASE_URL

compose() {
  docker compose --project-name "$project_name" --env-file "$env_file" -f "$compose_file" "$@"
}

server_ids="$(compose ps --all -q server)"
for server_id in $server_ids; do
  server_status="$(docker inspect --format '{{.State.Status}}' "$server_id")" || fail "cannot inspect PushGate service state"
  case "$server_status" in
    created|exited) ;;
    *) fail "PushGate service 'server' is $server_status; it must be fully stopped before rotating the database credential" ;;
  esac
done

postgres_ids="$(compose ps --status running -q postgres)"
[ -n "$postgres_ids" ] || fail "PostgreSQL service is not running for Compose project '$project_name'"
[ "$(printf '%s\n' "$postgres_ids" | wc -l)" -eq 1 ] || fail "expected exactly one running PostgreSQL container"
postgres_id="$postgres_ids"
expected_volume="${project_name}_pgdata"
data_mount="$(
  docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}} {{.Name}}{{end}}{{end}}' "$postgres_id"
)" || fail "cannot inspect the PostgreSQL data mount"
[ "$data_mount" = "volume $expected_volume" ] || fail "PostgreSQL data mount is not the expected volume '$expected_volume'; migrate this custom deployment manually"

# Generate a standard PostgreSQL SCRAM verifier on the client side. ALTER ROLE
# receives no plaintext password, avoiding exposure through SQL statement logs.
new_verifier="$(
  printf '%s' "$new_password" | python3 -c '
import base64
import hashlib
import hmac
import secrets
import sys

password = sys.stdin.buffer.read()
salt = secrets.token_bytes(16)
iterations = 4096
salted = hashlib.pbkdf2_hmac("sha256", password, salt, iterations)
client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
stored_key = hashlib.sha256(client_key).digest()
server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
encode = lambda value: base64.b64encode(value).decode("ascii")
print(f"SCRAM-SHA-256${iterations}:{encode(salt)}${encode(stored_key)}:{encode(server_key)}")
'
)" || fail "could not generate a client-side PostgreSQL SCRAM verifier"
if ! printf '%s' "$new_verifier" | grep -Eq \
  '^SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$'; then
  fail "client-side SCRAM verifier generation returned an invalid value"
fi

# The official Postgres image permits the database owner to use its local Unix
# socket. The plaintext password enters the container only over stdin and is
# used only for the post-change TCP authentication check.
printf '%s\n%s\n' "$new_verifier" "$new_password" | compose exec -T postgres sh -eu -c '
  IFS= read -r verifier
  IFS= read -r password
  case "$password" in
    ""|*[!0-9A-Fa-f]*)
      echo "invalid password input" >&2
      exit 2
      ;;
  esac
  [ "${#password}" -eq 64 ] || {
    echo "invalid password length" >&2
    exit 2
  }
  if ! printf "%s" "$verifier" | grep -Eq \
    "^SCRAM-SHA-256\\\$[0-9]+:[A-Za-z0-9+/=]+\\\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$"; then
    echo "invalid SCRAM verifier input" >&2
    exit 2
  fi

  old_verifier="$(
    psql -X --set=ON_ERROR_STOP=1 --tuples-only --no-align \
      --username=pushgate --dbname=pushgate \
      --command="SELECT rolpassword FROM pg_authid WHERE rolname = '\''pushgate'\''"
  )"
  if ! printf "%s" "$old_verifier" | grep -Eq \
    "^(md5[0-9A-Fa-f]{32}|SCRAM-SHA-256\\\$[0-9]+:[A-Za-z0-9+/=]+\\\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+)$"; then
    echo "cannot safely capture the existing PostgreSQL password verifier" >&2
    exit 3
  fi

  rotated=false
  restore_previous() {
    [ "$rotated" = true ] || return 0
    rotated=false
    if printf "ALTER ROLE pushgate PASSWORD '\''%s'\'';\n" "$old_verifier" |
      psql -X --set=ON_ERROR_STOP=1 --username=pushgate --dbname=pushgate >/dev/null; then
      echo "new-password verification failed; restored the previous PostgreSQL verifier" >&2
    else
      echo "critical: new-password verification failed and automatic verifier restoration also failed" >&2
      return 1
    fi
  }
  trap restore_previous EXIT
  trap "exit 130" HUP INT TERM

  rotated=true
  printf "ALTER ROLE pushgate PASSWORD '\''%s'\'';\n" "$verifier" |
    psql -X --set=ON_ERROR_STOP=1 --username=pushgate --dbname=pushgate
  PGPASSWORD="$password" psql -X --set=ON_ERROR_STOP=1 \
    --host=127.0.0.1 --username=pushgate --dbname=pushgate \
    --command="SELECT 1" >/dev/null
  if PGPASSWORD="${password}0" psql -X --set=ON_ERROR_STOP=1 \
    --host=127.0.0.1 --username=pushgate --dbname=pushgate \
    --command="SELECT 1" >/dev/null 2>&1; then
    echo "TCP connection accepted an incorrect password; refusing an unverified rotation" >&2
    exit 4
  fi
  rotated=false
  trap - EXIT HUP INT TERM
'

echo "PostgreSQL credential changed and TCP authentication verified."
echo "PushGate service 'server' remains stopped. Start and verify it using the documented command with the same project name and env file."
