#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

PREFIX=${PREFIX:-/usr/local}
CONFIG_DIR=${CONFIG_DIR:-/etc/pushgate}
CACHE_DIR=${CACHE_DIR:-/etc/pushgate/failmode.d}
VENV_DIR=${VENV_DIR:-/opt/pushgate-pam}
LIBEXEC_DIR=${LIBEXEC_DIR:-$PREFIX/libexec}
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
HELPER_SRC="$SCRIPT_DIR/pushgate_pam.py"
VALIDATION_SRC="$SCRIPT_DIR/config_validation.py"
REQUIREMENTS_LOCK="$SCRIPT_DIR/requirements.lock"
DRY_RUN=0
SERVER=${PUSHGATE_SERVER:-}
CLIENT_ID=${PUSHGATE_CLIENT_ID:-}
CLIENT_SECRET=${PUSHGATE_CLIENT_SECRET:-}
CLIENT_SECRET_FILE='' # Set only by explicit file option.
LEGACY_SECRET_ARGUMENT=0
APPROVER_USERNAME=${PUSHGATE_APPROVER_USERNAME:-}
SYSTEM_NAME=${PUSHGATE_SYSTEM_NAME:-}
TIMEOUT=${PUSHGATE_TIMEOUT:-70}
CACHE_MAX_AGE=${PUSHGATE_CACHE_MAX_AGE:-86400}

usage() {
  echo "usage: $0 --server URL --client-id ID --client-secret-file FILE [--approver-username USER] [--system-name NAME] [--timeout SECONDS] [--cache-max-age SECONDS] [--dry-run]" >&2
  echo "       $0 --server URL --client-id ID --client-secret SECRET ...  (deprecated compatibility form)" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --server) SERVER=$2; shift 2 ;;
    --client-id) CLIENT_ID=$2; shift 2 ;;
    --client-secret) CLIENT_SECRET=$2; LEGACY_SECRET_ARGUMENT=1; shift 2 ;;
    --client-secret-file) CLIENT_SECRET_FILE=$2; shift 2 ;;
    --approver-username) APPROVER_USERNAME=$2; shift 2 ;;
    --system-name) SYSTEM_NAME=$2; shift 2 ;;
    --timeout) TIMEOUT=$2; shift 2 ;;
    --cache-max-age) CACHE_MAX_AGE=$2; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

read_client_secret_file() {
  python3 -I - "$1" "${SUDO_UID:-}" <<'PY'
import os
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
path = path if path.is_absolute() else Path.cwd() / path
current = path
while True:
    try:
        metadata = os.lstat(current)
    except OSError as exc:
        raise SystemExit(f"cannot inspect client secret path: {exc.__class__.__name__}") from None
    if stat.S_ISLNK(metadata.st_mode):
        raise SystemExit("client secret path must not contain symlinks")
    if current.parent == current:
        break
    current = current.parent

flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
try:
    descriptor = os.open(path, flags)
except OSError as exc:
    raise SystemExit(f"cannot open client secret file: {exc.__class__.__name__}") from None
try:
    metadata = os.fstat(descriptor)
    allowed_owners = {os.geteuid()}
    if sys.argv[2].isdigit():
        allowed_owners.add(int(sys.argv[2]))
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SystemExit("client secret must be a regular, non-hardlinked file")
    if metadata.st_uid not in allowed_owners or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SystemExit("client secret file must be privately owned with no group or other permissions")
    data = os.read(descriptor, 4097)
finally:
    os.close(descriptor)

if len(data) > 4096:
    raise SystemExit("client secret is too large")
if data.endswith(b"\r\n"):
    data = data[:-2]
elif data.endswith(b"\n"):
    data = data[:-1]
if not data or any(byte < 0x21 or byte > 0x7E for byte in data):
    raise SystemExit("client secret must be non-empty printable ASCII without whitespace or control characters")
os.write(sys.stdout.fileno(), data)
PY
}

validate_config_value() {
  label=$1
  value=$2
  if ! printf '%s' "$value" | python3 -I -c '
import sys
label = sys.argv[1]
data = sys.stdin.buffer.read()
if any(byte < 0x20 or byte == 0x7F for byte in data):
    print(f"{label} must not contain control characters", file=sys.stderr)
    raise SystemExit(1)
' "$label"; then
    exit 2
  fi
}

if [ -n "$CLIENT_SECRET_FILE" ]; then
  if [ "$LEGACY_SECRET_ARGUMENT" = 1 ]; then
    echo "use only one of --client-secret-file or --client-secret" >&2
    exit 2
  fi
  if ! CLIENT_SECRET=$(read_client_secret_file "$CLIENT_SECRET_FILE"); then
    exit 2
  fi
elif [ "$LEGACY_SECRET_ARGUMENT" = 1 ]; then
  echo "warning: --client-secret is deprecated because command-line secrets may be visible; use --client-secret-file" >&2
fi

[ -n "$SERVER" ] || { usage; exit 2; }
[ -n "$CLIENT_ID" ] || { usage; exit 2; }
[ -n "$CLIENT_SECRET" ] || { usage; exit 2; }
[ -r "$REQUIREMENTS_LOCK" ] || { echo "missing hashed dependency lock: $REQUIREMENTS_LOCK" >&2; exit 1; }

if [ "$DRY_RUN" != 1 ] && [ "$(id -u)" != 0 ]; then
  echo "must run as root; use --dry-run to preview" >&2
  exit 1
fi

validate_config_value "server" "$SERVER"
validate_config_value "client ID" "$CLIENT_ID"
validate_config_value "client secret" "$CLIENT_SECRET"
validate_config_value "approver username" "$APPROVER_USERNAME"
validate_config_value "system name" "$SYSTEM_NAME"
validate_config_value "config directory" "$CONFIG_DIR"
validate_config_value "cache directory" "$CACHE_DIR"
validate_config_value "virtualenv directory" "$VENV_DIR"
validate_config_value "libexec directory" "$LIBEXEC_DIR"
validate_config_value "timeout" "$TIMEOUT"
validate_config_value "cache maximum age" "$CACHE_MAX_AGE"

case "$TIMEOUT" in *[!0-9]*|'') echo "timeout must be an integer" >&2; exit 2 ;; esac
case "$CACHE_MAX_AGE" in *[!0-9]*|'') echo "cache maximum age must be an integer" >&2; exit 2 ;; esac
if [ "$DRY_RUN" = 1 ]; then
  if ! python3 -I "$VALIDATION_SRC" \
    --server "$SERVER" \
    --timeout "$TIMEOUT" \
    --cache-max-age "$CACHE_MAX_AGE" \
    --config-dir "$CONFIG_DIR" \
    --cache-dir "$CACHE_DIR" \
    --venv-dir "$VENV_DIR" \
    --libexec-dir "$LIBEXEC_DIR"; then
    exit 2
  fi
else
  if ! python3 -I "$VALIDATION_SRC" \
    --server "$SERVER" \
    --timeout "$TIMEOUT" \
    --cache-max-age "$CACHE_MAX_AGE" \
    --config-dir "$CONFIG_DIR" \
    --cache-dir "$CACHE_DIR" \
    --venv-dir "$VENV_DIR" \
    --libexec-dir "$LIBEXEC_DIR" \
    --require-root-owned-paths; then
    exit 2
  fi
fi

run() {
  if [ "$DRY_RUN" = 1 ]; then
    printf 'DRY-RUN: %s\n' "$*"
  else
    "$@"
  fi
}

run mkdir -p "$CONFIG_DIR" "$CACHE_DIR" "$LIBEXEC_DIR" "$VENV_DIR"
run chmod 700 "$CONFIG_DIR" "$CACHE_DIR"
run python3 -I -m venv "$VENV_DIR"
run "$VENV_DIR/bin/python" -I -m pip install --require-hashes --only-binary=:all: -r "$REQUIREMENTS_LOCK"
run install -m 0755 "$HELPER_SRC" "$VENV_DIR/pushgate_pam.py"
run install -m 0644 "$VALIDATION_SRC" "$VENV_DIR/config_validation.py"

if [ "$DRY_RUN" = 1 ]; then
  echo "DRY-RUN: write $CONFIG_DIR/pushgate.env"
else
  umask 077
  SERVER_CONFIG=$(printf '%s' "$SERVER" | python3 -I -c 'import json, sys; print(json.dumps(sys.stdin.read()))')
  CLIENT_ID_CONFIG=$(printf '%s' "$CLIENT_ID" | python3 -I -c 'import json, sys; print(json.dumps(sys.stdin.read()))')
  CLIENT_SECRET_CONFIG=$(printf '%s' "$CLIENT_SECRET" | python3 -I -c 'import json, sys; print(json.dumps(sys.stdin.read()))')
  APPROVER_USERNAME_CONFIG=$(printf '%s' "$APPROVER_USERNAME" | python3 -I -c 'import json, sys; print(json.dumps(sys.stdin.read()))')
  SYSTEM_NAME_CONFIG=$(printf '%s' "$SYSTEM_NAME" | python3 -I -c 'import json, sys; print(json.dumps(sys.stdin.read()))')
  CACHE_DIR_CONFIG=$(printf '%s' "$CACHE_DIR" | python3 -I -c 'import json, sys; print(json.dumps(sys.stdin.read()))')
  cat > "$CONFIG_DIR/pushgate.env" <<EOF
PUSHGATE_SERVER=$SERVER_CONFIG
PUSHGATE_CLIENT_ID=$CLIENT_ID_CONFIG
PUSHGATE_CLIENT_SECRET=$CLIENT_SECRET_CONFIG
PUSHGATE_APPROVER_USERNAME=$APPROVER_USERNAME_CONFIG
PUSHGATE_SYSTEM_NAME=$SYSTEM_NAME_CONFIG
PUSHGATE_CACHE_DIR=$CACHE_DIR_CONFIG
PUSHGATE_TIMEOUT=$TIMEOUT
PUSHGATE_CACHE_MAX_AGE=$CACHE_MAX_AGE
EOF
  chmod 600 "$CONFIG_DIR/pushgate.env"
fi

if [ "$DRY_RUN" = 1 ]; then
  echo "DRY-RUN: write $LIBEXEC_DIR/pushgate_pam using config $CONFIG_DIR/pushgate.env"
else
  cat > "$LIBEXEC_DIR/pushgate_pam" <<EOF
#!/bin/sh
exec /usr/bin/env -i \
  PUSHGATE_PAM_LAUNCHER=1 \
  PUSHGATE_PAM_CONFIG="$CONFIG_DIR/pushgate.env" \
  PAM_USER="\${PAM_USER-}" \
  PAM_SERVICE="\${PAM_SERVICE-}" \
  PAM_RHOST="\${PAM_RHOST-}" \
  PAM_RUSER="\${PAM_RUSER-}" \
  PAM_TTY="\${PAM_TTY-}" \
  PAM_TYPE="\${PAM_TYPE-}" \
  "$VENV_DIR/bin/python" -I "$VENV_DIR/pushgate_pam.py" "\$@"
EOF
  chmod 0755 "$LIBEXEC_DIR/pushgate_pam"
fi

echo "Installed PushGate PAM helper wrapper at $LIBEXEC_DIR/pushgate_pam"
echo "Keep a root break-glass shell open before adding deploy/pam.d snippets."
