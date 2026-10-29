#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
IMAGE="${PUSHGATE_PAM_SMOKE_IMAGE:-python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de}"

docker run --rm \
  -v "$ROOT:/workspace:ro" \
  -w /workspace \
  "$IMAGE" \
  sh -lc '
    set -eu
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends \
      libpam-modules openssh-client openssh-server pamtester passwd sshpass sudo util-linux >/dev/null
    PIP_DISABLE_PIP_VERSION_CHECK=1 python -m pip install --quiet --root-user-action=ignore \
      --require-hashes --only-binary=:all: -r /workspace/requirements.lock

    sh /workspace/pam/install.sh \
      --server http://127.0.0.1:9 \
      --client-id smoke \
      --client-secret smoke \
      --system-name pushgate-smoke \
      --timeout 1 \
      --cache-max-age 86400 >/dev/null

    config_metadata="$(stat -c "%u:%g:%a" /etc/pushgate/pushgate.env)"
    cache_metadata="$(stat -c "%u:%g:%a" /etc/pushgate/failmode.d)"
    wrapper_metadata="$(stat -c "%u:%g:%a" /usr/local/libexec/pushgate_pam)"
    [ "$config_metadata" = "0:0:600" ] || { echo "insecure PushGate config metadata: $config_metadata" >&2; exit 1; }
    [ "$cache_metadata" = "0:0:700" ] || { echo "insecure PushGate cache metadata: $cache_metadata" >&2; exit 1; }
    [ "$wrapper_metadata" = "0:0:755" ] || { echo "insecure PushGate wrapper metadata: $wrapper_metadata" >&2; exit 1; }

    /opt/pushgate-pam/bin/python -I - <<PY
import importlib.util

spec = importlib.util.spec_from_file_location("pushgate_pam", "/opt/pushgate-pam/pushgate_pam.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

cache_dir = "/etc/pushgate/failmode.d"

def cache(username, fail_mode, backup_codes=()):
    module.write_cache(
        cache_dir,
        username,
        {
            "username": username,
            "fail_mode": fail_mode,
            "backup_code_hashes": [module.hash_value(code) for code in backup_codes],
            "binding": {
                "server": "http://127.0.0.1:9",
                "client_id": "smoke",
                "username": username,
                "approver_username": username,
                "system": "pushgate-smoke",
            },
        },
    )

cache("openuser", "open")
cache("closeduser", "closed")
cache("backupuser", "closed", ("ABCD1234", "WXYZ5678"))
PY

    cat >/etc/pam.d/pushgate-test <<EOF
auth required pam_exec.so expose_authtok seteuid /usr/local/libexec/pushgate_pam
account required pam_permit.so
EOF

    pamtester pushgate-test openuser authenticate >/dev/null 2>&1
    if pamtester pushgate-test closeduser authenticate >/dev/null 2>&1; then
      echo "closed user unexpectedly passed" >&2
      exit 1
    fi
    printf "ABCD1234\n" | pamtester pushgate-test backupuser authenticate >/dev/null 2>&1
    if printf "ABCD1234\n" | pamtester pushgate-test backupuser authenticate >/dev/null 2>&1; then
      echo "backup code unexpectedly reused" >&2
      exit 1
    fi
    printf "WXYZ5678\n" | pamtester pushgate-test backupuser authenticate >/dev/null 2>&1
    if printf "WXYZ5678\n" | pamtester pushgate-test backupuser authenticate >/dev/null 2>&1; then
      echo "stdin backup code unexpectedly reused" >&2
      exit 1
    fi
    PUSHGATE_PAM_SMOKE_DISPOSABLE=1 python -I /workspace/qa/pam_live_smoke.py
    echo "Linux PAM smoke checks passed"
  '
