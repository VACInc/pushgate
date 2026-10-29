#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
VM_NAME="${PUSHGATE_LIMA_VM:-pushgate-pam-smoke}"
TEMPLATE="${PUSHGATE_LIMA_TEMPLATE:-template:ubuntu-24.04}"

case "$VM_NAME" in
  pushgate-pam-smoke) ;;
  pushgate-pam-smoke-*)
    case "$VM_NAME" in
      *[!A-Za-z0-9_-]*)
        echo "Lima smoke VM names may contain only letters, digits, underscores, and hyphens" >&2
        exit 2
        ;;
    esac
    ;;
  *)
    echo "Refusing to modify non-smoke Lima VM: $VM_NAME" >&2
    exit 2
    ;;
esac

command -v limactl >/dev/null 2>&1 || {
  echo "limactl is required" >&2
  exit 1
}

if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -qx "$VM_NAME"; then
  limactl start \
    --tty=false \
    --name "$VM_NAME" \
    --cpus "${PUSHGATE_LIMA_CPUS:-2}" \
    --memory "${PUSHGATE_LIMA_MEMORY:-4}" \
    --disk "${PUSHGATE_LIMA_DISK:-20}" \
    --mount "$ROOT" \
    "$TEMPLATE"
else
  limactl start --tty=false "$VM_NAME" >/dev/null
fi

limactl shell --tty=false --workdir "$ROOT" "$VM_NAME" sudo bash -se <<EOF
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null
apt-get install -y --no-install-recommends \
  libpam-modules openssh-client openssh-server pamtester passwd python3 python3-pip python3-venv sshpass sudo util-linux >/dev/null

rm -rf /tmp/pushgate-pam-smoke-venv
rm -rf /tmp/pushgate-pam-smoke-src
mkdir -p /tmp/pushgate-pam-smoke-src
tar \
  --exclude .git \
  --exclude .venv \
  --exclude .pytest_cache \
  --exclude 'admin-web/node_modules' \
  --exclude 'android-phone/app/build' \
  --exclude 'android-wear/app/build' \
  -cf - -C "$ROOT" . | tar -xf - -C /tmp/pushgate-pam-smoke-src

python3 -I -m venv /tmp/pushgate-pam-smoke-venv
/tmp/pushgate-pam-smoke-venv/bin/python -I -m pip install --quiet --require-hashes --only-binary=:all: -r /tmp/pushgate-pam-smoke-src/requirements.lock
/tmp/pushgate-pam-smoke-venv/bin/python -I -m pip install --quiet --no-build-isolation --no-deps /tmp/pushgate-pam-smoke-src

cd /tmp/pushgate-pam-smoke-src
PUSHGATE_PAM_SMOKE_DISPOSABLE=1 \
  /tmp/pushgate-pam-smoke-venv/bin/python -I qa/pam_live_smoke.py
EOF

echo "Lima VM PAM smoke checks passed in $VM_NAME"
