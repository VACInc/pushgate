#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
APK_DIR="${PUSHGATE_APK_OUT:-$ROOT/dist/apks}"
ADB="${ADB:-adb}"
BUILD_TYPE="${PUSHGATE_ANDROID_BUILD_TYPE:-debug}"

case "$BUILD_TYPE" in
  debug|release) ;;
  *)
    echo "PUSHGATE_ANDROID_BUILD_TYPE must be debug or release" >&2
    exit 2
    ;;
esac

PHONE_APK="$APK_DIR/pushgate-phone-$BUILD_TYPE.apk"
WEAR_APK="$APK_DIR/pushgate-wear-$BUILD_TYPE.apk"

if [ "$BUILD_TYPE" = "debug" ]; then
  echo "WARNING: installing development-only debuggable APKs." >&2
fi

usage() {
  cat <<EOF
Usage:
  PUSHGATE_ANDROID_BUILD_TYPE=debug|release \
  deploy/install-android-apks.sh phone [phone-serial]
  deploy/install-android-apks.sh wear [wear-serial]
  deploy/install-android-apks.sh both <phone-serial> <wear-serial>
EOF
}

install_one() {
  serial="$1"
  apk="$2"
  if [ -n "$serial" ]; then
    "$ADB" -s "$serial" install -r "$apk"
  else
    "$ADB" install -r "$apk"
  fi
}

if ! command -v "$ADB" >/dev/null 2>&1; then
  echo "adb not found. Install Android platform-tools or set ADB=/path/to/adb." >&2
  exit 1
fi

if [ ! -f "$PHONE_APK" ] || [ ! -f "$WEAR_APK" ]; then
  PUSHGATE_ANDROID_BUILD_TYPE="$BUILD_TYPE" "$ROOT/deploy/package-android-apks.sh"
fi

target="${1:-}"
case "$target" in
  phone)
    install_one "${2:-}" "$PHONE_APK"
    ;;
  wear)
    install_one "${2:-}" "$WEAR_APK"
    ;;
  both)
    if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
      usage
      exit 2
    fi
    install_one "$2" "$PHONE_APK"
    install_one "$3" "$WEAR_APK"
    ;;
  *)
    usage
    exit 2
    ;;
esac
