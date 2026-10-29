#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
IMAGE="${PUSHGATE_ANDROID_BUILD_IMAGE:-ghcr.io/cirruslabs/android-sdk:35@sha256:c724009e305b4607157287624033ab97f319af44c244bfc9f73b6293f3bb01b9}"
PLATFORM="${PUSHGATE_ANDROID_BUILD_PLATFORM:-linux/amd64}"
BUILD_TYPE="${PUSHGATE_ANDROID_BUILD_TYPE:-debug}"

case "$BUILD_TYPE" in
  debug)
    TEST_TASK=testDebugUnitTest
    ASSEMBLE_TASK=assembleDebug
    ;;
  release)
    TEST_TASK=testReleaseUnitTest
    ASSEMBLE_TASK=assembleRelease
    ;;
  *)
    echo "PUSHGATE_ANDROID_BUILD_TYPE must be debug or release" >&2
    exit 2
    ;;
esac

set -- docker run --rm \
  --platform "$PLATFORM" \
  -e TEST_TASK="$TEST_TASK" \
  -e ASSEMBLE_TASK="$ASSEMBLE_TASK"

SIGNING_STORE_FILE="${PUSHGATE_ANDROID_SIGNING_STORE_FILE:-}"
if [ -n "$SIGNING_STORE_FILE" ]; then
  if [ ! -f "$SIGNING_STORE_FILE" ]; then
    echo "PUSHGATE_ANDROID_SIGNING_STORE_FILE is not a file: $SIGNING_STORE_FILE" >&2
    exit 1
  fi
  if [ -L "$SIGNING_STORE_FILE" ]; then
    echo "PUSHGATE_ANDROID_SIGNING_STORE_FILE must not be a symlink" >&2
    exit 1
  fi
  if SIGNING_STORE_MODE="$(stat -c %a -- "$SIGNING_STORE_FILE" 2>/dev/null)"; then
    :
  elif SIGNING_STORE_MODE="$(stat -f %Lp "$SIGNING_STORE_FILE" 2>/dev/null)"; then
    :
  else
    echo "Cannot inspect Android signing store permissions" >&2
    exit 1
  fi
  case "$SIGNING_STORE_MODE" in
    *[!0-7]*) echo "Cannot validate Android signing store permissions" >&2; exit 1 ;;
  esac
  if [ $((0$SIGNING_STORE_MODE & 077)) -ne 0 ]; then
    echo "Android signing store must not grant group or world permissions" >&2
    exit 1
  fi
  SIGNING_STORE_NAME=${SIGNING_STORE_FILE##*/}
  SIGNING_STORE_DIR=${SIGNING_STORE_FILE%/*}
  if [ "$SIGNING_STORE_DIR" = "$SIGNING_STORE_FILE" ]; then
    SIGNING_STORE_DIR=.
  elif [ -z "$SIGNING_STORE_DIR" ]; then
    SIGNING_STORE_DIR=/
  fi
  SIGNING_STORE_FILE="$(CDPATH= cd -- "$SIGNING_STORE_DIR" && pwd -P)/$SIGNING_STORE_NAME"
  set -- "$@" \
    -v "$SIGNING_STORE_FILE:/run/secrets/pushgate-android-keystore:ro" \
    -e PUSHGATE_ANDROID_SIGNING_STORE_FILE=/run/secrets/pushgate-android-keystore
else
  set -- "$@" -e PUSHGATE_ANDROID_SIGNING_STORE_FILE
fi

if [ "$BUILD_TYPE" = release ]; then
  if [ -z "$SIGNING_STORE_FILE" ] ||
     [ -z "${PUSHGATE_ANDROID_SIGNING_STORE_PASSWORD:-}" ] ||
     [ -z "${PUSHGATE_ANDROID_SIGNING_KEY_ALIAS:-}" ] ||
     [ -z "${PUSHGATE_ANDROID_SIGNING_KEY_PASSWORD:-}" ]; then
    echo "Release builds require the signing store and all three signing credential variables" >&2
    exit 2
  fi
fi

set -- "$@" \
  -e PUSHGATE_ANDROID_SIGNING_STORE_PASSWORD \
  -e PUSHGATE_ANDROID_SIGNING_KEY_ALIAS \
  -e PUSHGATE_ANDROID_SIGNING_KEY_PASSWORD \
  -v "$ROOT:/workspace" \
  -w /workspace \
  "$IMAGE" \
  sh -lc '
    set -eu
    for project in android-phone android-wear; do
      cd "/workspace/$project"
      ./gradlew --no-daemon "$TEST_TASK" "$ASSEMBLE_TASK"
    done
  '

"$@"
