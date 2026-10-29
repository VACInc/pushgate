#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"

find_sdk_root() {
  if [ -n "${ANDROID_SDK_ROOT:-}" ]; then
    printf '%s\n' "$ANDROID_SDK_ROOT"
    return
  fi
  if [ -n "${ANDROID_HOME:-}" ]; then
    printf '%s\n' "$ANDROID_HOME"
    return
  fi
  for candidate in "$HOME/android-sdk" "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" /opt/homebrew/share/android-commandlinetools; do
    if [ -d "$candidate" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  printf '%s\n' "$HOME/android-sdk"
}

SDK_ROOT="$(find_sdk_root)"
export ANDROID_HOME="$SDK_ROOT" ANDROID_SDK_ROOT="$SDK_ROOT"
if [ -z "${JAVA_HOME:-}" ] && [ -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
fi

ADB="${PUSHGATE_ADB:-$SDK_ROOT/platform-tools/adb}"
EMULATOR="${PUSHGATE_EMULATOR:-$SDK_ROOT/emulator/emulator}"
SDKMANAGER="${SDKMANAGER:-}"
AVDMANAGER="${AVDMANAGER:-}"
PHONE_AVD="${PUSHGATE_PHONE_AVD:-pushgate_phone_api35}"
WEAR_AVD="${PUSHGATE_WEAR_AVD:-pushgate_wear_api35}"
PHONE_SERIAL="${PUSHGATE_PHONE_SERIAL:-emulator-5554}"
WEAR_SERIAL="${PUSHGATE_WEAR_SERIAL:-emulator-5556}"

validate_emulator_serial() {
  serial="$1"
  case "$serial" in
    emulator-[0-9]*)
      port="${serial#emulator-}"
      case "$port" in
        ''|*[!0-9]*) ;;
        *) return 0 ;;
      esac
      ;;
  esac
  echo "Refusing Android instrumented tests on non-emulator serial: $serial" >&2
  exit 2
}

validate_emulator_serial "$PHONE_SERIAL"
validate_emulator_serial "$WEAR_SERIAL"
[ "$PHONE_SERIAL" != "$WEAR_SERIAL" ] || {
  echo "Phone and Wear emulator serials must be distinct" >&2
  exit 2
}
case "$PHONE_AVD" in
  pushgate_phone_*) ;;
  *) echo "Refusing non-smoke phone AVD: $PHONE_AVD" >&2; exit 2 ;;
esac
case "$WEAR_AVD" in
  pushgate_wear_*) ;;
  *) echo "Refusing non-smoke Wear AVD: $WEAR_AVD" >&2; exit 2 ;;
esac

PHONE_PORT="${PHONE_SERIAL#emulator-}"
WEAR_PORT="${WEAR_SERIAL#emulator-}"
case "$(uname -m)" in
  arm64|aarch64)
    DEFAULT_PHONE_IMAGE="system-images;android-35;google_apis;arm64-v8a"
    DEFAULT_WEAR_IMAGE="system-images;android-35-ext15;android-wear;arm64-v8a"
    ;;
  *)
    DEFAULT_PHONE_IMAGE="system-images;android-35;google_apis;x86_64"
    DEFAULT_WEAR_IMAGE="system-images;android-35;android-wear;x86_64"
    ;;
esac
PHONE_IMAGE="${PUSHGATE_PHONE_SYSTEM_IMAGE:-$DEFAULT_PHONE_IMAGE}"
WEAR_IMAGE="${PUSHGATE_WEAR_SYSTEM_IMAGE:-$DEFAULT_WEAR_IMAGE}"
PHONE_DEVICE="${PUSHGATE_PHONE_DEVICE:-pixel_6}"
WEAR_DEVICE="${PUSHGATE_WEAR_DEVICE:-wearos_large_round}"

if [ -z "$SDKMANAGER" ]; then
  for candidate in "$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" "$SDK_ROOT/tools/bin/sdkmanager"; do
    if [ -x "$candidate" ]; then
      SDKMANAGER="$candidate"
      break
    fi
  done
  SDKMANAGER="${SDKMANAGER:-sdkmanager}"
fi

if [ -z "$AVDMANAGER" ]; then
  for candidate in "$SDK_ROOT/cmdline-tools/latest/bin/avdmanager" "$SDK_ROOT/tools/bin/avdmanager"; do
    if [ -x "$candidate" ]; then
      AVDMANAGER="$candidate"
      break
    fi
  done
  AVDMANAGER="${AVDMANAGER:-avdmanager}"
fi

if [ ! -x "$ADB" ] || [ ! -x "$EMULATOR" ]; then
  yes | "$SDKMANAGER" "emulator" "platform-tools" "platforms;android-35" "$PHONE_IMAGE" "$WEAR_IMAGE"
fi

ensure_avd() {
  name="$1"
  image="$2"
  device="$3"
  if "$AVDMANAGER" list avd | grep -q "Name: $name"; then
    return
  fi
  yes | "$SDKMANAGER" "platforms;android-35" "$image"
  printf 'no\n' | "$AVDMANAGER" create avd --force --name "$name" --package "$image" --device "$device"
}

wait_boot() {
  serial="$1"
  "$ADB" -s "$serial" wait-for-device
  i=0
  while [ "$i" -lt 180 ]; do
    if [ "$("$ADB" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
      "$ADB" -s "$serial" shell wm dismiss-keyguard >/dev/null 2>&1 || true
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  echo "$serial did not boot" >&2
  return 1
}

launch_emulator() {
  avd="$1"
  port="$2"
  serial="emulator-$port"
  if "$ADB" devices | grep -q "^$serial[[:space:]]"; then
    running_avd="$("$ADB" -s "$serial" emu avd name 2>/dev/null | sed -n '1p' | tr -d '\r')"
    if [ "$running_avd" != "$avd" ]; then
      echo "Refusing to reuse $serial: expected AVD '$avd', found '$running_avd'" >&2
      exit 2
    fi
    echo "Reusing running $serial ($avd)"
    return 1
  fi
  echo "Launching $serial ($avd)"
  "$EMULATOR" @"$avd" -port "$port" -no-snapshot -no-audio -no-boot-anim -no-window \
    >/tmp/pushgate-$avd-androidtest.log 2>&1 &
  return 0
}

run_connected_tests() {
  project="$1"
  serial="$2"
  case "$serial" in
    emulator-[0-9]*)
      port="${serial#emulator-}"
      case "$port" in
        ''|*[!0-9]*)
          echo "Refusing test-app uninstall for invalid emulator serial: $serial" >&2
          return 1
          ;;
      esac
      ;;
    *)
      echo "Refusing test-app uninstall on non-emulator serial: $serial" >&2
      return 1
      ;;
  esac
  echo "Running $project connectedDebugAndroidTest on $serial"
  (
    cd "$ROOT/$project"
    if [ -n "${GRADLE:-}" ]; then
      PUSHGATE_ALLOW_TEST_APP_UNINSTALL=1 ANDROID_SERIAL="$serial" \
        "$GRADLE" --no-daemon connectedDebugAndroidTest
    else
      PUSHGATE_ALLOW_TEST_APP_UNINSTALL=1 ANDROID_SERIAL="$serial" \
        ./gradlew --no-daemon connectedDebugAndroidTest
    fi
  )
}

ensure_avd "$PHONE_AVD" "$PHONE_IMAGE" "$PHONE_DEVICE"
ensure_avd "$WEAR_AVD" "$WEAR_IMAGE" "$WEAR_DEVICE"

started_phone=0
started_wear=0
if launch_emulator "$PHONE_AVD" "$PHONE_PORT"; then started_phone=1; fi
if launch_emulator "$WEAR_AVD" "$WEAR_PORT"; then started_wear=1; fi

cleanup() {
  if [ "${PUSHGATE_KEEP_EMULATORS:-0}" != "1" ]; then
    if [ "$started_phone" = "1" ]; then "$ADB" -s "$PHONE_SERIAL" emu kill >/dev/null 2>&1 || true; fi
    if [ "$started_wear" = "1" ]; then "$ADB" -s "$WEAR_SERIAL" emu kill >/dev/null 2>&1 || true; fi
  fi
}
trap cleanup EXIT INT TERM

wait_boot "$PHONE_SERIAL"
wait_boot "$WEAR_SERIAL"
"$ADB" -s "$WEAR_SERIAL" shell dumpsys battery unplug >/dev/null 2>&1 || true

run_connected_tests android-phone "$PHONE_SERIAL"
run_connected_tests android-wear "$WEAR_SERIAL"

echo "Android instrumented tests passed"
