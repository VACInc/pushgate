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
PHONE_SERIAL=emulator-5554
WEAR_SERIAL=emulator-5556

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

case "$PHONE_AVD" in
  pushgate_phone_*) ;;
  *) echo "Refusing non-smoke phone AVD: $PHONE_AVD" >&2; exit 2 ;;
esac
case "$WEAR_AVD" in
  pushgate_wear_*) ;;
  *) echo "Refusing non-smoke Wear AVD: $WEAR_AVD" >&2; exit 2 ;;
esac

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

if [ ! -x "$EMULATOR" ] || [ ! -x "$ADB" ]; then
  yes | "$SDKMANAGER" "emulator" "platform-tools" "platforms;android-35" \
    "$PHONE_IMAGE" "$WEAR_IMAGE"
fi

if ! "$AVDMANAGER" list avd | grep -q "Name: $PHONE_AVD"; then
  yes | "$SDKMANAGER" "platforms;android-35" "$PHONE_IMAGE"
  printf 'no\n' | "$AVDMANAGER" create avd --force --name "$PHONE_AVD" \
    --package "$PHONE_IMAGE" --device "$PHONE_DEVICE"
fi

if ! "$AVDMANAGER" list avd | grep -q "Name: $WEAR_AVD"; then
  yes | "$SDKMANAGER" "platforms;android-35" "$WEAR_IMAGE"
  printf 'no\n' | "$AVDMANAGER" create avd --force --name "$WEAR_AVD" \
    --package "$WEAR_IMAGE" --device "$WEAR_DEVICE"
fi

wait_boot() {
  serial="$1"
  "$ADB" -s "$serial" wait-for-device
  i=0
  while [ "$i" -lt 180 ]; do
    if [ "$("$ADB" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
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
    return 1
  fi
  "$EMULATOR" @"$avd" -port "$port" -no-snapshot -no-audio -no-boot-anim -no-window >/tmp/pushgate-$avd.log 2>&1 &
  return 0
}

started_phone=0
started_wear=0
if launch_emulator "$PHONE_AVD" 5554; then started_phone=1; fi
if launch_emulator "$WEAR_AVD" 5556; then started_wear=1; fi

cleanup() {
  if [ "${PUSHGATE_KEEP_EMULATORS:-0}" != "1" ]; then
    if [ "$started_phone" = "1" ]; then "$ADB" -s "$PHONE_SERIAL" emu kill >/dev/null 2>&1 || true; fi
    if [ "$started_wear" = "1" ]; then "$ADB" -s "$WEAR_SERIAL" emu kill >/dev/null 2>&1 || true; fi
  fi
}
trap cleanup EXIT INT TERM

wait_boot "$PHONE_SERIAL"
wait_boot "$WEAR_SERIAL"

PUSHGATE_ANDROID_BUILD_TYPE=debug \
PUSHGATE_SKIP_ANDROID_BUILD="${PUSHGATE_SKIP_ANDROID_BUILD:-0}" \
  "$ROOT/deploy/package-android-apks.sh"

"$ADB" -s "$PHONE_SERIAL" uninstall org.pushgate.phone >/dev/null 2>&1 || true
"$ADB" -s "$PHONE_SERIAL" install -r "$ROOT/dist/apks/pushgate-phone-debug.apk" >/dev/null
"$ADB" -s "$PHONE_SERIAL" shell pm grant org.pushgate.phone android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
"$ADB" -s "$PHONE_SERIAL" logcat -c
"$ADB" -s "$PHONE_SERIAL" shell am start -S -n org.pushgate.phone/.MainActivity >/dev/null
sleep 2
"$ADB" -s "$PHONE_SERIAL" shell uiautomator dump /sdcard/window.xml >/dev/null
"$ADB" -s "$PHONE_SERIAL" shell cat /sdcard/window.xml | grep -q 'text="PushGate"'
"$ADB" -s "$PHONE_SERIAL" logcat -d -t 500 | grep -q "FATAL EXCEPTION" && {
  echo "phone emulator reported a fatal exception" >&2
  exit 1
}

"$ADB" -s "$WEAR_SERIAL" uninstall org.pushgate.wear >/dev/null 2>&1 || true
"$ADB" -s "$WEAR_SERIAL" install -r "$ROOT/dist/apks/pushgate-wear-debug.apk" >/dev/null
"$ADB" -s "$WEAR_SERIAL" shell dumpsys battery unplug >/dev/null 2>&1 || true
"$ADB" -s "$WEAR_SERIAL" shell pm grant org.pushgate.wear android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
"$ADB" -s "$WEAR_SERIAL" logcat -c
"$ADB" -s "$WEAR_SERIAL" shell am start -S \
  -n org.pushgate.wear/org.pushgate.wear.MainActivity >/dev/null
sleep 2
"$ADB" -s "$WEAR_SERIAL" shell uiautomator dump /sdcard/window.xml >/dev/null
if ! "$ADB" -s "$WEAR_SERIAL" shell cat /sdcard/window.xml | grep -q 'text="PushGate"'; then
  "$ADB" -s "$WEAR_SERIAL" shell pidof org.pushgate.wear >/dev/null
fi
"$ADB" -s "$WEAR_SERIAL" logcat -d -t 500 | grep -q "FATAL EXCEPTION" && {
  echo "wear emulator reported a fatal exception" >&2
  exit 1
}

echo "Android emulator smoke checks passed"
