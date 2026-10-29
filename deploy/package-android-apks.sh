#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
OUT="${PUSHGATE_APK_OUT:-$ROOT/dist/apks}"
BUILD_TYPE="${PUSHGATE_ANDROID_BUILD_TYPE:-debug}"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"

find_sdk_tool() {
  tool_name="$1"
  configured_path="$2"

  if [ -n "$configured_path" ]; then
    if [ ! -x "$configured_path" ]; then
      echo "$tool_name is not executable: $configured_path" >&2
      return 1
    fi
    printf '%s\n' "$configured_path"
    return
  fi
  if command -v "$tool_name" >/dev/null 2>&1; then
    command -v "$tool_name"
    return
  fi
  if [ -n "$SDK_ROOT" ]; then
    found="$(
      find "$SDK_ROOT" -type f -name "$tool_name" -perm -u+x 2>/dev/null |
        LC_ALL=C awk '
          function without_leading_zeroes(value) {
            sub(/^0+/, "", value)
            return value == "" ? "0" : value
          }

          function naturally_after(left, right, left_is_number, right_is_number,
                                   left_token, right_token, left_value, right_value) {
            while (left != "" || right != "") {
              if (left == "") return 0
              if (right == "") return 1

              left_is_number = substr(left, 1, 1) ~ /[0-9]/
              right_is_number = substr(right, 1, 1) ~ /[0-9]/
              if (left_is_number) match(left, /^[0-9]+/)
              else match(left, /^[^0-9]+/)
              left_token = substr(left, 1, RLENGTH)
              left = substr(left, RLENGTH + 1)
              if (right_is_number) match(right, /^[0-9]+/)
              else match(right, /^[^0-9]+/)
              right_token = substr(right, 1, RLENGTH)
              right = substr(right, RLENGTH + 1)

              if (left_is_number && right_is_number) {
                left_value = without_leading_zeroes(left_token)
                right_value = without_leading_zeroes(right_token)
                if (length(left_value) != length(right_value))
                  return length(left_value) > length(right_value)
                if (left_value != right_value)
                  return ("x" left_value) > ("x" right_value)
              } else if (left_token != right_token) {
                return ("x" left_token) > ("x" right_token)
              }
            }
            return 0
          }

          !found || naturally_after($0, latest) {
            latest = $0
            found = 1
          }

          END {
            if (found) print latest
          }
        '
    )"
    if [ -n "$found" ]; then
      printf '%s\n' "$found"
      return
    fi
  fi
  echo "$tool_name is required for release APK verification" >&2
  return 1
}

verify_release_apk() {
  apk="$1"
  expected_package="$2"
  expected_cert="$3"

  "$APKSIGNER" verify --verbose "$apk" >/dev/null
  debuggable="$("$APKANALYZER" manifest debuggable "$apk" | tr -d '\r\n')"
  if [ "$debuggable" != "false" ]; then
    echo "Refusing debuggable release APK: $apk" >&2
    return 1
  fi
  application_id="$("$APKANALYZER" manifest application-id "$apk" | tr -d '\r\n')"
  if [ "$application_id" != "$expected_package" ]; then
    echo "Unexpected application ID in $apk: $application_id" >&2
    return 1
  fi

  actual_cert="$("$APKSIGNER" verify --print-certs "$apk" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -n 1)"
  normalized_actual="$(printf '%s' "$actual_cert" | tr -d ':[:space:]' | tr '[:lower:]' '[:upper:]')"
  if [ -z "$normalized_actual" ]; then
    echo "Unable to read release APK signing certificate: $apk" >&2
    return 1
  fi

  normalized_expected="$(printf '%s' "$expected_cert" | tr -d ':[:space:]' | tr '[:lower:]' '[:upper:]')"
  if [ -n "$normalized_expected" ] && [ "$normalized_actual" != "$normalized_expected" ]; then
    echo "Release APK signer does not match its configured certificate digest: $apk" >&2
    return 1
  fi

  printf '%s\n' "$normalized_actual"
}

case "$BUILD_TYPE" in
  debug|release) ;;
  *)
    echo "PUSHGATE_ANDROID_BUILD_TYPE must be debug or release" >&2
    exit 2
    ;;
esac

if command -v shasum >/dev/null 2>&1; then
  CHECKSUM_TOOL=shasum
elif command -v sha256sum >/dev/null 2>&1; then
  CHECKSUM_TOOL=sha256sum
else
  echo "shasum or sha256sum is required to package APK checksums" >&2
  exit 1
fi

if [ "${PUSHGATE_SKIP_ANDROID_BUILD:-0}" != "1" ]; then
  PUSHGATE_ANDROID_BUILD_TYPE="$BUILD_TYPE" "$ROOT/deploy/android-build.sh"
fi

mkdir -p "$OUT"

if [ "$BUILD_TYPE" = "debug" ]; then
  echo "WARNING: packaging debuggable APKs for development and emulator testing only." >&2
  PHONE_SOURCE="$ROOT/android-phone/app/build/outputs/apk/debug/app-debug.apk"
  WEAR_SOURCE="$ROOT/android-wear/app/build/outputs/apk/debug/app-debug.apk"
  PHONE_OUTPUT="pushgate-phone-debug.apk"
  WEAR_OUTPUT="pushgate-wear-debug.apk"
  PACKAGE_HEADING="PushGate debug APKs, for development and emulator testing only"
else
  PHONE_SOURCE="${PUSHGATE_PHONE_RELEASE_APK:-$ROOT/android-phone/app/build/outputs/apk/release/app-release.apk}"
  WEAR_SOURCE="${PUSHGATE_WEAR_RELEASE_APK:-$ROOT/android-wear/app/build/outputs/apk/release/app-release.apk}"
  PHONE_OUTPUT="pushgate-phone-release.apk"
  WEAR_OUTPUT="pushgate-wear-release.apk"
  PACKAGE_HEADING="PushGate verified signed release APKs"
  for apk in "$PHONE_SOURCE" "$WEAR_SOURCE"; do
    if [ ! -f "$apk" ]; then
      echo "Signed release APK not found: $apk" >&2
      echo "Configure Gradle release signing or set PUSHGATE_PHONE_RELEASE_APK and PUSHGATE_WEAR_RELEASE_APK." >&2
      exit 1
    fi
  done
  APKSIGNER="$(find_sdk_tool apksigner "${PUSHGATE_APKSIGNER:-}")"
  APKANALYZER="$(find_sdk_tool apkanalyzer "${PUSHGATE_APKANALYZER:-}")"
  PHONE_EXPECTED_CERT="${PUSHGATE_PHONE_SIGNING_CERT_SHA256:-${PUSHGATE_SIGNING_CERT_SHA256:-}}"
  WEAR_EXPECTED_CERT="${PUSHGATE_WEAR_SIGNING_CERT_SHA256:-${PUSHGATE_SIGNING_CERT_SHA256:-}}"
  verify_release_apk \
    "$PHONE_SOURCE" org.pushgate.phone "$PHONE_EXPECTED_CERT" >/dev/null
  verify_release_apk \
    "$WEAR_SOURCE" org.pushgate.wear "$WEAR_EXPECTED_CERT" >/dev/null
fi

cp "$PHONE_SOURCE" "$OUT/$PHONE_OUTPUT"
cp "$WEAR_SOURCE" "$OUT/$WEAR_OUTPUT"

(
  cd "$OUT"
  if [ "$CHECKSUM_TOOL" = shasum ]; then
    shasum -a 256 "$PHONE_OUTPUT" "$WEAR_OUTPUT" > SHA256SUMS
  else
    sha256sum "$PHONE_OUTPUT" "$WEAR_OUTPUT" > SHA256SUMS
  fi
)

cat > "$OUT/INSTALL.txt" <<EOF
$PACKAGE_HEADING

Phone:
  adb install -r "$OUT/$PHONE_OUTPUT"

Wear OS (upgrades org.pushgate.wear):
  adb -s <wear-serial> install -r "$OUT/$WEAR_OUTPUT"

List devices:
  adb devices

Helper script:
  PUSHGATE_ANDROID_BUILD_TYPE=$BUILD_TYPE deploy/install-android-apks.sh phone [phone-serial]
  PUSHGATE_ANDROID_BUILD_TYPE=$BUILD_TYPE deploy/install-android-apks.sh wear [wear-serial]
  PUSHGATE_ANDROID_BUILD_TYPE=$BUILD_TYPE deploy/install-android-apks.sh both <phone-serial> <wear-serial>
EOF

echo "Packaged APKs in $OUT"
ls -lh "$OUT"
