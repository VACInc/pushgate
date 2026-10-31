# Android phone

Build with Java 17 and Android SDK 35: `./gradlew testDebugUnitTest assembleDebug`.
Dependencies use strict Gradle locks and verification metadata. No signing keys or Firebase configuration ship here.
Application ID is `org.pushgate.phone`. This public application is a new install; enroll it independently.
Phone and watch use independent enrollment and signed HTTPS/WebSocket decisions. Their distinct package IDs mean Wear Data Layer does not bridge these apps.
For a release build, supply your own ignored `keystore.properties` with `storeFile`, `storePassword`, `keyAlias`, `keyPassword`, then run `./gradlew assembleRelease`.
Without all signing fields, the release APK stays unsigned. Never distribute a debug-signed build for production.
Optional Firebase requires your own `app/google-services.json`; UnifiedPush requires an installed distributor and a server allowlist.
Release builds require HTTPS. Debug builds allow only emulator, loopback and example test host cleartext traffic.

## Screens

The menu button (top left) opens a side menu with exactly three entries:

- **Home**: connection status, the live request card (Approve/Deny) when a request is waiting, and plain-English warnings about anything that stops requests from arriving while the app is closed. Home has no other buttons.
- **Settings**: Restart connection, Re-enroll, Clear enrollment (asks for confirmation first, because it unpairs the phone and deletes its approval key), background delivery checks (notification permission and channel, battery optimization, Android background restriction, the last time Android stopped the app), and Debug logging.
- **History**: requests this phone received, newest first: time, user, host, where the request came from, service, and the result (Approved, Denied, Timed out, Waiting, or decided on another device). History is stored only on the phone (30 days, at most 300 requests) and never shows request or device identifiers.

## Screenshots

Screenshots and screen recording work on Home, Settings, History and the approval screens; they show nothing secret. Only the enrollment QR scanner sets `FLAG_SECURE`, because its camera preview shows the one-time enrollment code. `ScreenCapturePolicyTest` enforces this.

## Background delivery and Android stopping the app

UnifiedPush and FCM wake the app with a broadcast. Android does not deliver that broadcast while the app is in the stopped state (after a force stop, or when the system or a battery manager puts it to sleep), nor after it crashed twice in the background within a minute; the request then never reaches the app until it is opened again, at which point the pending request is replayed over the WebSocket. The push receivers never let an exception escape, Settings offers "Allow background use" (battery optimization exemption), and on the next open the app reads Android's recorded exit reasons and says on Home when Android stopped it.

## Debug logging

Settings > Debug logging is off by default. When on, the app writes one log file per day under its private storage: process starts with Android's recorded reason for the previous exit, crashes with stack traces, push receipt, notification posting (with notification permission and channel state), approve/deny actions and connection changes. Logs are kept for 7 days by default ("Keep logs for" opens a picker: 1, 3, 7, 14 or 30 days) and older days are deleted automatically. "Share log" exports one text file through the Android share sheet. Turning logging off deletes every stored log immediately. Lines are scrubbed before they are written: URLs keep only scheme and host, tokens, signatures, keys and passwords are removed, and identifiers are shortened to their first 8 characters.
