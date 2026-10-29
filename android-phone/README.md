# Android phone

Build with Java 17 and Android SDK 35: `./gradlew testDebugUnitTest assembleDebug`.
Dependencies use strict Gradle locks and verification metadata. No signing keys or Firebase configuration ship here.
Application ID is `org.pushgate.phone`. This public application is a new install; enroll it independently.
Phone and watch use independent enrollment and signed HTTPS/WebSocket decisions. Their distinct package IDs mean Wear Data Layer does not bridge these apps.
For a release build, supply your own ignored `keystore.properties` with `storeFile`, `storePassword`, `keyAlias`, `keyPassword`, then run `./gradlew assembleRelease`.
Without all signing fields, the release APK stays unsigned. Never distribute a debug-signed build for production.
Optional Firebase requires your own `app/google-services.json`; UnifiedPush requires an installed distributor and a server allowlist.
Release builds require HTTPS. Debug builds allow only emulator, loopback and example test host cleartext traffic.
