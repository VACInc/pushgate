import java.io.ByteArrayOutputStream
import java.io.File
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

val releaseSigningProperties = Properties().apply {
    val propertiesFile = rootProject.file("keystore.properties")
    if (propertiesFile.isFile) propertiesFile.inputStream().use(::load)
}

fun releaseSigningValue(environmentName: String, propertyName: String): String? =
    System.getenv(environmentName)?.trim()?.takeIf { it.isNotEmpty() }
        ?: releaseSigningProperties.getProperty(propertyName)?.trim()?.takeIf { it.isNotEmpty() }

val releaseStoreFile = releaseSigningValue("PUSHGATE_ANDROID_SIGNING_STORE_FILE", "storeFile")
val releaseStorePassword = releaseSigningValue("PUSHGATE_ANDROID_SIGNING_STORE_PASSWORD", "storePassword")
val releaseKeyAlias = releaseSigningValue("PUSHGATE_ANDROID_SIGNING_KEY_ALIAS", "keyAlias")
val releaseKeyPassword = releaseSigningValue("PUSHGATE_ANDROID_SIGNING_KEY_PASSWORD", "keyPassword")
val releaseSigningValues = listOf(releaseStoreFile, releaseStorePassword, releaseKeyAlias, releaseKeyPassword)
val hasReleaseSigning = releaseSigningValues.all { it != null }
require(hasReleaseSigning || releaseSigningValues.all { it == null }) {
    "PushGate release signing is partially configured; provide all four signing values or none"
}

android {
    namespace = "org.pushgate.phone"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.pushgate.phone"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("boolean", "FCM_CONFIGURED", "false")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    if (hasReleaseSigning) {
        signingConfigs {
            create("release") {
                storeFile = rootProject.file(requireNotNull(releaseStoreFile))
                storePassword = requireNotNull(releaseStorePassword)
                keyAlias = requireNotNull(releaseKeyAlias)
                keyPassword = requireNotNull(releaseKeyPassword)
            }
        }
        buildTypes {
            getByName("release") {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }
}

dependencyLocking {
    lockAllConfigurations()
    lockMode = org.gradle.api.artifacts.dsl.LockMode.STRICT
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("org.bouncycastle:bcprov-jdk18on:1.85")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.google.firebase:firebase-messaging:25.1.0")
    implementation("org.unifiedpush.android:connector:2.5.0")
    implementation("com.google.android.gms:play-services-wearable:18.2.0")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("org.json:json:20240303")
    androidTestImplementation("junit:junit:4.13.2")
    androidTestImplementation(platform("androidx.compose:compose-bom:2024.12.01"))
    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
}

fun uninstallIfPresent(adb: File, serial: String, packageName: String) {
    val output = ByteArrayOutputStream()
    exec {
        isIgnoreExitValue = true
        commandLine(adb.absolutePath, "-s", serial, "uninstall", packageName)
        standardOutput = output
        errorOutput = output
    }
}

// Stale emulator installs signed by another key fail before instrumentation and report 0 tests.
tasks.matching { it.name == "connectedDebugAndroidTest" }.configureEach {
    doFirst {
        require(System.getenv("PUSHGATE_ALLOW_TEST_APP_UNINSTALL") == "1") {
            "connectedDebugAndroidTest uninstalls app data; run the emulator harness or explicitly set PUSHGATE_ALLOW_TEST_APP_UNINSTALL=1"
        }
        val serial = System.getenv("ANDROID_SERIAL")?.trim()?.takeIf { it.isNotEmpty() }
            ?: error("PUSHGATE_ALLOW_TEST_APP_UNINSTALL=1 requires an explicit ANDROID_SERIAL")
        require(Regex("""emulator-\d+""").matches(serial)) {
            "Refusing test-app uninstall on non-emulator serial: $serial"
        }
        val sdkRoot = System.getenv("ANDROID_SDK_ROOT")
            ?: System.getenv("ANDROID_HOME")
            ?: error("ANDROID_SDK_ROOT or ANDROID_HOME must be set to run connectedDebugAndroidTest")
        val adb = File(sdkRoot, "platform-tools/adb")
        require(adb.canExecute()) { "adb is not executable at ${adb.absolutePath}" }

        uninstallIfPresent(adb, serial, "org.pushgate.phone.test")
        uninstallIfPresent(adb, serial, "org.pushgate.phone")
    }
}
