import java.io.ByteArrayOutputStream
import java.io.File
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.isFile) {
        keystorePropertiesFile.inputStream().use(::load)
    }
}

fun signingValue(environmentName: String, propertyName: String): String? =
    System.getenv(environmentName)?.takeIf(String::isNotBlank)
        ?: keystoreProperties.getProperty(propertyName)?.takeIf(String::isNotBlank)

val releaseStoreFile = signingValue("PUSHGATE_ANDROID_SIGNING_STORE_FILE", "storeFile")
val releaseStorePassword = signingValue("PUSHGATE_ANDROID_SIGNING_STORE_PASSWORD", "storePassword")
val releaseKeyAlias = signingValue("PUSHGATE_ANDROID_SIGNING_KEY_ALIAS", "keyAlias")
val releaseKeyPassword = signingValue("PUSHGATE_ANDROID_SIGNING_KEY_PASSWORD", "keyPassword")
val hasReleaseSigning = listOf(
    releaseStoreFile,
    releaseStorePassword,
    releaseKeyAlias,
    releaseKeyPassword
).all { !it.isNullOrBlank() }

android {
    namespace = "org.pushgate.wear"
    compileSdk = 35

    defaultConfig {
        // This deployed ID is an upgrade contract. Changing it strands enrollment preferences
        // and AndroidKeyStore entries in a second installed app.
        applicationId = "org.pushgate.wear"
        minSdk = 28
        targetSdk = 35
        versionCode = 2
        versionName = "1.0.2"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = rootProject.file(requireNotNull(releaseStoreFile))
                storePassword = requireNotNull(releaseStorePassword)
                keyAlias = requireNotNull(releaseKeyAlias)
                keyPassword = requireNotNull(releaseKeyPassword)
            }
        }
    }

    buildTypes {
        getByName("release") {
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
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
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.wear.compose:compose-foundation:1.4.1")
    implementation("androidx.wear.compose:compose-material:1.4.1")
    implementation("org.bouncycastle:bcprov-jdk18on:1.85")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
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

        uninstallIfPresent(adb, serial, "org.pushgate.wear.test")
        uninstallIfPresent(adb, serial, "org.pushgate.wear")
    }
}
