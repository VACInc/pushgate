package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Screenshots and screen recording are allowed everywhere except the enrollment QR scanner,
 * whose camera preview shows the one-time enrollment code. Home, Settings, History and the
 * approval screens show nothing secret, so they must not set FLAG_SECURE.
 */
class ScreenCapturePolicyTest {
    private val sourceRoot = File("src/main/kotlin/org/pushgate/phone")

    private fun source(name: String) = File(sourceRoot, name).readText()

    @Test
    fun onlyTheQrScannerBlocksScreenCapture() {
        assertTrue("run from the android-phone/app module directory", sourceRoot.isDirectory)
        val securing = sourceRoot.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filter { "FLAG_SECURE" in it.readText() || "setRecentsScreenshotEnabled" in it.readText() }
            .map { it.name }
            .toSortedSet()
        assertEquals(sortedSetOf("QrCaptureActivity.kt"), securing)
    }

    @Test
    fun qrScannerSetsFlagSecureOnItsWindow() {
        assertTrue(source("QrCaptureActivity.kt").contains("window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)"))
    }

    @Test
    fun appAndApprovalScreensAllowScreenshots() {
        listOf("MainActivity.kt", "NotificationDecisionActivity.kt").forEach { name ->
            val text = source(name)
            assertTrue("$name must not block screenshots", "FLAG_SECURE" !in text && "setRecentsScreenshotEnabled" !in text)
        }
    }

    @Test
    fun manifestActivitiesAreTheOnesChecked() {
        val manifest = File("src/main/AndroidManifest.xml").readText()
        val activities = Regex("""<activity[^>]*android:name="\.?([A-Za-z]+)"""").findAll(manifest).map { it.groupValues[1] }.toSet()
        assertEquals(setOf("MainActivity", "NotificationDecisionActivity", "QrCaptureActivity"), activities)
    }
}
