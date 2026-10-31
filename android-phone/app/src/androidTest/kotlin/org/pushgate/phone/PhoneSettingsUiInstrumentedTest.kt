package org.pushgate.phone

import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.Density
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Settings > Debug logging renders as standard settings rows that stay inside the screen at any font size. */
@RunWith(AndroidJUnit4::class)
class PhoneSettingsUiInstrumentedTest {
    @get:Rule
    val compose = createComposeRule()

    private var loggingChanges = mutableListOf<Boolean>()
    private var retentionChanges = mutableListOf<Int>()
    private var shares = 0

    private fun actions(onLogging: (Boolean) -> Unit, onRetention: (Int) -> Unit) = PhoneUiActions(
        onServerUrlChange = {},
        onEnrollmentPayloadChange = {},
        onScanQr = {},
        onPastePayload = {},
        onEnroll = {},
        onRestartConnection = {},
        onReenroll = {},
        onClearEnrollment = {},
        onApprove = {},
        onDeny = {},
        onNavigate = {},
        onDebugLoggingChange = onLogging,
        onRetentionChange = onRetention,
        onShareLogs = { shares++ },
        onOpenNotificationSettings = {},
        onAllowBackground = {}
    )

    private fun show(fontScale: Float, loggingOn: Boolean, retentionDays: Int = 7) {
        compose.setContent {
            var panels by androidx.compose.runtime.remember {
                mutableStateOf(
                    PhonePanels(
                        debugLoggingEnabled = loggingOn,
                        retentionDays = retentionDays,
                        debugLogBytes = 2_048,
                        batteryUnrestricted = false,
                        appVersion = "0.1.9 (10)"
                    )
                )
            }
            val base = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(base.density, fontScale)) {
                PushGatePhoneApp(
                    state = PhoneUiState(
                        screen = PhoneScreen.Settings,
                        enrollment = null,
                        serverUrl = "",
                        enrollmentPayload = "",
                        statusMessage = "",
                        challenge = null,
                        isEnrolling = false,
                        isListening = false,
                        isDeciding = false,
                        decisionFeedback = null,
                        panels = panels
                    ),
                    actions = actions(
                        onLogging = { on ->
                            loggingChanges += on
                            panels = panels.copy(debugLoggingEnabled = on)
                        },
                        onRetention = { days ->
                            retentionChanges += days
                            panels = panels.copy(retentionDays = days)
                        }
                    )
                )
            }
        }
    }

    /** Scrolls [tag] into view, checks it lies inside the screen width, and returns its bounds. */
    private fun assertInsideScreen(tag: String): Rect {
        val rootWidth = compose.onRoot().fetchSemanticsNode().boundsInRoot.width
        val node = compose.onNodeWithTag(tag).performScrollTo().assertIsDisplayed().fetchSemanticsNode()
        val b = node.boundsInRoot
        assertTrue("$tag starts off screen: $b", b.left >= 0f)
        assertTrue("$tag runs past the right edge ($rootWidth): $b", b.right <= rootWidth)
        return b
    }

    private fun checkLayout(fontScale: Float) {
        show(fontScale, loggingOn = true)
        listOf("restart_button", "clear_enrollment_button").forEach { assertInsideScreen(it) }
        val switchRow = assertInsideScreen("debug_logging_switch")
        val pickerRow = assertInsideScreen("retention_row")
        val share = assertInsideScreen("share_log_button")
        compose.onNodeWithTag("retention_row").assert(
            SemanticsMatcher("shows the current value") { node ->
                node.config.getOrNull(SemanticsProperties.Text).orEmpty().map { it.text }.containsAll(listOf("Keep logs for", "7 days"))
            }
        )
        assertEquals("switch and picker rows share one left edge", switchRow.left, pickerRow.left, 0.5f)
        assertEquals("rows and Share log share one left edge", switchRow.left, share.left, 0.5f)
        assertEquals("rows and Share log share one right edge", switchRow.right, share.right, 0.5f)
    }

    @Test
    fun debugLoggingRowsFitAtDefaultFontSize() = checkLayout(1.0f)

    @Test
    fun debugLoggingRowsFitAtLargestFontSize() = checkLayout(2.0f)

    @Test
    fun wholeRowTogglesLoggingAndShareFollowsIt() {
        show(1.0f, loggingOn = false)
        compose.onNodeWithTag("debug_logging_switch").performScrollTo()
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.ToggleableState, ToggleableState.Off))
        compose.onNodeWithTag("share_log_button").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("Record debug log").performClick()
        assertEquals(listOf(true), loggingChanges)
        compose.onNodeWithTag("debug_logging_switch")
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.ToggleableState, ToggleableState.On))
        compose.onNodeWithTag("share_log_button").performScrollTo().assertIsEnabled().performClick()
        assertEquals(1, shares)
    }

    @Test
    fun retentionPickerOffersEveryChoiceAndSavesThePickedOne() {
        show(1.0f, loggingOn = true, retentionDays = 7)
        compose.onNodeWithTag("retention_row").performScrollTo().performClick()
        compose.onNodeWithTag("retention_dialog").assertIsDisplayed()
        DebugLogPolicy.RETENTION_CHOICES.forEach { days -> compose.onNodeWithTag("retention_$days").assertIsDisplayed() }
        compose.onNodeWithTag("retention_7").assertIsSelected()
        compose.onNodeWithTag("retention_30").performClick()
        assertEquals(listOf(30), retentionChanges)
        compose.onNodeWithTag("retention_dialog").assertDoesNotExist()
        compose.onNodeWithTag("retention_row").assert(
            SemanticsMatcher("shows 30 days") { node ->
                node.config.getOrNull(SemanticsProperties.Text).orEmpty().any { it.text == "30 days" }
            }
        )
    }
}
