package org.pushgate.wear

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.wear.compose.material.Chip
import androidx.wear.compose.material.ChipDefaults
import androidx.wear.compose.material.Colors
import androidx.wear.compose.material.Icon
import androidx.wear.compose.material.MaterialTheme
import androidx.wear.compose.material.OutlinedChip
import androidx.wear.compose.material.PositionIndicator
import androidx.wear.compose.material.Scaffold
import androidx.wear.compose.material.ScalingLazyColumn
import androidx.wear.compose.material.ScalingLazyListScope
import androidx.wear.compose.material.Text
import androidx.wear.compose.material.TimeText
import androidx.wear.compose.material.Vignette
import androidx.wear.compose.material.VignettePosition
import androidx.wear.compose.material.rememberScalingLazyListState
import kotlinx.coroutines.delay
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlin.math.roundToInt

enum class WearScreen {
    Enrollment,
    Home,
    Settings
}

enum class WearDecisionFeedbackKind {
    Approved,
    Denied
}

data class WearDecisionFeedback(
    val kind: WearDecisionFeedbackKind,
    val username: String,
    val service: String,
    val system: String
)

data class WearUiState(
    val screen: WearScreen,
    val enrollment: WearEnrollment?,
    val serverUrl: String,
    val enrollmentPayload: String,
    val challengePayload: String,
    val statusMessage: String,
    val challenge: WearChallenge?,
    val isEnrolling: Boolean,
    val isListening: Boolean,
    val isDeciding: Boolean,
    val decisionFeedback: WearDecisionFeedback?
)

private val WearPrimary = Color(0xFF9B8CFF)
private val WearApprove = Color(0xFF34D399)
private val WearDeny = Color(0xFFFB7185)
private val WearBackground = Color(0xFF05070C)
private val WearSurface = Color(0xFF11141D)
private val WearText = Color(0xFFF4F2FF)
private val WearMuted = Color(0xFFB8B6C8)

private val PushGateWearColors = Colors(
    primary = WearPrimary,
    primaryVariant = Color(0xFF7C6CFF),
    secondary = WearApprove,
    secondaryVariant = Color(0xFF1EA672),
    background = WearBackground,
    surface = WearSurface,
    error = WearDeny,
    onPrimary = Color(0xFF120F2E),
    onSecondary = Color(0xFF032217),
    onBackground = WearText,
    onSurface = WearText,
    onError = Color(0xFF3A0712)
)

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun PushGateWearApp(
    state: WearUiState,
    onServerUrlChange: (String) -> Unit,
    onEnrollmentPayloadChange: (String) -> Unit,
    onChallengePayloadChange: (String) -> Unit,
    onScanQr: () -> Unit,
    onPastePayload: () -> Unit,
    onEnroll: () -> Unit,
    onLoadChallenge: () -> Unit,
    onStartListening: () -> Unit,
    onClearEnrollment: () -> Unit,
    onApprove: () -> Unit,
    onDeny: () -> Unit,
    onOpenHome: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenEnrollment: () -> Unit
) {
    PushGateWearTheme {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colors.background)
                .semantics { testTagsAsResourceId = true }
        ) {
            when {
                state.challenge != null -> WearChallengeScreen(
                    state = state,
                    challenge = state.challenge,
                    onApprove = onApprove,
                    onDeny = onDeny
                )

                state.enrollment == null || state.screen == WearScreen.Enrollment -> WearEnrollmentScreen(
                    state = state,
                    onServerUrlChange = onServerUrlChange,
                    onEnrollmentPayloadChange = onEnrollmentPayloadChange,
                    onChallengePayloadChange = onChallengePayloadChange,
                    onScanQr = onScanQr,
                    onPastePayload = onPastePayload,
                    onEnroll = onEnroll,
                    onLoadChallenge = onLoadChallenge
                )

                state.screen == WearScreen.Settings -> WearSettingsScreen(
                    state = state,
                    onClearEnrollment = onClearEnrollment,
                    onOpenEnrollment = onOpenEnrollment,
                    onOpenHome = onOpenHome
                )

                else -> WearHomeScreen(
                    state = state,
                    onStartListening = onStartListening,
                    onOpenSettings = onOpenSettings
                )
            }
        }
    }
}

@Composable
internal fun PushGateWearTheme(content: @Composable () -> Unit) {
    MaterialTheme(colors = PushGateWearColors, content = content)
}

@Composable
private fun WearFrame(content: ScalingLazyListScope.() -> Unit) {
    val listState = rememberScalingLazyListState()
    Scaffold(
        timeText = { TimeText() },
        vignette = { Vignette(vignettePosition = VignettePosition.TopAndBottom) },
        positionIndicator = { PositionIndicator(scalingLazyListState = listState) }
    ) {
        ScalingLazyColumn(
            modifier = Modifier.fillMaxSize(),
            state = listState,
            contentPadding = PaddingValues(top = 34.dp, bottom = 28.dp, start = 10.dp, end = 10.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
            content = content
        )
    }
}

@Composable
private fun WearChallengeFrame(
    actionBar: @Composable BoxScope.() -> Unit,
    content: ScalingLazyListScope.() -> Unit
) {
    val listState = rememberScalingLazyListState()
    Scaffold(
        timeText = { TimeText() },
        vignette = { Vignette(vignettePosition = VignettePosition.TopAndBottom) }
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colors.background)
        ) {
            ScalingLazyColumn(
                modifier = Modifier.fillMaxSize(),
                state = listState,
                contentPadding = PaddingValues(top = 34.dp, bottom = 106.dp, start = 10.dp, end = 10.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp),
                content = content
            )
            actionBar()
        }
    }
}

@Composable
private fun BoxScope.WearDecisionActions(
    enabled: Boolean,
    onApprove: () -> Unit,
    onDeny: () -> Unit
) {
    Row(
        modifier = Modifier
            .align(Alignment.BottomCenter)
            .fillMaxWidth()
            .padding(start = 18.dp, end = 18.dp, bottom = 34.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        WearDecisionChip(
            modifier = Modifier.weight(1f),
            label = "Approve",
            tag = "wear_approve_button",
            description = "Approve",
            enabled = enabled,
            background = WearApprove,
            contentColor = Color(0xFF032217),
            icon = { Icon(Icons.Rounded.CheckCircle, contentDescription = null) },
            onClick = onApprove
        )
        WearDecisionChip(
            modifier = Modifier.weight(1f),
            label = "Deny",
            tag = "wear_deny_button",
            description = "Deny",
            enabled = enabled,
            background = WearDeny,
            contentColor = Color(0xFF3A0712),
            icon = { Icon(Icons.Rounded.Close, contentDescription = null) },
            onClick = onDeny
        )
    }
}

@Composable
private fun WearDecisionChip(
    modifier: Modifier,
    label: String,
    tag: String,
    description: String,
    enabled: Boolean,
    background: Color,
    contentColor: Color,
    icon: @Composable BoxScope.() -> Unit,
    onClick: () -> Unit
) {
    Chip(
        modifier = modifier
            .height(52.dp)
            .testTag(tag)
            .semantics { contentDescription = description },
        onClick = onClick,
        enabled = enabled,
        colors = ChipDefaults.chipColors(
            backgroundColor = background,
            contentColor = contentColor,
            secondaryContentColor = contentColor,
            iconColor = contentColor
        ),
        label = {
            Text(
                text = label,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        },
        icon = icon
    )
}

@Composable
private fun WearEnrollmentScreen(
    state: WearUiState,
    onServerUrlChange: (String) -> Unit,
    onEnrollmentPayloadChange: (String) -> Unit,
    onChallengePayloadChange: (String) -> Unit,
    onScanQr: () -> Unit,
    onPastePayload: () -> Unit,
    onEnroll: () -> Unit,
    onLoadChallenge: () -> Unit
) {
    WearFrame {
        item { WearHeader(title = "PushGate", subtitle = "Enroll this watch") }
        item {
            WearTextField(
                label = "Server URL",
                value = state.serverUrl,
                onValueChange = onServerUrlChange,
                singleLine = true,
                keyboardType = KeyboardType.Uri,
                tag = "wear_server_url_field"
            )
        }
        item {
            WearTextField(
                label = "Enrollment payload",
                value = state.enrollmentPayload,
                onValueChange = onEnrollmentPayloadChange,
                singleLine = false,
                tag = "wear_enrollment_payload_field"
            )
        }
        item {
            WearPrimaryChip(
                label = "Scan QR",
                icon = { Icon(Icons.Rounded.QrCodeScanner, contentDescription = null) },
                tag = "wear_scan_qr_button",
                onClick = onScanQr
            )
        }
        item {
            WearSecondaryChip(
                label = "Paste",
                icon = { Icon(Icons.Rounded.ContentPaste, contentDescription = null) },
                tag = "wear_paste_payload_button",
                onClick = onPastePayload
            )
        }
        item {
            WearPrimaryChip(
                label = if (state.isEnrolling) "Enrolling..." else "Enroll watch",
                icon = { Icon(Icons.Rounded.VerifiedUser, contentDescription = null) },
                enabled = !state.isEnrolling,
                tag = "wear_enroll_button",
                onClick = onEnroll
            )
        }
        item {
            WearTextField(
                label = "Challenge JSON",
                value = state.challengePayload,
                onValueChange = onChallengePayloadChange,
                singleLine = false,
                tag = "wear_challenge_payload_field"
            )
        }
        item {
            WearSecondaryChip(
                label = "Load challenge",
                icon = { Icon(Icons.Rounded.Refresh, contentDescription = null) },
                tag = "wear_load_challenge_button",
                onClick = onLoadChallenge
            )
        }
        item { WearStatus(state.statusMessage) }
    }
}

@Composable
private fun WearHomeScreen(
    state: WearUiState,
    onStartListening: () -> Unit,
    onOpenSettings: () -> Unit
) {
    WearFrame {
        item { WearHeader(title = "PushGate", subtitle = "Protected") }
        item { WearProtectedCard(state) }
        item {
            AnimatedVisibility(visible = state.decisionFeedback != null) {
                state.decisionFeedback?.let { WearDecisionFeedbackCard(it) }
            }
        }
        item {
            WearSecondaryChip(
                label = "Start push listener",
                icon = { Icon(Icons.Rounded.Refresh, contentDescription = null) },
                tag = "wear_start_listener_button",
                onClick = onStartListening
            )
        }
        item {
            WearPrimaryChip(
                label = "Settings",
                icon = { Icon(Icons.Rounded.Settings, contentDescription = null) },
                tag = "wear_settings_button",
                onClick = onOpenSettings
            )
        }
        item { WearStatus(state.statusMessage) }
    }
}

@Composable
private fun WearChallengeScreen(
    state: WearUiState,
    challenge: WearChallenge,
    onApprove: () -> Unit,
    onDeny: () -> Unit
) {
    val countdown = rememberWearCountdown(challenge)
    WearChallengeFrame(
        actionBar = {
            WearDecisionActions(
                enabled = !state.isDeciding && countdown.remainingSeconds?.let { it > 0 } == true,
                onApprove = onApprove,
                onDeny = onDeny
            )
        }
    ) {
        item { WearHeader(title = challenge.username.ifBlank { "Unknown user" }, subtitle = challenge.pamService.ifBlank { "authentication" }) }
        item {
            WearCard(modifier = Modifier.testTag("wear_challenge_card")) {
                Text(
                    text = challenge.system.ifBlank { "Unknown host" },
                    style = MaterialTheme.typography.title3,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    text = sourceSummary(challenge),
                    style = MaterialTheme.typography.caption1,
                    color = WearMuted,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(Modifier.height(8.dp))
                WearCountdownBar(countdown)
                Spacer(Modifier.height(6.dp))
                Text(
                    text = "Requested ${compactTime(challenge.requestedAt)}",
                    style = MaterialTheme.typography.caption2,
                    color = WearMuted,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }
        item { WearStatus(if (state.isDeciding) "Sending decision..." else state.statusMessage) }
    }
}

@Composable
private fun WearSettingsScreen(
    state: WearUiState,
    onClearEnrollment: () -> Unit,
    onOpenEnrollment: () -> Unit,
    onOpenHome: () -> Unit
) {
    WearFrame {
        item { WearHeader(title = "Settings", subtitle = "PushGate") }
        item { WearProtectedCard(state) }
        item {
            WearPrimaryChip(
                label = "Re-enroll",
                icon = { Icon(Icons.Rounded.Refresh, contentDescription = null) },
                tag = "wear_reenroll_button",
                onClick = onOpenEnrollment
            )
        }
        item {
            WearSecondaryChip(
                label = "Home",
                icon = { Icon(Icons.Rounded.Home, contentDescription = null) },
                tag = "wear_home_button",
                onClick = onOpenHome
            )
        }
        item {
            WearDangerChip(
                label = "Clear enrollment",
                icon = { Icon(Icons.Rounded.Delete, contentDescription = null) },
                tag = "wear_clear_enrollment_button",
                onClick = onClearEnrollment
            )
        }
        item { WearStatus(state.statusMessage) }
    }
}

@Composable
private fun WearHeader(title: String, subtitle: String) {
    Column(
        modifier = Modifier.fillMaxWidth(0.88f),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            modifier = Modifier
                .size(42.dp)
                .clip(CircleShape)
                .background(WearPrimary.copy(alpha = 0.18f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(Icons.Rounded.Security, contentDescription = "PushGate shield", tint = WearPrimary)
        }
        Spacer(Modifier.height(6.dp))
        Text(
            text = title,
            style = MaterialTheme.typography.title2,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = subtitle,
            style = MaterialTheme.typography.caption1,
            color = WearMuted,
            textAlign = TextAlign.Center,
            maxLines = 2
        )
    }
}

@Composable
private fun WearProtectedCard(state: WearUiState) {
    WearCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(38.dp)
                    .clip(CircleShape)
                    .background(WearApprove.copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(Icons.Rounded.CheckCircle, contentDescription = "Protected", tint = WearApprove)
            }
            Spacer(Modifier.width(8.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text("Protected", style = MaterialTheme.typography.title3, fontWeight = FontWeight.Bold)
                Text(
                    text = if (state.isListening) "Listening" else "Ready",
                    style = MaterialTheme.typography.caption1,
                    color = WearMuted
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        SelectionContainer {
            Column {
                Text(
                    text = state.enrollment?.deviceId.orEmpty().ifBlank { "No device" },
                    style = MaterialTheme.typography.caption1,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = state.enrollment?.serverUrl.orEmpty().ifBlank { "No server" },
                    style = MaterialTheme.typography.caption2,
                    color = WearMuted,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
private fun WearDecisionFeedbackCard(feedback: WearDecisionFeedback) {
    val approved = feedback.kind == WearDecisionFeedbackKind.Approved
    val color = if (approved) WearApprove else WearDeny
    WearCard(borderColor = color.copy(alpha = 0.55f), background = color.copy(alpha = 0.14f)) {
        Icon(
            imageVector = if (approved) Icons.Rounded.CheckCircle else Icons.Rounded.Close,
            contentDescription = if (approved) "Approved" else "Denied",
            tint = color
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = if (approved) "Approved" else "Denied",
            style = MaterialTheme.typography.title3,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
        Text(
            text = "${feedback.service} • ${feedback.system}",
            style = MaterialTheme.typography.caption1,
            color = WearMuted,
            textAlign = TextAlign.Center,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

@Composable
private fun WearTextField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    singleLine: Boolean,
    tag: String,
    keyboardType: KeyboardType = KeyboardType.Text
) {
    Column(
        modifier = Modifier
            .fillMaxWidth(0.88f)
            .clip(RoundedCornerShape(8.dp))
            .background(WearSurface)
            .border(BorderStroke(1.dp, WearPrimary.copy(alpha = 0.28f)), RoundedCornerShape(8.dp))
            .padding(10.dp)
    ) {
        Text(label, style = MaterialTheme.typography.caption2, color = WearMuted)
        BasicTextField(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = if (singleLine) 30.dp else 74.dp)
                .testTag(tag)
                .semantics { contentDescription = label },
            value = value,
            onValueChange = onValueChange,
            singleLine = singleLine,
            maxLines = if (singleLine) 1 else 4,
            keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
            textStyle = TextStyle(
                color = WearText,
                fontSize = 14.sp,
                fontFamily = if (singleLine) FontFamily.Default else FontFamily.Monospace
            ),
            cursorBrush = SolidColor(WearPrimary)
        )
    }
}

@Composable
private fun WearPrimaryChip(
    label: String,
    icon: @Composable BoxScope.() -> Unit,
    tag: String,
    enabled: Boolean = true,
    onClick: () -> Unit
) {
    Chip(
        modifier = Modifier
            .fillMaxWidth(0.88f)
            .height(52.dp)
            .testTag(tag),
        onClick = onClick,
        enabled = enabled,
        label = { Text(label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        icon = icon,
        colors = ChipDefaults.primaryChipColors()
    )
}

@Composable
private fun WearSecondaryChip(
    label: String,
    icon: @Composable BoxScope.() -> Unit,
    tag: String,
    onClick: () -> Unit
) {
    OutlinedChip(
        modifier = Modifier
            .fillMaxWidth(0.88f)
            .height(52.dp)
            .testTag(tag),
        onClick = onClick,
        label = { Text(label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        icon = icon,
        colors = ChipDefaults.outlinedChipColors(contentColor = WearText)
    )
}

@Composable
private fun WearDangerChip(
    label: String,
    icon: @Composable BoxScope.() -> Unit,
    tag: String,
    onClick: () -> Unit
) {
    OutlinedChip(
        modifier = Modifier
            .fillMaxWidth(0.88f)
            .height(52.dp)
            .testTag(tag),
        onClick = onClick,
        label = { Text(label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        icon = icon,
        colors = ChipDefaults.outlinedChipColors(contentColor = WearDeny)
    )
}

@Composable
private fun WearCard(
    modifier: Modifier = Modifier,
    background: Color = WearSurface,
    borderColor: Color = WearPrimary.copy(alpha = 0.25f),
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        modifier = modifier
            .fillMaxWidth(0.88f)
            .clip(RoundedCornerShape(8.dp))
            .background(background)
            .border(BorderStroke(1.dp, borderColor), RoundedCornerShape(8.dp))
            .padding(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        content = content
    )
}

@Composable
private fun WearCountdownBar(countdown: WearCountdownUi) {
    val progress by animateFloatAsState(targetValue = countdown.progress, label = "wearCountdown")
    Column(modifier = Modifier.fillMaxWidth()) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(7.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(Color.White.copy(alpha = 0.14f))
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth(progress)
                    .height(7.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(if (countdown.remainingSeconds == 0) WearDeny else WearPrimary)
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(
            text = "Expires in ${countdown.label}",
            style = MaterialTheme.typography.caption2,
            color = WearMuted,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

@Composable
private fun WearStatus(message: String) {
    if (message.isBlank()) return
    Text(
        modifier = Modifier
            .fillMaxWidth(0.86f)
            .widthIn(min = 48.dp)
            .testTag("wear_status_text"),
        text = message,
        style = MaterialTheme.typography.caption1,
        color = WearMuted,
        textAlign = TextAlign.Center,
        maxLines = 4,
        overflow = TextOverflow.Ellipsis
    )
}

private data class WearCountdownUi(
    val label: String,
    val progress: Float,
    val remainingSeconds: Int?
)

@Composable
private fun rememberWearCountdown(challenge: WearChallenge): WearCountdownUi {
    var now by remember(challenge.id) { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(challenge.id, challenge.expiresAt) {
        while (true) {
            now = System.currentTimeMillis()
            delay(1_000)
        }
    }
    return remember(challenge.id, challenge.requestedAt, challenge.expiresAt, now) {
        wearCountdownUi(challenge, now)
    }
}

private fun wearCountdownUi(challenge: WearChallenge, nowMillis: Long): WearCountdownUi {
    val expires = parseInstantMillis(challenge.expiresAt) ?: return WearCountdownUi("invalid", 0f, null)
    val requested = parseInstantMillis(challenge.requestedAt)
    val total = ((requested ?: nowMillis).let { (expires - it).coerceAtLeast(1L) }).toFloat()
    val remainingMillis = (expires - nowMillis).coerceAtLeast(0L)
    val remainingSeconds = (remainingMillis / 1000f).roundToInt()
    val label = if (remainingSeconds > 99) "${remainingSeconds / 60}m" else "${remainingSeconds}s"
    return WearCountdownUi(
        label = label,
        progress = (remainingMillis / total).coerceIn(0f, 1f),
        remainingSeconds = remainingSeconds
    )
}

private fun parseInstantMillis(value: String?): Long? =
    value?.takeIf { it.isNotBlank() }?.let { raw ->
        runCatching { Instant.parse(raw).toEpochMilli() }.getOrNull()
    }

private fun compactTime(value: String?): String =
    value?.takeIf { it.isNotBlank() }?.let { raw ->
        runCatching {
            DateTimeFormatter.ofPattern("HH:mm:ss")
                .withZone(ZoneId.systemDefault())
                .format(Instant.parse(raw))
        }.getOrElse { raw }
    } ?: "unknown"

private fun sourceSummary(challenge: WearChallenge): String {
    val source = challenge.sourceIp?.takeIf { it.isNotBlank() } ?: "Unknown IP"
    val location = challenge.geolocation?.takeIf { it.isNotBlank() }
    return if (location == null) source else "$source • $location"
}
