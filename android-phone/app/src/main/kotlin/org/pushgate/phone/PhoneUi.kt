package org.pushgate.phone

import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.BatteryAlert
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Computer
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Menu
import androidx.compose.material.icons.rounded.Notifications
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlin.math.roundToInt

enum class DecisionFeedbackKind {
    Approved,
    Denied
}

data class DecisionFeedback(
    val kind: DecisionFeedbackKind,
    val username: String,
    val service: String,
    val system: String
)

internal data class PhonePanels(
    val history: List<HistoryEntry> = emptyList(),
    val debugLoggingEnabled: Boolean = false,
    val retentionDays: Int = DebugLogPolicy.DEFAULT_RETENTION_DAYS,
    val debugLogBytes: Long = 0L,
    val deliveryWarnings: List<String> = emptyList(),
    val batteryUnrestricted: Boolean = true,
    val lastStopNotice: String? = null,
    val appVersion: String = ""
)

internal data class PhoneUiState(
    val screen: PhoneScreen,
    val enrollment: Enrollment?,
    val serverUrl: String,
    val enrollmentPayload: String,
    val statusMessage: String,
    val challenge: AuthChallenge?,
    val isEnrolling: Boolean,
    val isListening: Boolean,
    val isDeciding: Boolean,
    val decisionFeedback: DecisionFeedback?,
    val panels: PhonePanels = PhonePanels()
)

internal class PhoneUiActions(
    val onServerUrlChange: (String) -> Unit,
    val onEnrollmentPayloadChange: (String) -> Unit,
    val onScanQr: () -> Unit,
    val onPastePayload: () -> Unit,
    val onEnroll: () -> Unit,
    val onRestartConnection: () -> Unit,
    val onReenroll: () -> Unit,
    val onClearEnrollment: () -> Unit,
    val onApprove: () -> Unit,
    val onDeny: () -> Unit,
    val onNavigate: (PhoneScreen) -> Unit,
    val onDebugLoggingChange: (Boolean) -> Unit,
    val onRetentionChange: (Int) -> Unit,
    val onShareLogs: () -> Unit,
    val onOpenNotificationSettings: () -> Unit,
    val onAllowBackground: () -> Unit
)

private val BrandPrimary = Color(0xFF7C6CFF)
private val BrandPrimaryDark = Color(0xFF9B8CFF)
private val BrandPrimaryContainer = Color(0xFFE8E3FF)
private val BrandOnPrimaryContainer = Color(0xFF21165C)
private val BrandPrimaryContainerDark = Color(0xFF332A72)
private val BrandOnPrimaryContainerDark = Color(0xFFEDE9FF)
private val ApproveGreen = Color(0xFF34D399)
private val DenyRed = Color(0xFFFB7185)
private val WarnAmber = Color(0xFFF5A524)
private val DarkBackground = Color(0xFF101218)
private val DarkSurface = Color(0xFF171A22)
private val DarkSurfaceVariant = Color(0xFF252938)

private val PushGateDarkScheme = darkColorScheme(
    primary = BrandPrimaryDark,
    onPrimary = Color(0xFF151033),
    primaryContainer = BrandPrimaryContainerDark,
    onPrimaryContainer = BrandOnPrimaryContainerDark,
    secondary = ApproveGreen,
    onSecondary = Color(0xFF032217),
    tertiary = DenyRed,
    onTertiary = Color(0xFF3A0712),
    background = DarkBackground,
    onBackground = Color(0xFFE9E9F2),
    surface = DarkSurface,
    onSurface = Color(0xFFE9E9F2),
    surfaceVariant = DarkSurfaceVariant,
    onSurfaceVariant = Color(0xFFC7C7D6),
    error = DenyRed,
    onError = Color(0xFF3A0712)
)

private val PushGateLightScheme = lightColorScheme(
    primary = BrandPrimary,
    onPrimary = Color.White,
    primaryContainer = BrandPrimaryContainer,
    onPrimaryContainer = BrandOnPrimaryContainer,
    secondary = Color(0xFF057A55),
    onSecondary = Color.White,
    tertiary = Color(0xFFC73652),
    onTertiary = Color.White,
    background = Color(0xFFF8F8FC),
    onBackground = Color(0xFF171822),
    surface = Color.White,
    onSurface = Color(0xFF171822),
    surfaceVariant = Color(0xFFE8E7F5),
    onSurfaceVariant = Color(0xFF4E5061),
    error = Color(0xFFBA1A1A),
    onError = Color.White
)

@OptIn(ExperimentalComposeUiApi::class)
@Composable
internal fun PushGatePhoneApp(state: PhoneUiState, actions: PhoneUiActions) {
    val enrolled = state.enrollment != null
    val screen = if (!enrolled && state.screen != PhoneScreen.Settings && state.screen != PhoneScreen.History) {
        PhoneScreen.Enrollment
    } else {
        state.screen
    }
    val drawerState = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    BackHandler(enabled = drawerState.isOpen) { scope.launch { drawerState.close() } }
    BackHandler(enabled = !drawerState.isOpen && screenAfterBack(screen, enrolled) != null) {
        screenAfterBack(screen, enrolled)?.let(actions.onNavigate)
    }
    PushGateTheme {
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .semantics { testTagsAsResourceId = true },
            color = MaterialTheme.colorScheme.background
        ) {
            ModalNavigationDrawer(
                drawerState = drawerState,
                drawerContent = {
                    PhoneMenu(
                        current = screen,
                        onSelect = { target ->
                            scope.launch { drawerState.close() }
                            actions.onNavigate(target)
                        }
                    )
                }
            ) {
                Scaffold(
                    topBar = {
                        PhoneTopBar(
                            subtitle = when {
                                screen == PhoneScreen.Home && state.challenge != null -> "Approval request"
                                else -> menuLabel(screen)
                            },
                            onOpenMenu = { scope.launch { drawerState.open() } }
                        )
                    },
                    containerColor = MaterialTheme.colorScheme.background
                ) { padding ->
                    val modifier = Modifier
                        .padding(padding)
                        .fillMaxSize()
                        .padding(horizontal = 20.dp)

                    when (screen) {
                        PhoneScreen.Enrollment -> EnrollmentScreen(
                            modifier = modifier,
                            state = state,
                            onServerUrlChange = actions.onServerUrlChange,
                            onEnrollmentPayloadChange = actions.onEnrollmentPayloadChange,
                            onScanQr = actions.onScanQr,
                            onPastePayload = actions.onPastePayload,
                            onEnroll = actions.onEnroll
                        )

                        PhoneScreen.Settings -> SettingsScreen(modifier = modifier, state = state, actions = actions)

                        PhoneScreen.History -> HistoryScreen(modifier = modifier, entries = state.panels.history)

                        PhoneScreen.Home -> if (state.challenge != null) {
                            ChallengeScreen(
                                modifier = modifier,
                                challenge = state.challenge,
                                isDeciding = state.isDeciding,
                                statusMessage = state.statusMessage,
                                onApprove = actions.onApprove,
                                onDeny = actions.onDeny
                            )
                        } else {
                            HomeScreen(modifier = modifier, state = state)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PhoneMenu(current: PhoneScreen, onSelect: (PhoneScreen) -> Unit) {
    ModalDrawerSheet(modifier = Modifier.testTag("menu_drawer")) {
        Row(
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Rounded.Security, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(12.dp))
            Text("PushGate", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        }
        MenuScreens.forEach { target ->
            NavigationDrawerItem(
                modifier = Modifier
                    .padding(horizontal = 12.dp)
                    .testTag("menu_${target.name.lowercase()}"),
                label = { Text(menuLabel(target)) },
                icon = {
                    Icon(
                        imageVector = when (target) {
                            PhoneScreen.Settings -> Icons.Rounded.Settings
                            PhoneScreen.History -> Icons.Rounded.History
                            else -> Icons.Rounded.Home
                        },
                        contentDescription = null
                    )
                },
                selected = current == target,
                onClick = { onSelect(target) }
            )
        }
    }
}

@Composable
private fun PhoneTopBar(subtitle: String, onOpenMenu: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.background)
            .statusBarsPadding()
            .padding(horizontal = 8.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        IconButton(
            modifier = Modifier.testTag("menu_button"),
            onClick = onOpenMenu
        ) {
            Icon(imageVector = Icons.Rounded.Menu, contentDescription = "Open menu")
        }
        Spacer(Modifier.width(4.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = "PushGate",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Box(
            modifier = Modifier
                .padding(end = 12.dp)
                .size(36.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.18f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Rounded.Security,
                contentDescription = "PushGate shield",
                tint = MaterialTheme.colorScheme.primary
            )
        }
    }
}

/** Status only: no buttons. Everything that changes state lives in Settings. */
@Composable
private fun HomeScreen(modifier: Modifier, state: PhoneUiState) {
    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        ProtectedCard(state)
        AnimatedVisibility(visible = state.decisionFeedback != null) {
            state.decisionFeedback?.let { DecisionFeedbackCard(it) }
        }
        val notices = listOfNotNull(state.panels.lastStopNotice) + state.panels.deliveryWarnings
        if (notices.isNotEmpty()) {
            NoticeCard(notices, footer = "Fix these in Settings.")
        }
        StatusLine(state.statusMessage)
    }
}

@Composable
private fun NoticeCard(lines: List<String>, footer: String?) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("delivery_warnings"),
        colors = CardDefaults.cardColors(containerColor = WarnAmber.copy(alpha = 0.12f)),
        shape = RoundedCornerShape(8.dp),
        border = BorderStroke(1.dp, WarnAmber.copy(alpha = 0.5f))
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            lines.forEach { line ->
                Row(verticalAlignment = Alignment.Top) {
                    Icon(Icons.Rounded.Warning, contentDescription = null, tint = WarnAmber, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(10.dp))
                    Text(line, style = MaterialTheme.typography.bodyMedium)
                }
            }
            footer?.let {
                Text(it, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun SettingsSection(title: String, icon: ImageVector, content: @Composable () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(8.dp)
    ) {
        Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(10.dp))
                Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            }
            content()
        }
    }
}

@Composable
private fun SettingsButton(label: String, icon: ImageVector, tag: String, enabled: Boolean = true, danger: Boolean = false, onClick: () -> Unit) {
    OutlinedButton(
        modifier = Modifier
            .fillMaxWidth()
            .height(50.dp)
            .testTag(tag),
        enabled = enabled,
        onClick = onClick,
        colors = if (danger) ButtonDefaults.outlinedButtonColors(contentColor = DenyRed) else ButtonDefaults.outlinedButtonColors(),
        border = if (danger) BorderStroke(1.dp, DenyRed.copy(alpha = 0.65f)) else ButtonDefaults.outlinedButtonBorder(enabled)
    ) {
        Icon(icon, contentDescription = null)
        Spacer(Modifier.width(8.dp))
        Text(label)
    }
}

@Composable
private fun SettingsScreen(modifier: Modifier, state: PhoneUiState, actions: PhoneUiActions) {
    var confirmClear by remember { mutableStateOf(false) }
    var pickRetention by remember { mutableStateOf(false) }
    val panels = state.panels
    val enrolled = state.enrollment != null
    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SettingsSection("Connection", Icons.Rounded.VerifiedUser) {
            InfoRow(
                if (state.isListening) Icons.Rounded.CheckCircle else Icons.Rounded.Schedule,
                "Status",
                when {
                    !enrolled -> "This phone is not enrolled"
                    state.isListening -> "Connected"
                    else -> "Not connected"
                }
            )
            if (enrolled) InfoRow(Icons.Rounded.Public, "Server", state.enrollment?.serverUrl.orEmpty(), monospace = true)
            SettingsButton("Restart connection", Icons.Rounded.Refresh, "restart_button", enabled = enrolled, onClick = actions.onRestartConnection)
            SettingsButton("Re-enroll", Icons.Rounded.QrCodeScanner, "reenroll_button", onClick = actions.onReenroll)
            SettingsButton("Clear enrollment", Icons.Rounded.Delete, "clear_enrollment_button", enabled = enrolled, danger = true) {
                confirmClear = true
            }
        }
        SettingsSection("Background delivery", Icons.Rounded.Notifications) {
            val notices = listOfNotNull(panels.lastStopNotice) + panels.deliveryWarnings
            if (notices.isEmpty()) {
                Text(
                    "Nothing on this phone is blocking requests while PushGate is closed.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                NoticeCard(notices, footer = null)
            }
            SettingsButton("Notification settings", Icons.Rounded.Notifications, "notification_settings_button", onClick = actions.onOpenNotificationSettings)
            if (!panels.batteryUnrestricted) {
                SettingsButton("Allow background use", Icons.Rounded.BatteryAlert, "allow_background_button", onClick = actions.onAllowBackground)
            }
        }
        SettingsSection("Debug logging", Icons.Rounded.BugReport) {
            SettingsSwitchRow(
                title = "Record debug log",
                summary = if (panels.debugLoggingEnabled) {
                    "On. Log size: ${formatBytes(panels.debugLogBytes)}. Turning it off deletes the whole log."
                } else {
                    "Off. Nothing is stored. When on, saves what PushGate does on this phone so problems can be traced."
                },
                tag = "debug_logging_switch",
                checked = panels.debugLoggingEnabled,
                onCheckedChange = actions.onDebugLoggingChange
            )
            SettingsPickerRow(
                title = "Keep logs for",
                value = retentionLabel(panels.retentionDays),
                tag = "retention_row",
                onClick = { pickRetention = true }
            )
            SettingsButton("Share log", Icons.Rounded.Share, "share_log_button", enabled = panels.debugLoggingEnabled, onClick = actions.onShareLogs)
        }
        SettingsSection("About", Icons.Rounded.Info) {
            InfoRow(Icons.Rounded.Security, "App version", panels.appVersion)
        }
        StatusLine(state.statusMessage)
    }
    if (confirmClear) {
        AlertDialog(
            modifier = Modifier.testTag("clear_enrollment_dialog"),
            onDismissRequest = { confirmClear = false },
            icon = { Icon(Icons.Rounded.Warning, contentDescription = null, tint = DenyRed) },
            title = { Text("Clear enrollment?") },
            text = {
                Text(
                    "This unpairs this phone from PushGate and deletes its approval key. " +
                        "It will stop receiving requests until you enroll it again with a new code from the server."
                )
            },
            confirmButton = {
                TextButton(
                    modifier = Modifier.testTag("confirm_clear_button"),
                    onClick = {
                        confirmClear = false
                        actions.onClearEnrollment()
                    }
                ) { Text("Clear enrollment", color = DenyRed) }
            },
            dismissButton = {
                TextButton(modifier = Modifier.testTag("cancel_clear_button"), onClick = { confirmClear = false }) { Text("Cancel") }
            }
        )
    }
    if (pickRetention) {
        AlertDialog(
            modifier = Modifier.testTag("retention_dialog"),
            onDismissRequest = { pickRetention = false },
            title = { Text("Keep logs for") },
            text = {
                Column(
                    modifier = Modifier
                        .selectableGroup()
                        .verticalScroll(rememberScrollState())
                ) {
                    DebugLogPolicy.RETENTION_CHOICES.forEach { days ->
                        val selected = panels.retentionDays == days
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = 48.dp)
                                .testTag("retention_$days")
                                .selectable(
                                    selected = selected,
                                    role = Role.RadioButton,
                                    onClick = {
                                        pickRetention = false
                                        actions.onRetentionChange(days)
                                    }
                                ),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(selected = selected, onClick = null)
                            Spacer(Modifier.width(16.dp))
                            Text(retentionLabel(days), style = MaterialTheme.typography.bodyLarge)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(modifier = Modifier.testTag("retention_cancel"), onClick = { pickRetention = false }) { Text("Cancel") }
            }
        )
    }
}

internal fun retentionLabel(days: Int): String = if (days == 1) "1 day" else "$days days"

/** Standard Material settings row: title and summary on the left, switch on the right; the whole row toggles. */
@Composable
private fun SettingsSwitchRow(title: String, summary: String, tag: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .testTag(tag)
            .toggleable(value = checked, role = Role.Switch, onValueChange = onCheckedChange)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(summary, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.width(16.dp))
        Switch(checked = checked, onCheckedChange = null)
    }
}

/** Standard Material picker row: title with the current value below it; tapping opens a choice dialog. */
@Composable
private fun SettingsPickerRow(title: String, value: String, tag: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .testTag(tag)
            .clickable(role = Role.Button, onClickLabel = "Change", onClick = onClick)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(value, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.width(16.dp))
        Icon(Icons.Rounded.ChevronRight, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun HistoryScreen(modifier: Modifier, entries: List<HistoryEntry>) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(5_000)
            now = System.currentTimeMillis()
        }
    }
    if (entries.isEmpty()) {
        Column(modifier = modifier.padding(top = 24.dp)) {
            Text("No requests yet", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(6.dp))
            Text(
                "Requests this phone receives will be listed here, newest first.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        return
    }
    LazyColumn(
        modifier = modifier.testTag("history_list"),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        contentPadding = PaddingValues(bottom = 28.dp)
    ) {
        items(entries, key = { it.requestId }) { entry -> HistoryRow(entry, now) }
    }
}

@Composable
private fun HistoryRow(entry: HistoryEntry, nowMillis: Long) {
    val result = HistoryRecords.resultText(entry, nowMillis)
    val color = when {
        result.startsWith("Approved") -> ApproveGreen
        result.startsWith("Denied") -> DenyRed
        result == "Waiting" -> MaterialTheme.colorScheme.primary
        else -> WarnAmber
    }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("history_row")
            .semantics { contentDescription = HistoryRecords.summary(entry) + ". " + result },
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(8.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = entry.host.ifBlank { "Unknown host" },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = result,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = color
                )
            }
            Text(
                text = "${entry.username.ifBlank { "Unknown user" }} from ${entry.source.ifBlank { "unknown address" }}" +
                    (entry.service.takeIf { it.isNotBlank() && !it.equals(entry.host, ignoreCase = true) }?.let { " · $it" } ?: ""),
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = historyTime(entry.sortTimeMillis, nowMillis),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
internal fun PushGateTheme(content: @Composable () -> Unit) {
    val context = LocalContext.current
    val dark = isSystemInDarkTheme()
    val baseColors = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
    } else {
        if (dark) PushGateDarkScheme else PushGateLightScheme
    }
    val colors = baseColors.withPushGateBrandAccent(dark)

    MaterialTheme(
        colorScheme = colors,
        typography = MaterialTheme.typography,
        content = content
    )
}

private fun ColorScheme.withPushGateBrandAccent(dark: Boolean): ColorScheme =
    copy(
        primary = if (dark) BrandPrimaryDark else BrandPrimary,
        onPrimary = if (dark) Color(0xFF151033) else Color.White,
        primaryContainer = if (dark) BrandPrimaryContainerDark else BrandPrimaryContainer,
        onPrimaryContainer = if (dark) BrandOnPrimaryContainerDark else BrandOnPrimaryContainer,
        inversePrimary = if (dark) BrandPrimary else BrandPrimaryDark
    )

@Composable
private fun EnrollmentScreen(
    modifier: Modifier,
    state: PhoneUiState,
    onServerUrlChange: (String) -> Unit,
    onEnrollmentPayloadChange: (String) -> Unit,
    onScanQr: () -> Unit,
    onPastePayload: () -> Unit,
    onEnroll: () -> Unit
) {
    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        HeroLockup()
        OutlinedTextField(
            modifier = Modifier
                .fillMaxWidth()
                .testTag("server_url_field"),
            value = state.serverUrl,
            onValueChange = onServerUrlChange,
            singleLine = true,
            label = { Text("Server URL") },
            placeholder = { Text("https://pushgate.example") },
            leadingIcon = { Icon(Icons.Rounded.Public, contentDescription = null) }
        )
        OutlinedTextField(
            modifier = Modifier
                .fillMaxWidth()
                .height(132.dp)
                .testTag("enrollment_payload_field"),
            value = state.enrollmentPayload,
            onValueChange = onEnrollmentPayloadChange,
            minLines = 4,
            label = { Text("Enrollment payload") },
            leadingIcon = { Icon(Icons.Rounded.ContentPaste, contentDescription = null) }
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                modifier = Modifier
                    .weight(1f)
                    .height(52.dp)
                    .testTag("scan_qr_button"),
                onClick = onScanQr
            ) {
                Icon(Icons.Rounded.QrCodeScanner, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Scan QR")
            }
            OutlinedButton(
                modifier = Modifier
                    .weight(1f)
                    .height(52.dp)
                    .testTag("paste_payload_button"),
                onClick = onPastePayload
            ) {
                Icon(Icons.Rounded.ContentPaste, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Paste")
            }
        }
        Button(
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp)
                .testTag("enroll_button"),
            onClick = onEnroll,
            enabled = !state.isEnrolling,
            contentPadding = PaddingValues(horizontal = 20.dp)
        ) {
            Icon(Icons.Rounded.VerifiedUser, contentDescription = null)
            Spacer(Modifier.width(10.dp))
            Text(if (state.isEnrolling) "Enrolling..." else "Enroll")
        }
        StatusLine(state.statusMessage)
    }
}

@Composable
private fun HeroLockup() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(8.dp),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.45f))
    ) {
        Row(
            modifier = Modifier.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(64.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.18f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    modifier = Modifier.size(38.dp),
                    imageVector = Icons.Rounded.Security,
                    contentDescription = "PushGate shield-check",
                    tint = MaterialTheme.colorScheme.primary
                )
            }
            Spacer(Modifier.width(16.dp))
            Column {
                Text(
                    text = "PushGate",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Trust decisions from your own server",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun ProtectedCard(state: PhoneUiState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(8.dp)
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(52.dp)
                        .clip(CircleShape)
                        .background((if (state.isListening) ApproveGreen else MaterialTheme.colorScheme.onSurfaceVariant).copy(alpha = 0.16f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = if (state.isListening) Icons.Rounded.CheckCircle else Icons.Rounded.Schedule,
                        contentDescription = if (state.isListening) "Connected" else "Not connected",
                        tint = if (state.isListening) ApproveGreen else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Spacer(Modifier.width(14.dp))
                Column {
                    Text(
                        text = if (state.isListening) "Connected" else "Not connected",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = if (state.isListening) "Listening for requests" else "No live request connection",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.35f))
            InfoRow(Icons.Rounded.Public, "Server", state.enrollment?.serverUrl.orEmpty(), monospace = true)
        }
    }
}

@Composable
private fun ChallengeScreen(
    modifier: Modifier,
    challenge: AuthChallenge,
    isDeciding: Boolean,
    statusMessage: String,
    onApprove: () -> Unit,
    onDeny: () -> Unit
) {
    val countdown = rememberCountdown(challenge)
    val isActionable = countdown.remainingSeconds?.let { it > 0 } == true
    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .testTag("challenge_card"),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(8.dp),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.28f))
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(18.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = safeDisplayText(challenge.username).ifBlank { "Unknown user" },
                            style = MaterialTheme.typography.headlineMedium,
                            fontWeight = FontWeight.Bold,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = safeDisplayText(challenge.pamService).ifBlank { "authentication" },
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.primary,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    CountdownRing(countdown)
                }
                LinearProgressIndicator(
                    progress = { countdown.progress },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(6.dp)
                        .clip(RoundedCornerShape(8.dp)),
                    color = if (countdown.remainingSeconds == 0) DenyRed else MaterialTheme.colorScheme.primary,
                    trackColor = MaterialTheme.colorScheme.surfaceVariant
                )
                InfoRow(Icons.Rounded.Computer, "System / host", safeDisplayText(challenge.system), monospace = true)
                InfoRow(Icons.Rounded.Person, "User", safeDisplayText(challenge.username))
                InfoRow(Icons.Rounded.Terminal, "Service", safeDisplayText(challenge.pamService), monospace = true)
                InfoRow(Icons.Rounded.Public, "Source", sourceSummary(challenge), monospace = true)
                InfoRow(Icons.Rounded.Schedule, "Request time", compactTime(challenge.requestedAt))
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                modifier = Modifier
                    .weight(1f)
                    .height(64.dp)
                    .testTag("deny_button")
                    .semantics { contentDescription = "Deny PushGate request" },
                onClick = onDeny,
                enabled = !isDeciding && isActionable,
                colors = ButtonDefaults.buttonColors(
                    containerColor = DenyRed,
                    contentColor = Color(0xFF3A0712)
                )
            ) {
                Icon(Icons.Rounded.Close, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Deny", fontWeight = FontWeight.Bold)
            }
            Button(
                modifier = Modifier
                    .weight(1f)
                    .height(64.dp)
                    .testTag("approve_button")
                    .semantics { contentDescription = "Approve PushGate request" },
                onClick = onApprove,
                enabled = !isDeciding && isActionable,
                colors = ButtonDefaults.buttonColors(
                    containerColor = ApproveGreen,
                    contentColor = Color(0xFF042315)
                )
            ) {
                Icon(Icons.Rounded.CheckCircle, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Approve", fontWeight = FontWeight.Bold)
            }
        }
        StatusLine(
            when {
                isDeciding -> "Sending decision..."
                !isActionable -> "Request expired"
                else -> statusMessage
            }
        )
    }
}

@Composable
private fun CountdownRing(countdown: CountdownUi) {
    val animatedProgress by animateFloatAsState(targetValue = countdown.progress, label = "challengeCountdown")
    Box(
        modifier = Modifier
            .size(78.dp)
            .semantics { contentDescription = "Expires in ${countdown.label}" },
        contentAlignment = Alignment.Center
    ) {
        CircularProgressIndicator(
            progress = { animatedProgress },
            modifier = Modifier.fillMaxSize(),
            color = if (countdown.remainingSeconds == 0) DenyRed else MaterialTheme.colorScheme.primary,
            trackColor = MaterialTheme.colorScheme.surfaceVariant,
            strokeWidth = 6.dp
        )
        Text(
            text = countdown.label,
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun DecisionFeedbackCard(feedback: DecisionFeedback) {
    val approved = feedback.kind == DecisionFeedbackKind.Approved
    val color = if (approved) ApproveGreen else DenyRed
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.14f)),
        shape = RoundedCornerShape(8.dp),
        border = BorderStroke(1.dp, color.copy(alpha = 0.5f))
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = if (approved) Icons.Rounded.CheckCircle else Icons.Rounded.Close,
                contentDescription = if (approved) "Approved" else "Denied",
                tint = color
            )
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = if (approved) "Request approved" else "Request denied",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "${feedback.username} • ${feedback.service} • ${feedback.system}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
private fun InfoRow(icon: ImageVector, label: String, value: String, monospace: Boolean = false) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            modifier = Modifier
                .padding(top = 2.dp)
                .size(20.dp),
            imageVector = icon,
            contentDescription = label,
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = value.ifBlank { "Unknown" },
                style = MaterialTheme.typography.bodyLarge,
                fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun StatusLine(message: String) {
    if (message.isBlank()) return
    Text(
        modifier = Modifier
            .fillMaxWidth()
            .widthIn(min = 48.dp)
            .testTag("status_text"),
        text = message,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        maxLines = 2,
        overflow = TextOverflow.Ellipsis
    )
}

private data class CountdownUi(
    val label: String,
    val progress: Float,
    val remainingSeconds: Int?
)

@Composable
private fun rememberCountdown(challenge: AuthChallenge): CountdownUi {
    var now by remember(challenge.id) { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(challenge.id, challenge.expiresAt) {
        while (true) {
            now = System.currentTimeMillis()
            delay(1_000)
        }
    }
    return remember(challenge.id, challenge.requestedAt, challenge.expiresAt, now) {
        countdownUi(challenge, now)
    }
}

private fun countdownUi(challenge: AuthChallenge, nowMillis: Long): CountdownUi {
    val expires = parseInstantMillis(challenge.expiresAt) ?: return CountdownUi("Invalid", 0f, null)
    val requested = parseInstantMillis(challenge.requestedAt)
    val total = ((requested ?: nowMillis).let { (expires - it).coerceAtLeast(1L) }).toFloat()
    val remainingMillis = (expires - nowMillis).coerceAtLeast(0L)
    val remainingSeconds = (remainingMillis / 1000f).roundToInt()
    val label = if (remainingSeconds > 99) "${remainingSeconds / 60}m" else "${remainingSeconds}s"
    return CountdownUi(
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
            DateTimeFormatter.ofPattern("MMM d, HH:mm:ss")
                .withZone(ZoneId.systemDefault())
                .format(Instant.parse(raw))
        }.getOrElse { safeDisplayText(raw) }
    } ?: "Unknown"

private fun sourceSummary(challenge: AuthChallenge): String {
    val source = safeDisplayText(challenge.sourceIp).ifBlank { "Unknown IP" }
    val location = safeDisplayText(challenge.geolocation).takeIf { it.isNotBlank() }
    return if (location == null) source else "$source • $location"
}
