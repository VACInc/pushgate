package org.pushgate.phone

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlin.math.roundToInt

/** Where the user is. Home, Settings and History are the menu; Enrollment is reached from Settings. */
enum class PhoneScreen {
    Enrollment,
    Home,
    Settings,
    History
}

/** The three menu entries, in menu order. */
internal val MenuScreens = listOf(PhoneScreen.Home, PhoneScreen.Settings, PhoneScreen.History)

/** Back from any secondary screen goes Home; Back on Home (or an unenrolled phone) leaves the app. */
internal fun screenAfterBack(screen: PhoneScreen, enrolled: Boolean): PhoneScreen? = when {
    screen == PhoneScreen.Home -> null
    screen == PhoneScreen.Enrollment && !enrolled -> null
    else -> PhoneScreen.Home
}

internal fun menuLabel(screen: PhoneScreen): String = when (screen) {
    PhoneScreen.Home -> "Home"
    PhoneScreen.Settings -> "Settings"
    PhoneScreen.History -> "History"
    PhoneScreen.Enrollment -> "Enroll this phone"
}

internal fun historyTime(epochMillis: Long, nowMillis: Long, zone: ZoneId = ZoneId.systemDefault()): String {
    val time = Instant.ofEpochMilli(epochMillis).atZone(zone)
    val today = Instant.ofEpochMilli(nowMillis).atZone(zone).toLocalDate()
    val clock = DateTimeFormatter.ofPattern("h:mm a", java.util.Locale.US).format(time)
    return when (time.toLocalDate()) {
        today -> "Today $clock"
        today.minusDays(1) -> "Yesterday $clock"
        else -> DateTimeFormatter.ofPattern("MMM d", java.util.Locale.US).format(time) + " $clock"
    }
}

internal fun formatBytes(bytes: Long): String = when {
    bytes < 1024 -> "$bytes bytes"
    bytes < 1024 * 1024 -> "${(bytes / 1024.0).roundToInt()} KB"
    else -> String.format(java.util.Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0))
}

