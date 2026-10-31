package org.pushgate.phone

/**
 * What can stop a request from reaching this phone while the app is closed, in plain words.
 * Pure so every combination is unit tested; [DeliveryHealthProbe] fills it from Android.
 */
internal data class DeliveryHealth(
    val notificationsAllowed: Boolean,
    /** Importance of the approvals channel; null before it exists. 0 = blocked, 1-2 = silent. */
    val channelImportance: Int?,
    val batteryUnrestricted: Boolean,
    val backgroundRestricted: Boolean,
    /** Android app standby bucket; 45 = restricted, 50 = never. Null when unknown. */
    val standbyBucket: Int?,
    val pushRegistered: Boolean,
    val lastStop: AppExit?
)

/** One past exit of the app process as Android recorded it. */
internal data class AppExit(
    val reason: Int,
    val description: String?,
    val timestampMillis: Long
)

internal object AppExitReasons {
    // android.app.ApplicationExitInfo reason codes (stable public constants).
    const val EXIT_SELF = 1
    const val SIGNALED = 2
    const val LOW_MEMORY = 3
    const val CRASH = 4
    const val CRASH_NATIVE = 5
    const val ANR = 6
    const val INITIALIZATION_FAILURE = 7
    const val PERMISSION_CHANGE = 8
    const val EXCESSIVE_RESOURCE_USAGE = 9
    const val USER_REQUESTED = 10
    const val USER_STOPPED = 11
    const val DEPENDENCY_DIED = 12
    const val OTHER = 13
    const val FREEZER = 14
    const val PACKAGE_STATE_CHANGE = 15
    const val PACKAGE_UPDATED = 16

    fun plainEnglish(reason: Int, description: String?): String {
        val forceStop = description?.contains("stop", ignoreCase = true) == true
        return when (reason) {
            USER_REQUESTED, USER_STOPPED ->
                if (forceStop || reason == USER_STOPPED) {
                    "Android stopped PushGate (force stop or app sleeping)"
                } else {
                    "PushGate was closed from the recent apps list or by a system cleaner"
                }
            CRASH, CRASH_NATIVE -> "PushGate crashed"
            ANR -> "PushGate stopped responding and Android closed it"
            LOW_MEMORY -> "Android closed PushGate to free memory (normal)"
            EXCESSIVE_RESOURCE_USAGE -> "Android closed PushGate for using too much battery or CPU"
            FREEZER -> "Android froze and then closed PushGate in the background"
            SIGNALED -> "Android ended PushGate in the background (normal)"
            EXIT_SELF -> "PushGate closed itself"
            INITIALIZATION_FAILURE -> "PushGate failed to start"
            PERMISSION_CHANGE -> "PushGate restarted after a permission change"
            DEPENDENCY_DIED -> "A system service PushGate depends on stopped"
            PACKAGE_UPDATED, PACKAGE_STATE_CHANGE -> "PushGate was updated or changed"
            else -> "Android closed PushGate"
        }
    }

    /**
     * Exits after which Android refuses to start the app for a background push until the user
     * opens it again: a force stop or sleeping app, or a crash (two quick background crashes mark
     * the app as bad). Ordinary memory or background kills restart cleanly on the next push.
     */
    fun blocksBackgroundDelivery(reason: Int, description: String?): Boolean = when (reason) {
        USER_STOPPED, CRASH, CRASH_NATIVE, ANR, INITIALIZATION_FAILURE -> true
        USER_REQUESTED -> description?.contains("stop", ignoreCase = true) == true
        else -> false
    }
}

internal object DeliveryWarnings {
    const val CHANNEL_BLOCKED = 0
    const val CHANNEL_SILENT_MAX = 2
    const val BUCKET_RESTRICTED = 45

    /** Plain-English problems, worst first. Empty means nothing known blocks background delivery. */
    fun of(health: DeliveryHealth): List<String> = buildList {
        if (!health.notificationsAllowed) {
            add("Notifications are off for PushGate, so requests cannot appear. Turn them on in Settings.")
        } else if (health.channelImportance == CHANNEL_BLOCKED) {
            add("PushGate approval notifications are turned off. Turn them on in Settings.")
        } else if (health.channelImportance != null && health.channelImportance <= CHANNEL_SILENT_MAX) {
            add("PushGate approval notifications are set to silent, so they will not pop up.")
        }
        if (!health.pushRegistered) {
            add("Background push is not set up. Requests only arrive while PushGate is open.")
        }
        if (health.backgroundRestricted || (health.standbyBucket ?: 0) >= BUCKET_RESTRICTED) {
            add("Android restricts PushGate in the background. Set its battery use to Unrestricted in Settings.")
        } else if (!health.batteryUnrestricted) {
            add("Battery optimization can put PushGate to sleep. Allow it to run in the background in Settings.")
        }
    }

    /** One line about the last time Android stopped the app in a way that drops pushes, else null. */
    fun lastStopNotice(lastStop: AppExit?, sinceMillis: Long): String? {
        val stop = lastStop ?: return null
        if (stop.timestampMillis < sinceMillis) return null
        if (!AppExitReasons.blocksBackgroundDelivery(stop.reason, stop.description)) return null
        return AppExitReasons.plainEnglish(stop.reason, stop.description) +
            ". Requests could not reach this phone until PushGate was opened again."
    }
}
