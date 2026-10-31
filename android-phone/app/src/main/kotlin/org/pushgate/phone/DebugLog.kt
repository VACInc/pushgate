package org.pushgate.phone

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.app.NotificationManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.os.Build
import android.os.PowerManager
import android.os.Process
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId

/**
 * Opt-in on-device debug log (Settings > Debug logging). Off by default. While on, the app
 * records its own lifecycle (process start, Android's recorded reason for the previous exit,
 * crashes with stack traces), push receipt, notification posting, permission/channel state and
 * approve/deny actions, one file per day, kept for the chosen number of days. Turning it off
 * deletes every stored log at once. Every line is scrubbed by [DebugLogPolicy.redact].
 */
object DebugLog {
    private const val PREFS = "pushgate.debug_log"
    private const val ENABLED = "enabled"
    private const val RETENTION_DAYS = "retention_days"
    private const val LAST_EXIT_SEEN = "last_exit_seen"
    private const val DIR = "debuglog"
    private const val EXPORT_DIR = "debuglog-export"
    private const val EXPORT_FILE = "pushgate-debug-log.txt"

    @Volatile
    private var prunedDay: LocalDate? = null

    fun isEnabled(context: Context): Boolean = prefs(context).getBoolean(ENABLED, false)

    fun retentionDays(context: Context): Int =
        DebugLogPolicy.clampRetention(prefs(context).getInt(RETENTION_DAYS, DebugLogPolicy.DEFAULT_RETENTION_DAYS))

    @Synchronized
    fun setEnabled(context: Context, enabled: Boolean) {
        if (enabled) {
            prefs(context).edit().putBoolean(ENABLED, true).commit()
            log(context, "log", "Debug logging turned on; keeping ${retentionDays(context)} days")
            log(context, "state", snapshot(context))
            recordRecentExits(context, includeAlreadySeen = true)
        } else {
            prefs(context).edit().putBoolean(ENABLED, false).commit()
            deleteAll(context)
        }
    }

    @Synchronized
    fun setRetentionDays(context: Context, days: Int) {
        val clamped = DebugLogPolicy.clampRetention(days)
        prefs(context).edit().putInt(RETENTION_DAYS, clamped).commit()
        prunedDay = null
        prune(context, System.currentTimeMillis())
        log(context, "log", "Debug log retention set to $clamped days")
    }

    fun log(context: Context, tag: String, message: String) {
        if (!isEnabled(context)) return
        write(context, tag, message)
    }

    fun error(context: Context, tag: String, message: String, error: Throwable?) {
        if (!isEnabled(context)) return
        write(context, tag, if (error == null) message else "$message: ${stackTrace(error)}")
    }

    @Synchronized
    private fun write(context: Context, tag: String, message: String) {
        runCatching {
            val now = System.currentTimeMillis()
            val zone = ZoneId.systemDefault()
            prune(context, now)
            val file = File(dir(context), DebugLogPolicy.fileNameFor(now, zone))
            if (file.length() >= DebugLogPolicy.MAX_FILE_BYTES) return
            file.appendText(DebugLogPolicy.formatLine(now, zone, tag, message) + "\n")
        }
    }

    private fun prune(context: Context, nowMillis: Long) {
        val today = Instant.ofEpochMilli(nowMillis).atZone(ZoneId.systemDefault()).toLocalDate()
        if (prunedDay == today) return
        val directory = dir(context)
        val names = directory.list()?.toList().orEmpty()
        DebugLogPolicy.expiredFiles(names, today, retentionDays(context)).forEach { File(directory, it).delete() }
        prunedDay = today
    }

    @Synchronized
    fun deleteAll(context: Context) {
        dir(context).deleteRecursively()
        File(context.cacheDir, EXPORT_DIR).deleteRecursively()
        prunedDay = null
    }

    fun storedBytes(context: Context): Long = dir(context).listFiles()?.sumOf { it.length() } ?: 0L

    /** Writes one shareable file: a fresh state snapshot, Android's recent exit reasons, then the logs. */
    @Synchronized
    fun export(context: Context): File {
        val out = File(context.cacheDir, EXPORT_DIR).apply { mkdirs() }
        val file = File(out, EXPORT_FILE)
        val now = System.currentTimeMillis()
        val zone = ZoneId.systemDefault()
        file.bufferedWriter().use { writer ->
            writer.appendLine("PushGate debug log, exported ${DebugLogPolicy.formatTime(now, zone)}")
            writer.appendLine(DebugLogPolicy.redact(snapshot(context)))
            writer.appendLine("Recent exits recorded by Android (newest first):")
            recentExits(context).forEach { writer.appendLine("  " + DebugLogPolicy.redact(describeExit(it, zone))) }
            writer.appendLine()
            dir(context).listFiles()?.sortedBy { it.name }?.forEach { day ->
                writer.appendLine("== ${day.name}")
                day.forEachLine { writer.appendLine(it) }
            }
        }
        return file
    }

    /** Called once per process start, from the Application. */
    fun onProcessStart(context: Context) {
        installCrashHandler(context.applicationContext)
        if (!isEnabled(context)) return
        val importance = runCatching {
            val info = ActivityManager.RunningAppProcessInfo()
            ActivityManager.getMyMemoryState(info)
            info.importance
        }.getOrNull()
        log(context, "process", "Process started (pid ${Process.myPid()}, importance $importance)")
        recordRecentExits(context, includeAlreadySeen = false)
    }

    private fun installCrashHandler(context: Context) {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        if (previous is CrashLogger) return
        Thread.setDefaultUncaughtExceptionHandler(CrashLogger(context, previous))
    }

    private class CrashLogger(
        private val context: Context,
        private val previous: Thread.UncaughtExceptionHandler?
    ) : Thread.UncaughtExceptionHandler {
        override fun uncaughtException(thread: Thread, error: Throwable) {
            runCatching { DebugLog.error(context, "crash", "Uncaught exception on thread ${thread.name}", error) }
            previous?.uncaughtException(thread, error)
        }
    }

    /** Logs exits Android recorded since the last one we logged (API 30+). */
    private fun recordRecentExits(context: Context, includeAlreadySeen: Boolean) {
        val exits = recentExits(context)
        if (exits.isEmpty()) return
        val lastSeen = prefs(context).getLong(LAST_EXIT_SEEN, 0L)
        val zone = ZoneId.systemDefault()
        exits.filter { includeAlreadySeen || it.timestampMillis > lastSeen }
            .sortedBy { it.timestampMillis }
            .forEach { log(context, "exit", describeExit(it, zone)) }
        prefs(context).edit().putLong(LAST_EXIT_SEEN, exits.maxOf { it.timestampMillis }).apply()
    }

    private fun describeExit(exit: AppExit, zone: ZoneId): String =
        "Previous exit at ${DebugLogPolicy.formatTime(exit.timestampMillis, zone)}: " +
            "${AppExitReasons.plainEnglish(exit.reason, exit.description)} " +
            "(reason ${exit.reason}${exit.description?.let { ", \"$it\"" } ?: ""})"

    internal fun recentExits(context: Context): List<AppExit> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return emptyList()
        return runCatching {
            context.getSystemService(ActivityManager::class.java)
                .getHistoricalProcessExitReasons(context.packageName, 0, 16)
                .map { info: ApplicationExitInfo -> AppExit(info.reason, info.description, info.timestamp) }
        }.getOrDefault(emptyList())
    }

    /** The most recent exit that keeps pushes out until the app is opened, if any. */
    internal fun lastBlockingStop(context: Context): AppExit? =
        recentExits(context)
            .filter { AppExitReasons.blocksBackgroundDelivery(it.reason, it.description) }
            .maxByOrNull { it.timestampMillis }

    fun snapshot(context: Context): String {
        val health = DeliveryHealthProbe.read(context)
        return buildString {
            append("App ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE}) on Android ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT}), ")
            append("${Build.MANUFACTURER} ${Build.MODEL}; ")
            append("notifications allowed=${health.notificationsAllowed}, channel importance=${health.channelImportance}, ")
            append("battery unrestricted=${health.batteryUnrestricted}, background restricted=${health.backgroundRestricted}, ")
            append("standby bucket=${health.standbyBucket}, background push registered=${health.pushRegistered}, ")
            append("enrolled=${EnrollmentStore.load(context) != null}")
        }
    }

    internal fun stackTrace(error: Throwable): String {
        val writer = StringWriter()
        error.printStackTrace(PrintWriter(writer))
        return writer.toString().lines().take(40).joinToString("\n    ")
    }

    private fun dir(context: Context): File = File(context.applicationContext.filesDir, DIR).apply { mkdirs() }

    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}

/** Reads the Android settings that decide whether a closed app can still show a request. */
internal object DeliveryHealthProbe {
    fun read(context: Context): DeliveryHealth {
        val notifications = context.getSystemService(NotificationManager::class.java)
        val power = context.getSystemService(PowerManager::class.java)
        val activity = context.getSystemService(ActivityManager::class.java)
        return DeliveryHealth(
            notificationsAllowed = runCatching { notifications.areNotificationsEnabled() }.getOrDefault(true),
            channelImportance = runCatching {
                notifications.getNotificationChannel(AuthNotificationDispatcher.CHANNEL_ID)?.importance
            }.getOrNull(),
            batteryUnrestricted = runCatching { power.isIgnoringBatteryOptimizations(context.packageName) }.getOrDefault(false),
            backgroundRestricted = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                runCatching { activity.isBackgroundRestricted }.getOrDefault(false),
            standbyBucket = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                runCatching { context.getSystemService(UsageStatsManager::class.java).appStandbyBucket }.getOrNull()
            } else null,
            pushRegistered = BuildConfig.FCM_CONFIGURED || UnifiedPushRegistration.isUploaded(context),
            lastStop = DebugLog.lastBlockingStop(context)
        )
    }
}
