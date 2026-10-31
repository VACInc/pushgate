package org.pushgate.phone

import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Pure rules for the opt-in debug log: one file per local day, kept for a chosen number of
 * days, every line scrubbed of secrets before it touches storage. Kept free of Android so the
 * retention and redaction rules are unit tested.
 */
internal object DebugLogPolicy {
    const val DEFAULT_RETENTION_DAYS = 7
    const val MIN_RETENTION_DAYS = 1
    const val MAX_RETENTION_DAYS = 30
    val RETENTION_CHOICES = listOf(1, 3, 7, 14, 30)

    /** One day's file stops growing past this; a runaway loop cannot fill the phone. */
    const val MAX_FILE_BYTES = 4L * 1024 * 1024

    private const val FILE_PREFIX = "pushgate-"
    private const val FILE_SUFFIX = ".log"
    private val LINE_TIME: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS xxx")

    fun clampRetention(days: Int): Int = days.coerceIn(MIN_RETENTION_DAYS, MAX_RETENTION_DAYS)

    fun fileNameFor(epochMillis: Long, zone: ZoneId): String =
        FILE_PREFIX + Instant.ofEpochMilli(epochMillis).atZone(zone).toLocalDate() + FILE_SUFFIX

    fun dateOf(fileName: String): LocalDate? {
        if (!fileName.startsWith(FILE_PREFIX) || !fileName.endsWith(FILE_SUFFIX)) return null
        return runCatching {
            LocalDate.parse(fileName.removePrefix(FILE_PREFIX).removeSuffix(FILE_SUFFIX))
        }.getOrNull()
    }

    /**
     * Files to delete: anything older than the retention window (today counts as day one), and
     * anything that is not one of our day files.
     */
    fun expiredFiles(fileNames: Collection<String>, today: LocalDate, retentionDays: Int): List<String> {
        val oldestKept = today.minusDays((clampRetention(retentionDays) - 1).toLong())
        return fileNames.filter { name ->
            val date = dateOf(name)
            date == null || date.isBefore(oldestKept)
        }.sorted()
    }

    fun formatTime(epochMillis: Long, zone: ZoneId): String = LINE_TIME.format(Instant.ofEpochMilli(epochMillis).atZone(zone))

    fun formatLine(epochMillis: Long, zone: ZoneId, tag: String, message: String): String {
        val time = formatTime(epochMillis, zone)
        val cleanTag = tag.filter { it.isLetterOrDigit() || it == '-' || it == '_' }.take(24).ifBlank { "app" }
        return "$time [$cleanTag] ${redact(message)}"
    }

    private val URL = Regex("""(?i)\b(https?|wss?)://([^/\s?#"']+)[^\s"']*""")
    private val PEM = Regex("""-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----""")
    private val BEARER = Regex("""(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+""")
    private val SECRET_FIELD = Regex(
        """(?i)\b(token|secret|password|passwd|signature|private[_ ]?key|enrollment_token|authorization|auth|nonce|key)(["']?\s*[:=]\s*["']?)[^\s"',;&}]+"""
    )
    private val UUID = Regex("""\b([0-9a-fA-F]{8})-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b""")
    private val LONG_TOKEN = Regex("""[A-Za-z0-9_+/=-]{32,}""")

    /**
     * Never let a secret reach the log: URLs keep only scheme and host (a push endpoint path is a
     * delivery capability), key-like fields and bearer values are blanked, PEM blocks dropped, long
     * opaque strings removed, and IDs shortened to their first 8 characters so one request can still
     * be followed through the log without storing full identifiers.
     */
    fun redact(text: String): String =
        text
            .replace(PEM, "[key removed]")
            .replace(URL) { "${it.groupValues[1]}://${it.groupValues[2]}/…" }
            .replace(BEARER) { "${it.groupValues[1]} [removed]" }
            .replace(SECRET_FIELD) { "${it.groupValues[1]}${it.groupValues[2]}[removed]" }
            .replace(UUID) { "${it.groupValues[1]}…" }
            .replace(LONG_TOKEN, "[removed]")
}
