package org.pushgate.phone

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.time.OffsetDateTime

/** One request this phone saw. The request ID is kept only to match its later result; never shown. */
internal data class HistoryEntry(
    val requestId: String,
    val receivedAtMillis: Long,
    val requestedAtMillis: Long?,
    val expiresAtMillis: Long?,
    val username: String,
    val host: String,
    val source: String,
    val service: String,
    /** Server status: pending, approved, denied, timeout (or another settled status). */
    val status: String,
    val decidedAtMillis: Long? = null,
    val decidedHere: Boolean = false
) {
    /** Newest-first ordering key: when the request was made, else when it arrived here. */
    val sortTimeMillis: Long get() = requestedAtMillis ?: receivedAtMillis
}

internal object HistoryRecords {
    const val MAX_ENTRIES = 300
    const val MAX_AGE_MILLIS = 30L * 24 * 60 * 60 * 1000

    fun fromChallenge(challenge: AuthChallenge, nowMillis: Long): HistoryEntry =
        HistoryEntry(
            requestId = challenge.id,
            receivedAtMillis = nowMillis,
            requestedAtMillis = parseMillis(challenge.requestedAt),
            expiresAtMillis = parseMillis(challenge.expiresAt),
            username = safeDisplayText(challenge.username),
            host = safeDisplayText(challenge.system),
            source = safeDisplayText(challenge.sourceIp),
            service = safeDisplayText(challenge.pamService),
            status = "pending"
        )

    /** A repeat delivery of a request already listed changes nothing (its result is kept). */
    fun recordRequest(entries: List<HistoryEntry>, entry: HistoryEntry): List<HistoryEntry> =
        if (entries.any { it.requestId == entry.requestId }) entries else entries + entry

    /** Settles a listed request; the first settled result wins, later copies are ignored. */
    fun resolve(
        entries: List<HistoryEntry>,
        requestId: String,
        status: String,
        decidedHere: Boolean,
        nowMillis: Long
    ): List<HistoryEntry> {
        val normalized = status.trim().lowercase()
        if (normalized.isEmpty() || normalized == "pending") return entries
        return entries.map { entry ->
            if (entry.requestId != requestId || entry.status != "pending") entry
            else entry.copy(status = normalized, decidedAtMillis = nowMillis, decidedHere = decidedHere)
        }
    }

    fun prune(entries: List<HistoryEntry>, nowMillis: Long): List<HistoryEntry> =
        entries
            .filter { nowMillis - it.receivedAtMillis <= MAX_AGE_MILLIS }
            .sortedByDescending { it.sortTimeMillis }
            .take(MAX_ENTRIES)

    fun newestFirst(entries: List<HistoryEntry>): List<HistoryEntry> = entries.sortedByDescending { it.sortTimeMillis }

    /** Plain result word for the History screen. An unanswered request past its expiry timed out. */
    fun resultText(entry: HistoryEntry, nowMillis: Long): String = when (entry.status) {
        "approved" -> if (entry.decidedHere) "Approved" else "Approved on another device"
        "denied" -> if (entry.decidedHere) "Denied" else "Denied on another device"
        "timeout", "expired" -> "Timed out"
        "pending" -> if (entry.expiresAtMillis != null && entry.expiresAtMillis <= nowMillis) "Timed out" else "Waiting"
        "consumed" -> "Approved"
        else -> entry.status.replaceFirstChar { it.uppercase() }
    }

    /** "deploy wants web-02 from bastion (SSH access)" with blanks spelled out. */
    fun summary(entry: HistoryEntry): String {
        val user = entry.username.ifBlank { "Unknown user" }
        val host = entry.host.ifBlank { "unknown host" }
        val source = entry.source.ifBlank { "unknown address" }
        val service = entry.service.takeIf { it.isNotBlank() && !it.equals(entry.host, ignoreCase = true) }
        return "$user wants $host from $source" + (service?.let { " ($it)" } ?: "")
    }

    fun encode(entries: List<HistoryEntry>): String {
        val array = JSONArray()
        entries.forEach { e ->
            array.put(
                JSONObject()
                    .put("id", e.requestId)
                    .put("received", e.receivedAtMillis)
                    .put("requested", e.requestedAtMillis ?: JSONObject.NULL)
                    .put("expires", e.expiresAtMillis ?: JSONObject.NULL)
                    .put("user", e.username)
                    .put("host", e.host)
                    .put("source", e.source)
                    .put("service", e.service)
                    .put("status", e.status)
                    .put("decided", e.decidedAtMillis ?: JSONObject.NULL)
                    .put("here", e.decidedHere)
            )
        }
        return array.toString()
    }

    fun decode(raw: String?): List<HistoryEntry> {
        if (raw.isNullOrBlank()) return emptyList()
        val array = runCatching { JSONArray(raw) }.getOrNull() ?: return emptyList()
        return (0 until array.length()).mapNotNull { index ->
            runCatching {
                val o = array.getJSONObject(index)
                HistoryEntry(
                    requestId = o.getString("id").also { require(it.isNotBlank()) },
                    receivedAtMillis = o.getLong("received"),
                    requestedAtMillis = o.optLongOrNull("requested"),
                    expiresAtMillis = o.optLongOrNull("expires"),
                    username = o.optString("user"),
                    host = o.optString("host"),
                    source = o.optString("source"),
                    service = o.optString("service"),
                    status = o.optString("status").ifBlank { "pending" },
                    decidedAtMillis = o.optLongOrNull("decided"),
                    decidedHere = o.optBoolean("here", false)
                )
            }.getOrNull()
        }
    }

    private fun JSONObject.optLongOrNull(key: String): Long? =
        if (!has(key) || isNull(key)) null else runCatching { getLong(key) }.getOrNull()

    internal fun parseMillis(value: String?): Long? =
        value?.takeIf { it.isNotBlank() }?.let { runCatching { OffsetDateTime.parse(it).toInstant().toEpochMilli() }.getOrNull() }
}

/** Local request history (this phone only), newest first, capped at 30 days / 300 requests. */
internal object RequestHistoryStore {
    private const val PREFS = "pushgate.history"
    private const val ENTRIES = "entries"

    @Synchronized
    fun recordRequest(context: Context, challenge: AuthChallenge, nowMillis: Long = System.currentTimeMillis()) {
        if (challenge.id.isBlank()) return
        update(context, nowMillis) { HistoryRecords.recordRequest(it, HistoryRecords.fromChallenge(challenge, nowMillis)) }
    }

    @Synchronized
    fun resolve(
        context: Context,
        requestId: String,
        status: String,
        decidedHere: Boolean,
        nowMillis: Long = System.currentTimeMillis()
    ) {
        if (requestId.isBlank()) return
        update(context, nowMillis) { HistoryRecords.resolve(it, requestId, status, decidedHere, nowMillis) }
    }

    @Synchronized
    fun list(context: Context): List<HistoryEntry> = HistoryRecords.newestFirst(read(context))

    @Synchronized
    fun clear(context: Context) {
        prefs(context).edit().clear().commit()
    }

    private fun update(context: Context, nowMillis: Long, change: (List<HistoryEntry>) -> List<HistoryEntry>) {
        runCatching {
            val next = HistoryRecords.prune(change(read(context)), nowMillis)
            prefs(context).edit().putString(ENTRIES, HistoryRecords.encode(next)).commit()
        }.onFailure { DebugLog.error(context, "history", "Could not save request history", it) }
    }

    private fun read(context: Context): List<HistoryEntry> = HistoryRecords.decode(prefs(context).getString(ENTRIES, null))

    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
