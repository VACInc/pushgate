package org.pushgate.phone

import android.content.Context

/**
 * Request IDs this phone has already acted on or seen settled. A request reaches the phone over
 * several paths (WebSocket, WebSocket pending replay, UnifiedPush/FCM, server push retries), and a
 * copy that arrives after the notification was cleared by a tap or an `auth_decided` would
 * otherwise post it again, so the approver sees (and taps) the same request twice.
 */
internal object SettledRequestStore {
    private const val PREFS = "pushgate.settled_requests"
    private const val RECORDS = "records"

    /** Longer than any request lifetime, so a late copy of a settled request is still recognised. */
    internal const val RETENTION_MILLIS = 30 * 60 * 1000L

    @Synchronized
    fun mark(context: Context, challengeId: String, nowMillis: Long = System.currentTimeMillis()) {
        if (challengeId.isBlank()) return
        val records = SettledRecords.prune(read(context), nowMillis) + (challengeId to nowMillis + RETENTION_MILLIS)
        write(context, records)
    }

    @Synchronized
    fun contains(context: Context, challengeId: String, nowMillis: Long = System.currentTimeMillis()): Boolean =
        SettledRecords.contains(read(context), challengeId, nowMillis)

    @Synchronized
    fun clear(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().commit()
    }

    private fun read(context: Context): Map<String, Long> =
        SettledRecords.decode(
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getStringSet(RECORDS, emptySet()).orEmpty()
        )

    private fun write(context: Context, records: Map<String, Long>) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(RECORDS, SettledRecords.encode(records))
            .commit()
    }
}

/** Pure encoding and expiry rules for [SettledRequestStore], kept free of Android for unit tests. */
internal object SettledRecords {
    fun prune(records: Map<String, Long>, nowMillis: Long): Map<String, Long> =
        records.filterValues { it > nowMillis }

    fun contains(records: Map<String, Long>, challengeId: String, nowMillis: Long): Boolean =
        records[challengeId]?.let { it > nowMillis } ?: false

    fun encode(records: Map<String, Long>): Set<String> =
        records.mapTo(linkedSetOf()) { (id, until) -> "$until|$id" }

    fun decode(raw: Set<String>): Map<String, Long> =
        raw.mapNotNull { entry ->
            val split = entry.indexOf('|')
            if (split <= 0) return@mapNotNull null
            val until = entry.substring(0, split).toLongOrNull() ?: return@mapNotNull null
            val id = entry.substring(split + 1).takeIf(String::isNotBlank) ?: return@mapNotNull null
            id to until
        }.toMap()
}

/**
 * A delivered request is posted only when it is not already on screen, this phone has not
 * already claimed a decision on it, and it is not known to be settled.
 */
internal fun deliveryShouldPostNotification(
    alreadyShown: Boolean,
    claimed: Boolean = false,
    settled: Boolean = false
): Boolean = !alreadyShown && !claimed && !settled

/**
 * The single gate every decision path passes before it signs and sends: a request this phone
 * already settled (its own decision succeeded, or `auth_decided` arrived) never gets a second
 * decision, even after its claim was released, and an in-flight claim blocks a concurrent one.
 */
internal fun decisionMayStart(settled: Boolean, conflictingClaim: Boolean): Boolean =
    !settled && !conflictingClaim

/** An in-app card (or a card reopened from a notification) is shown only for unsettled requests. */
internal fun phoneCardShouldShow(settled: Boolean, actionable: Boolean): Boolean = !settled && actionable
