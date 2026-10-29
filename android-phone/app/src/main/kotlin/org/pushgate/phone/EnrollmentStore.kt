package org.pushgate.phone

import android.content.Context

object EnrollmentStore {
    private const val PREFS = "pushgate.enrollment"
    private const val SERVER_URL = "server_url"
    private const val DEVICE_ID = "device_id"
    private const val DECISION_API = "decision_api"
    private const val PENDING_SERVER_URL = "pending_server_url"
    private const val PENDING_DEVICE_ID = "pending_device_id"
    private const val PENDING_DECISION_API = "pending_decision_api"
    private const val PENDING_SIGNING_KEY_ALIAS = "pending_signing_key_alias"
    private const val PENDING_PREVIOUS_SIGNING_KEY_ALIAS = "pending_previous_signing_key_alias"
    private const val PENDING_SERVER_ACCEPTED = "pending_server_accepted"
    private const val KEY_CLEANUP_ALIASES = "key_cleanup_aliases"
    private const val KEY_CLEANUP_CLEAR_ACTIVE = "key_cleanup_clear_active"
    @Volatile
    private var cleanupJournalPersistenceFailed = false

    data class PendingEnrollment(
        val enrollment: Enrollment,
        val signingKeyAlias: String,
        val previousSigningKeyAlias: String,
        val serverAccepted: Boolean
    )

    fun save(context: Context, enrollment: Enrollment): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(SERVER_URL, enrollment.serverUrl)
            .putString(DEVICE_ID, enrollment.deviceId)
            .putString(DECISION_API, enrollment.decisionApi)
            .commit()

    fun savePending(
        context: Context,
        enrollment: Enrollment,
        signingKeyAlias: String,
        previousSigningKeyAlias: String
    ): Boolean = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        .edit()
        .putString(PENDING_SERVER_URL, enrollment.serverUrl)
        .putString(PENDING_DEVICE_ID, enrollment.deviceId)
        .putString(PENDING_DECISION_API, enrollment.decisionApi)
        .putString(PENDING_SIGNING_KEY_ALIAS, signingKeyAlias)
        .putString(PENDING_PREVIOUS_SIGNING_KEY_ALIAS, previousSigningKeyAlias)
        .putBoolean(PENDING_SERVER_ACCEPTED, false)
        .commit()

    fun hasPending(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).contains(PENDING_SERVER_URL)

    fun loadPending(context: Context): PendingEnrollment? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val serverUrl = prefs.getString(PENDING_SERVER_URL, null) ?: return null
        val deviceId = prefs.getString(PENDING_DEVICE_ID, null) ?: return null
        val decisionApi = prefs.getString(PENDING_DECISION_API, null) ?: return null
        val signingKeyAlias = prefs.getString(PENDING_SIGNING_KEY_ALIAS, null)
            ?.takeIf { it.isNotBlank() }
            ?: return null
        val previousSigningKeyAlias = prefs.getString(PENDING_PREVIOUS_SIGNING_KEY_ALIAS, null)
            ?.takeIf { it.isNotBlank() }
            ?: return null
        val enrollment = storedEnrollment(
                serverUrl = serverUrl,
                deviceId = deviceId,
                decisionApi = decisionApi
            ) ?: return null
        return PendingEnrollment(
            enrollment = enrollment,
            signingKeyAlias = signingKeyAlias,
            previousSigningKeyAlias = previousSigningKeyAlias,
            serverAccepted = prefs.getBoolean(PENDING_SERVER_ACCEPTED, false)
        )
    }

    internal fun pendingSigningKeyAlias(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(PENDING_SIGNING_KEY_ALIAS, null)
            ?.takeIf(String::isNotBlank)

    fun pendingSigningKeyAliases(context: Context): Set<String> {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return setOfNotNull(
            prefs.getString(PENDING_SIGNING_KEY_ALIAS, null)?.takeIf(String::isNotBlank),
            prefs.getString(PENDING_PREVIOUS_SIGNING_KEY_ALIAS, null)?.takeIf(String::isNotBlank)
        )
    }

    fun markPendingServerAccepted(context: Context, signingKeyAlias: String): Boolean {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.getString(PENDING_SIGNING_KEY_ALIAS, null) != signingKeyAlias) return false
        return prefs.edit().putBoolean(PENDING_SERVER_ACCEPTED, true).commit()
    }

    fun promotePending(context: Context, enrollment: Enrollment): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(SERVER_URL, enrollment.serverUrl)
            .putString(DEVICE_ID, enrollment.deviceId)
            .putString(DECISION_API, enrollment.decisionApi)
            .remove(PENDING_SERVER_URL)
            .remove(PENDING_DEVICE_ID)
            .remove(PENDING_DECISION_API)
            .remove(PENDING_SIGNING_KEY_ALIAS)
            .remove(PENDING_PREVIOUS_SIGNING_KEY_ALIAS)
            .remove(PENDING_SERVER_ACCEPTED)
            .commit()

    fun clearPending(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(PENDING_SERVER_URL)
            .remove(PENDING_DEVICE_ID)
            .remove(PENDING_DECISION_API)
            .remove(PENDING_SIGNING_KEY_ALIAS)
            .remove(PENDING_PREVIOUS_SIGNING_KEY_ALIAS)
            .remove(PENDING_SERVER_ACCEPTED)
            .commit()

    fun beginPendingRollback(context: Context, signingKeyAlias: String): Boolean {
        require(signingKeyAlias.isNotBlank()) { "Signing key cleanup alias is blank" }
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (hasUsableCleanupJournal(prefs.getStringSet(KEY_CLEANUP_ALIASES, emptySet()))) return false
        val committed = prefs.edit()
            .remove(PENDING_SERVER_URL)
            .remove(PENDING_DEVICE_ID)
            .remove(PENDING_DECISION_API)
            .remove(PENDING_SIGNING_KEY_ALIAS)
            .remove(PENDING_PREVIOUS_SIGNING_KEY_ALIAS)
            .remove(PENDING_SERVER_ACCEPTED)
            .putStringSet(KEY_CLEANUP_ALIASES, setOf(signingKeyAlias))
            .putBoolean(KEY_CLEANUP_CLEAR_ACTIVE, false)
            .commit()
        cleanupJournalPersistenceFailed = !committed
        return committed
    }

    fun beginOrphanedStagedKeyCleanup(context: Context, signingKeyAliases: Set<String>): Boolean {
        require(signingKeyAliases.isNotEmpty()) { "Signing key cleanup aliases are empty" }
        require(signingKeyAliases.none(String::isBlank)) { "Signing key cleanup alias is blank" }
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (hasUsableCleanupJournal(prefs.getStringSet(KEY_CLEANUP_ALIASES, emptySet()))) return false
        val committed = prefs.edit()
            .putStringSet(KEY_CLEANUP_ALIASES, signingKeyAliases)
            .putBoolean(KEY_CLEANUP_CLEAR_ACTIVE, false)
            .commit()
        cleanupJournalPersistenceFailed = !committed
        return committed
    }

    fun beginClear(context: Context, signingKeyAliases: Set<String>): Boolean {
        require(signingKeyAliases.none(String::isBlank)) { "Signing key cleanup alias is blank" }
        val committed = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .putStringSet(KEY_CLEANUP_ALIASES, signingKeyAliases)
            .putBoolean(KEY_CLEANUP_CLEAR_ACTIVE, true)
            .commit()
        cleanupJournalPersistenceFailed = !committed
        return committed
    }

    fun pendingKeyCleanupAliases(context: Context): Set<String> =
        if (cleanupJournalPersistenceFailed) {
            emptySet()
        } else {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getStringSet(KEY_CLEANUP_ALIASES, emptySet())
                .orEmpty()
                .filterTo(linkedSetOf(), String::isNotBlank)
        }

    private fun hasUsableCleanupJournal(aliases: Set<String>?): Boolean =
        !cleanupJournalPersistenceFailed && !aliases.isNullOrEmpty()

    fun keyCleanupClearsActiveSigningKey(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_CLEANUP_CLEAR_ACTIVE, false)

    fun finishClear(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_CLEANUP_ALIASES)
            .remove(KEY_CLEANUP_CLEAR_ACTIVE)
            .commit()

    fun load(context: Context): Enrollment? {
        if (hasPending(context)) return loadPending(context)?.enrollment
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val serverUrl = prefs.getString(SERVER_URL, null) ?: return null
        val deviceId = prefs.getString(DEVICE_ID, null) ?: return null
        val decisionApi = prefs.getString(DECISION_API, null) ?: return null
        return storedEnrollment(
            serverUrl = serverUrl,
            deviceId = deviceId,
            decisionApi = decisionApi
        )
    }

    private fun storedEnrollment(serverUrl: String, deviceId: String, decisionApi: String): Enrollment? =
        runCatching {
            val canonicalUrl = canonicalServerUrl(serverUrl, allowDebugCleartext = BuildConfig.DEBUG)
            Enrollment(
                serverUrl = canonicalUrl,
                deviceId = deviceId,
                enrollmentToken = "",
                enrollApi = "/api/v1/devices/{id}/enroll",
                decisionApi = decisionApi
            ).also {
                it.endpointUrl(it.enrollApi, deviceId)
                it.endpointUrl(decisionApi, "request-id")
            }
        }.getOrNull()

    fun clear(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().commit()
}
