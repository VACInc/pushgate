package org.pushgate.wear

import android.content.Context

internal enum class SigningKeyCleanupMode {
    ClearEnrollment,
    ActivatePending,
    RollbackPending,
    DeleteOnly
}

object WearEnrollmentStore {
    private const val PREFS = "pushgate.wear.enrollment"
    private const val SERVER_URL = "server_url"
    private const val DEVICE_ID = "device_id"
    private const val DECISION_API = "decision_api"
    private const val SIGNING_KEY_ALIAS = "signing_key_alias"
    private const val PENDING_SERVER_URL = "pending_server_url"
    private const val PENDING_DEVICE_ID = "pending_device_id"
    private const val PENDING_DECISION_API = "pending_decision_api"
    private const val PENDING_SIGNING_KEY_ALIAS = "pending_signing_key_alias"
    private const val SIGNING_KEY_CLEANUP_ALIASES = "signing_key_cleanup_aliases"
    private const val SIGNING_KEY_CLEANUP_MODE = "signing_key_cleanup_mode"
    private const val SIGNING_KEY_CLEANUP_EXPECTED_ALIAS = "signing_key_cleanup_expected_alias"

    fun save(context: Context, enrollment: WearEnrollment): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(SERVER_URL, enrollment.serverUrl)
            .putString(DEVICE_ID, enrollment.deviceId)
            .putString(DECISION_API, enrollment.decisionApi)
            .putString(SIGNING_KEY_ALIAS, enrollment.signingKeyAlias)
            .remove(PENDING_SERVER_URL)
            .remove(PENDING_DEVICE_ID)
            .remove(PENDING_DECISION_API)
            .remove(PENDING_SIGNING_KEY_ALIAS)
            .commit()

    fun savePending(context: Context, enrollment: WearEnrollment): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(PENDING_SERVER_URL, enrollment.serverUrl)
            .putString(PENDING_DEVICE_ID, enrollment.deviceId)
            .putString(PENDING_DECISION_API, enrollment.decisionApi)
            .putString(PENDING_SIGNING_KEY_ALIAS, enrollment.signingKeyAlias)
            .commit()

    fun hasPending(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .contains(PENDING_SERVER_URL)

    fun signingKeyAliases(context: Context): Set<String> {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return persistedEnrollmentSigningKeyAliases(
            hasActiveEnrollment = prefs.contains(SERVER_URL),
            activeAlias = prefs.getString(SIGNING_KEY_ALIAS, null),
            hasPendingEnrollment = prefs.contains(PENDING_SERVER_URL),
            pendingAlias = prefs.getString(PENDING_SIGNING_KEY_ALIAS, null)
        )
    }

    fun hasSigningKeyCleanupJournal(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .contains(SIGNING_KEY_CLEANUP_ALIASES)

    fun signingKeyCleanupAliases(context: Context): Set<String> =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getStringSet(SIGNING_KEY_CLEANUP_ALIASES, emptySet())
            .orEmpty()
            .filter(String::isNotBlank)
            .toSet()

    fun beginSigningKeyCleanup(context: Context, aliases: Set<String>): Boolean {
        val durableAliases = signingKeyCleanupAliases(context)
            .plus(aliases.filter(String::isNotBlank))
        return beginSigningKeyCleanup(
            context = context,
            aliases = durableAliases,
            mode = SigningKeyCleanupMode.ClearEnrollment,
            expectedAlias = null
        )
    }

    fun beginActivationSigningKeyCleanup(
        context: Context,
        previousAlias: String?,
        replacementAlias: String
    ): Boolean {
        if (replacementAlias.isBlank() || hasSigningKeyCleanupJournal(context)) return false
        return replaceActivationSigningKeyCleanup(context, previousAlias, replacementAlias)
    }

    internal fun replaceActivationSigningKeyCleanup(
        context: Context,
        previousAlias: String?,
        replacementAlias: String
    ): Boolean {
        if (replacementAlias.isBlank()) return false
        val aliases = setOfNotNull(previousAlias?.takeIf { it.isNotBlank() && it != replacementAlias })
        return beginSigningKeyCleanup(
            context = context,
            aliases = aliases,
            mode = SigningKeyCleanupMode.ActivatePending,
            expectedAlias = replacementAlias
        )
    }

    fun beginPendingRollbackSigningKeyCleanup(context: Context, stagedAlias: String): Boolean {
        if (stagedAlias.isBlank() || hasSigningKeyCleanupJournal(context)) return false
        return replacePendingRollbackSigningKeyCleanup(context, stagedAlias)
    }

    internal fun replacePendingRollbackSigningKeyCleanup(
        context: Context,
        stagedAlias: String
    ): Boolean {
        if (stagedAlias.isBlank()) return false
        return beginSigningKeyCleanup(
            context = context,
            aliases = setOf(stagedAlias),
            mode = SigningKeyCleanupMode.RollbackPending,
            expectedAlias = stagedAlias
        )
    }

    fun beginDeleteOnlySigningKeyCleanup(context: Context, aliases: Set<String>): Boolean {
        val durableAliases = aliases.filter(String::isNotBlank).toSet()
        if (durableAliases.isEmpty() || hasSigningKeyCleanupJournal(context)) return false
        return replaceDeleteOnlySigningKeyCleanup(context, durableAliases)
    }

    internal fun replaceDeleteOnlySigningKeyCleanup(context: Context, aliases: Set<String>): Boolean {
        val durableAliases = aliases.filter(String::isNotBlank).toSet()
        if (durableAliases.isEmpty()) return false
        return beginSigningKeyCleanup(
            context = context,
            aliases = durableAliases,
            mode = SigningKeyCleanupMode.DeleteOnly,
            expectedAlias = null
        )
    }

    private fun beginSigningKeyCleanup(
        context: Context,
        aliases: Set<String>,
        mode: SigningKeyCleanupMode,
        expectedAlias: String?
    ): Boolean {
        val editor = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            // Keep an empty set as a durable transition marker when no old key
            // exists. It is removed only after the record transition commits.
            .putStringSet(SIGNING_KEY_CLEANUP_ALIASES, aliases)
            .putString(SIGNING_KEY_CLEANUP_MODE, mode.name)
        if (expectedAlias == null) {
            editor.remove(SIGNING_KEY_CLEANUP_EXPECTED_ALIAS)
        } else {
            editor.putString(SIGNING_KEY_CLEANUP_EXPECTED_ALIAS, expectedAlias)
        }
        return editor.commit()
    }

    fun clearEnrollmentRecordsForCleanup(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(SERVER_URL)
            .remove(DEVICE_ID)
            .remove(DECISION_API)
            .remove(SIGNING_KEY_ALIAS)
            .remove(PENDING_SERVER_URL)
            .remove(PENDING_DEVICE_ID)
            .remove(PENDING_DECISION_API)
            .remove(PENDING_SIGNING_KEY_ALIAS)
            .commit()

    fun acknowledgeSigningKeyDeleted(context: Context, alias: String): Boolean {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!prefs.contains(SIGNING_KEY_CLEANUP_ALIASES)) return false
        val remaining = signingKeyCleanupAliases(context) - alias
        return prefs.edit()
            .putStringSet(SIGNING_KEY_CLEANUP_ALIASES, remaining)
            .commit()
    }

    fun finishEmptySigningKeyCleanup(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!prefs.contains(SIGNING_KEY_CLEANUP_ALIASES)) return true
        if (signingKeyCleanupAliases(context).isNotEmpty()) return false
        return prefs.edit()
            .remove(SIGNING_KEY_CLEANUP_ALIASES)
            .remove(SIGNING_KEY_CLEANUP_MODE)
            .remove(SIGNING_KEY_CLEANUP_EXPECTED_ALIAS)
            .commit()
    }

    internal fun retrySigningKeyCleanup(context: Context): EnrollmentCleanupResult =
        retryEnrollmentCleanup(
            loadCleanupAliases = { signingKeyCleanupAliases(context) },
            clearEnrollmentRecords = {
                when (signingKeyCleanupMode(context)) {
                    SigningKeyCleanupMode.ClearEnrollment ->
                        clearEnrollmentRecordsForCleanup(context)
                    SigningKeyCleanupMode.ActivatePending ->
                        promotePendingEnrollmentForCleanup(context)
                    SigningKeyCleanupMode.RollbackPending ->
                        clearPendingEnrollmentForCleanup(context)
                    SigningKeyCleanupMode.DeleteOnly -> true
                    null -> false
                }
            },
            clearSigningKey = { alias -> WearKeyStore.clearSigningKey(context, alias) },
            acknowledgeDeletedAlias = { alias -> acknowledgeSigningKeyDeleted(context, alias) },
            finishEmptyJournal = { finishEmptySigningKeyCleanup(context) },
            hasCleanupJournal = { hasSigningKeyCleanupJournal(context) }
        )

    /**
     * Finishes any durable cleanup first, then recovers staged keys left by a
     * process death between key creation and savePending(). Referenced active
     * and pending aliases are always excluded before the delete-only journal is
     * committed.
     */
    internal fun recoverSigningKeyCleanup(context: Context): EnrollmentCleanupResult? {
        val priorCleanup = if (hasSigningKeyCleanupJournal(context)) {
            retrySigningKeyCleanup(context).also { cleanup ->
                if (!cleanup.complete) return cleanup
            }
        } else {
            null
        }

        val discoveredAliases = runCatching {
            WearKeyStore.stagedSigningKeyAliases(context)
        }.getOrElse {
            // Discovery must be complete before enrollment can create another
            // staged alias. A later startup or button press retries enumeration.
            return EnrollmentCleanupResult(
                recordsCleared = true,
                remainingAliases = emptySet(),
                journalPending = true
            )
        }
        val orphanedAliases = orphanedStagedSigningKeyAliases(
            discoveredAliases = discoveredAliases,
            referencedAliases = signingKeyAliases(context)
        )
        if (orphanedAliases.isEmpty()) return priorCleanup

        return startEnrollmentCleanup(
            signingKeyAliases = orphanedAliases,
            persistCleanupJournal = { aliases -> beginDeleteOnlySigningKeyCleanup(context, aliases) },
            retryCleanup = { retrySigningKeyCleanup(context) }
        )
    }

    private fun signingKeyCleanupMode(context: Context): SigningKeyCleanupMode? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val stored = prefs.getString(SIGNING_KEY_CLEANUP_MODE, null)
            ?: return SigningKeyCleanupMode.ClearEnrollment
        return SigningKeyCleanupMode.entries.firstOrNull { it.name == stored }
    }

    private fun cleanupExpectedAlias(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(SIGNING_KEY_CLEANUP_EXPECTED_ALIAS, null)
            ?.takeIf(String::isNotBlank)

    private fun promotePendingEnrollmentForCleanup(context: Context): Boolean {
        val expectedAlias = cleanupExpectedAlias(context) ?: return false
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        when (
            activationCleanupAction(
                expectedAlias = expectedAlias,
                hasCompleteActiveEnrollment = hasCompleteActiveEnrollment(prefs),
                activeAlias = storedActiveAlias(prefs),
                hasCompletePendingEnrollment = hasCompletePendingEnrollment(prefs),
                pendingAlias = storedPendingAlias(prefs)
            )
        ) {
            EnrollmentRecordCleanupAction.AlreadyApplied -> return true
            EnrollmentRecordCleanupAction.Refuse -> return false
            EnrollmentRecordCleanupAction.Apply -> Unit
        }
        return prefs.edit()
            .putString(SERVER_URL, prefs.getString(PENDING_SERVER_URL, null))
            .putString(DEVICE_ID, prefs.getString(PENDING_DEVICE_ID, null))
            .putString(DECISION_API, prefs.getString(PENDING_DECISION_API, null))
            .putString(SIGNING_KEY_ALIAS, expectedAlias)
            .remove(PENDING_SERVER_URL)
            .remove(PENDING_DEVICE_ID)
            .remove(PENDING_DECISION_API)
            .remove(PENDING_SIGNING_KEY_ALIAS)
            .commit()
    }

    private fun clearPendingEnrollmentForCleanup(context: Context): Boolean {
        val stagedAlias = cleanupExpectedAlias(context) ?: return false
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return when (
            pendingRollbackCleanupAction(
                stagedAlias = stagedAlias,
                hasActiveEnrollment = prefs.contains(SERVER_URL),
                activeAlias = storedActiveAlias(prefs),
                hasPendingEnrollment = prefs.contains(PENDING_SERVER_URL),
                pendingAlias = storedPendingAlias(prefs)
            )
        ) {
            EnrollmentRecordCleanupAction.AlreadyApplied -> true
            EnrollmentRecordCleanupAction.Refuse -> false
            EnrollmentRecordCleanupAction.Apply -> clearPending(context)
        }
    }

    private fun hasCompleteActiveEnrollment(prefs: android.content.SharedPreferences): Boolean =
        prefs.contains(SERVER_URL) && prefs.contains(DEVICE_ID) && prefs.contains(DECISION_API)

    private fun hasCompletePendingEnrollment(prefs: android.content.SharedPreferences): Boolean =
        prefs.contains(PENDING_SERVER_URL) &&
            prefs.contains(PENDING_DEVICE_ID) &&
            prefs.contains(PENDING_DECISION_API)

    private fun storedActiveAlias(prefs: android.content.SharedPreferences): String =
        prefs.getString(SIGNING_KEY_ALIAS, null)
            ?.takeIf(String::isNotBlank)
            ?: WearKeyStore.DEFAULT_ALIAS

    private fun storedPendingAlias(prefs: android.content.SharedPreferences): String =
        prefs.getString(PENDING_SIGNING_KEY_ALIAS, null)
            ?.takeIf(String::isNotBlank)
            ?: WearKeyStore.DEFAULT_ALIAS

    fun clearPending(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(PENDING_SERVER_URL)
            .remove(PENDING_DEVICE_ID)
            .remove(PENDING_DECISION_API)
            .remove(PENDING_SIGNING_KEY_ALIAS)
            .commit()

    fun load(context: Context): WearEnrollment? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        load(
            serverUrl = prefs.getString(PENDING_SERVER_URL, null),
            deviceId = prefs.getString(PENDING_DEVICE_ID, null),
            decisionApi = prefs.getString(PENDING_DECISION_API, null),
            signingKeyAlias = prefs.getString(PENDING_SIGNING_KEY_ALIAS, null)
        )?.let { return it }
        return load(
            serverUrl = prefs.getString(SERVER_URL, null),
            deviceId = prefs.getString(DEVICE_ID, null),
            decisionApi = prefs.getString(DECISION_API, null),
            signingKeyAlias = prefs.getString(SIGNING_KEY_ALIAS, null)
        )
    }

    private fun load(
        serverUrl: String?,
        deviceId: String?,
        decisionApi: String?,
        signingKeyAlias: String?
    ): WearEnrollment? {
        val storedServerUrl = serverUrl ?: return null
        val storedDeviceId = deviceId ?: return null
        val storedDecisionApi = decisionApi ?: return null
        val storedSigningKeyAlias = signingKeyAlias
            ?.takeIf { it.isNotBlank() }
            ?: WearKeyStore.DEFAULT_ALIAS
        return WearEnrollment(
            serverUrl = storedServerUrl,
            deviceId = storedDeviceId,
            enrollmentToken = "",
            enrollApi = "/api/v1/devices/{id}/enroll",
            decisionApi = storedDecisionApi,
            signingKeyAlias = storedSigningKeyAlias
        )
    }

}

internal fun persistedEnrollmentSigningKeyAliases(
    hasActiveEnrollment: Boolean,
    activeAlias: String?,
    hasPendingEnrollment: Boolean,
    pendingAlias: String?
): Set<String> = buildSet {
    if (hasActiveEnrollment) add(activeAlias?.takeIf(String::isNotBlank) ?: WearKeyStore.DEFAULT_ALIAS)
    if (hasPendingEnrollment) add(pendingAlias?.takeIf(String::isNotBlank) ?: WearKeyStore.DEFAULT_ALIAS)
}

internal fun orphanedStagedSigningKeyAliases(
    discoveredAliases: Set<String>,
    referencedAliases: Set<String>
): Set<String> = discoveredAliases - referencedAliases
