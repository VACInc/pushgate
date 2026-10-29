package org.pushgate.wear

data class StagedDeviceSigningKey(
    val alias: String,
    val signingKey: DeviceSigningKey
)

internal fun shouldHandleWearEnrollmentResult(
    activeAttemptAlias: String?,
    completedAttemptAlias: String
): Boolean = activeAttemptAlias == completedAttemptAlias

internal fun enrollmentBeforeNewAttempt(
    inMemoryEnrollment: WearEnrollment?,
    durableEnrollment: WearEnrollment?
): WearEnrollment? = inMemoryEnrollment ?: durableEnrollment

internal enum class EnrollmentFailureDisposition {
    RejectedRolledBack,
    RejectedRollbackFailed,
    RejectedCleanupPending,
    UncertainPreserved
}

internal data class EnrollmentFailureSettlement(
    val disposition: EnrollmentFailureDisposition,
    val cleanup: EnrollmentCleanupResult? = null
)

internal fun settleEnrollmentFailure(
    error: Throwable,
    stagedAlias: String,
    persistRollbackJournal: (String) -> Boolean,
    retryRollback: () -> EnrollmentCleanupResult
): EnrollmentFailureSettlement {
    if (error !is DefinitiveEnrollmentRejection && error !is EnrollmentRequestNotStarted) {
        return EnrollmentFailureSettlement(EnrollmentFailureDisposition.UncertainPreserved)
    }
    if (!persistRollbackJournal(stagedAlias)) {
        return EnrollmentFailureSettlement(EnrollmentFailureDisposition.RejectedRollbackFailed)
    }
    val cleanup = retryRollback()
    val disposition = when {
        !cleanup.recordsCleared -> EnrollmentFailureDisposition.RejectedRollbackFailed
        cleanup.complete -> EnrollmentFailureDisposition.RejectedRolledBack
        else -> EnrollmentFailureDisposition.RejectedCleanupPending
    }
    return EnrollmentFailureSettlement(disposition, cleanup)
}

internal enum class EnrollmentRecordCleanupAction {
    AlreadyApplied,
    Apply,
    Refuse
}

internal fun activationCleanupAction(
    expectedAlias: String,
    hasCompleteActiveEnrollment: Boolean,
    activeAlias: String?,
    hasCompletePendingEnrollment: Boolean,
    pendingAlias: String?
): EnrollmentRecordCleanupAction = when {
    hasCompleteActiveEnrollment && activeAlias == expectedAlias ->
        EnrollmentRecordCleanupAction.AlreadyApplied
    hasCompletePendingEnrollment && pendingAlias == expectedAlias ->
        EnrollmentRecordCleanupAction.Apply
    else -> EnrollmentRecordCleanupAction.Refuse
}

internal fun pendingRollbackCleanupAction(
    stagedAlias: String,
    hasActiveEnrollment: Boolean,
    activeAlias: String?,
    hasPendingEnrollment: Boolean,
    pendingAlias: String?
): EnrollmentRecordCleanupAction = when {
    hasPendingEnrollment && pendingAlias == stagedAlias ->
        EnrollmentRecordCleanupAction.Apply
    hasPendingEnrollment -> EnrollmentRecordCleanupAction.Refuse
    hasActiveEnrollment && activeAlias == stagedAlias ->
        EnrollmentRecordCleanupAction.Refuse
    else -> EnrollmentRecordCleanupAction.AlreadyApplied
}

internal data class EnrollmentCleanupResult(
    val recordsCleared: Boolean,
    val remainingAliases: Set<String>,
    val journalPending: Boolean
) {
    val complete: Boolean
        get() = recordsCleared && !journalPending
}

internal fun startEnrollmentCleanup(
    signingKeyAliases: Set<String>,
    persistCleanupJournal: (Set<String>) -> Boolean,
    retryCleanup: () -> EnrollmentCleanupResult
): EnrollmentCleanupResult {
    if (!persistCleanupJournal(signingKeyAliases)) {
        return EnrollmentCleanupResult(
            recordsCleared = false,
            remainingAliases = signingKeyAliases,
            journalPending = false
        )
    }
    return retryCleanup()
}

internal fun retryEnrollmentCleanup(
    loadCleanupAliases: () -> Set<String>,
    clearEnrollmentRecords: () -> Boolean,
    clearSigningKey: (String) -> Boolean,
    acknowledgeDeletedAlias: (String) -> Boolean,
    finishEmptyJournal: () -> Boolean,
    hasCleanupJournal: () -> Boolean
): EnrollmentCleanupResult {
    val aliases = runCatching(loadCleanupAliases).getOrElse {
        return EnrollmentCleanupResult(false, emptySet(), true)
    }
    if (!runCatching(clearEnrollmentRecords).getOrDefault(false)) {
        return EnrollmentCleanupResult(false, aliases, true)
    }

    val aliasesWithoutDurableAcknowledgement = mutableSetOf<String>()
    aliases.sorted().forEach { alias ->
        val deleted = runCatching { clearSigningKey(alias) }.getOrDefault(false)
        if (deleted) {
            // A successful deletion is idempotent. If this durable acknowledgement
            // fails, the alias remains in the journal and startup retries it.
            if (!runCatching { acknowledgeDeletedAlias(alias) }.getOrDefault(false)) {
                aliasesWithoutDurableAcknowledgement += alias
            }
        } else {
            aliasesWithoutDurableAcknowledgement += alias
        }
    }

    val remaining = runCatching(loadCleanupAliases).getOrElse { aliases }
        .plus(aliasesWithoutDurableAcknowledgement)
    var journalFinishSucceeded = false
    if (remaining.isEmpty()) {
        journalFinishSucceeded = runCatching(finishEmptyJournal).getOrDefault(false)
    }
    val journalPending = remaining.isNotEmpty() ||
        !journalFinishSucceeded ||
        runCatching(hasCleanupJournal).getOrDefault(true)
    return EnrollmentCleanupResult(
        recordsCleared = true,
        remainingAliases = remaining,
        journalPending = journalPending
    )
}

internal fun failedCleanupJournalRecreationMode(
    cleanup: EnrollmentCleanupResult,
    intendedMode: SigningKeyCleanupMode
): SigningKeyCleanupMode? = intendedMode.takeIf {
    !cleanup.recordsCleared && !cleanup.journalPending
}
