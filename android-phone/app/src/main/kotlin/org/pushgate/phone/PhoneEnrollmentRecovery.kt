package org.pushgate.phone

internal fun shouldHandleEnrollmentResult(activeAttemptAlias: String?, completedAttemptAlias: String): Boolean =
    activeAttemptAlias == completedAttemptAlias

internal fun shouldFinalizePendingEnrollment(
    serverAccepted: Boolean,
    activeSigningKeyAlias: String,
    stagedSigningKeyAlias: String
): Boolean = serverAccepted || activeSigningKeyAlias == stagedSigningKeyAlias

internal enum class StagedKeyRecoveryResult {
    Cleaned,
    CleanupPending,
    JournalFailed
}

internal fun recoverStagedKeyAfterPendingSaveFailure(
    persistCleanupJournal: () -> Boolean,
    retryCleanup: () -> Boolean
): StagedKeyRecoveryResult {
    if (!persistCleanupJournal()) return StagedKeyRecoveryResult.JournalFailed
    return if (retryCleanup()) {
        StagedKeyRecoveryResult.Cleaned
    } else {
        StagedKeyRecoveryResult.CleanupPending
    }
}
