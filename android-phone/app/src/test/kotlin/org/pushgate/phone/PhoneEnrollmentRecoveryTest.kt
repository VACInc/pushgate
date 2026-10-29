package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PhoneEnrollmentRecoveryTest {
    @Test
    fun onlyCurrentEnrollmentAttemptMayApplyLateResult() {
        assertTrue(shouldHandleEnrollmentResult("staged-current", "staged-current"))
        assertFalse(shouldHandleEnrollmentResult(null, "staged-cleared"))
        assertFalse(shouldHandleEnrollmentResult("staged-new", "staged-old"))
    }

    @Test
    fun acceptedPendingEnrollmentCanFinalizeAfterRestart() {
        assertTrue(
            shouldFinalizePendingEnrollment(
                serverAccepted = true,
                activeSigningKeyAlias = "previous",
                stagedSigningKeyAlias = "staged"
            )
        )
    }

    @Test
    fun selectedStagedAliasIsAlsoDurableAcceptanceMarker() {
        assertTrue(
            shouldFinalizePendingEnrollment(
                serverAccepted = false,
                activeSigningKeyAlias = "staged",
                stagedSigningKeyAlias = "staged"
            )
        )
        assertFalse(
            shouldFinalizePendingEnrollment(
                serverAccepted = false,
                activeSigningKeyAlias = "previous",
                stagedSigningKeyAlias = "staged"
            )
        )
    }

    @Test
    fun enrollmentCleanupCoversActiveDefaultStagedAndPreviousAliases() {
        assertEquals(
            setOf("legacy", "active", "staged", "previous"),
            persistedPhoneSigningKeyAliases(
                defaultAlias = "legacy",
                activeAlias = "active",
                pendingAliases = setOf("staged", "previous", "")
            )
        )
    }

    @Test
    fun pendingSaveFailureJournalsStagedAliasBeforeDeletingKey() {
        val events = mutableListOf<String>()

        val result = recoverStagedKeyAfterPendingSaveFailure(
            persistCleanupJournal = {
                events += "journal:staged"
                true
            },
            retryCleanup = {
                events += "delete:staged"
                true
            }
        )

        assertEquals(StagedKeyRecoveryResult.Cleaned, result)
        assertEquals(listOf("journal:staged", "delete:staged"), events)
    }

    @Test
    fun failedStagedKeyDeletionRemainsPendingForStartupRetry() {
        var deletionAttempts = 0

        val result = recoverStagedKeyAfterPendingSaveFailure(
            persistCleanupJournal = { true },
            retryCleanup = {
                deletionAttempts += 1
                false
            }
        )

        assertEquals(StagedKeyRecoveryResult.CleanupPending, result)
        assertEquals(1, deletionAttempts)
    }

    @Test
    fun failedCleanupJournalDoesNotDeleteUntrackedStagedKey() {
        var deletionAttempted = false

        val result = recoverStagedKeyAfterPendingSaveFailure(
            persistCleanupJournal = { false },
            retryCleanup = {
                deletionAttempted = true
                true
            }
        )

        assertEquals(StagedKeyRecoveryResult.JournalFailed, result)
        assertFalse(deletionAttempted)
    }

    @Test
    fun unjournaledStagedKeysAreRediscoveredAfterRestart() {
        val discovered = persistedStagedPhoneSigningKeyAliases(
            stagedAliasPrefix = "phone-key.pending.",
            keyStoreAliases = setOf(
                "phone-key",
                "phone-key.pending.hardware",
                "unrelated.pending.key"
            ),
            softwarePreferenceKeys = setOf(
                "phone-key.pending.software.private.raw",
                "phone-key.pending.incomplete.public.raw",
                "phone-key.public.raw",
                "unrelated.preference"
            )
        )

        assertEquals(
            setOf(
                "phone-key.pending.hardware",
                "phone-key.pending.software",
                "phone-key.pending.incomplete"
            ),
            discovered
        )
    }

    @Test
    fun rediscoveryNeverTreatsActiveOrPendingStagedKeysAsOrphans() {
        assertEquals(
            setOf("staged-orphan"),
            orphanedStagedPhoneSigningKeyAliases(
                discoveredAliases = setOf("staged-active", "staged-pending", "staged-orphan"),
                referencedAliases = setOf("staged-active", "staged-pending")
            )
        )
    }
}
