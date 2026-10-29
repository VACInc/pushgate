package org.pushgate.wear

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class EnrollmentKeyTransitionTest {
    @Test
    fun staleCallbackAfterClearOrReopenCannotApply() {
        assertFalse(shouldHandleWearEnrollmentResult(null, "staged-before-clear"))
        assertFalse(
            shouldHandleWearEnrollmentResult(
                activeAttemptAlias = "staged-after-reopen",
                completedAttemptAlias = "staged-before-clear"
            )
        )
    }

    @Test
    fun currentEnrollmentCallbackCanApply() {
        assertTrue(
            shouldHandleWearEnrollmentResult(
                activeAttemptAlias = "staged-current",
                completedAttemptAlias = "staged-current"
            )
        )
    }

    @Test
    fun deferredRollbackReloadsSurvivingActiveAliasBeforeNextAttempt() {
        val durable = enrollment("legacy-active")

        assertEquals(durable, enrollmentBeforeNewAttempt(null, durable))
        assertEquals(
            "legacy-active",
            enrollmentBeforeNewAttempt(null, durable)?.signingKeyAlias
        )
    }

    @Test
    fun failedPendingSaveUsesRollbackBeforeDeletingStagedKey() {
        val events = mutableListOf<String>()

        val result = startEnrollmentCleanup(
            signingKeyAliases = setOf("staged"),
            persistCleanupJournal = {
                events += "journal-rollback"
                true
            },
            retryCleanup = {
                events += "clear-pending-then-delete"
                EnrollmentCleanupResult(true, emptySet(), false)
            }
        )

        assertTrue(result.complete)
        assertEquals(listOf("journal-rollback", "clear-pending-then-delete"), events)
    }

    @Test
    fun activationJournalsPreviousAliasBeforePromotingPendingEnrollment() {
        val events = mutableListOf<String>()

        val result = startEnrollmentCleanup(
            signingKeyAliases = setOf("previous"),
            persistCleanupJournal = { aliases ->
                events += "journal:${aliases.single()}"
                true
            },
            retryCleanup = {
                events += "promote-pending-then-delete"
                EnrollmentCleanupResult(true, emptySet(), false)
            }
        )

        assertTrue(result.complete)
        assertEquals(listOf("journal:previous", "promote-pending-then-delete"), events)
    }

    @Test
    fun definitiveRejectionJournalsStagedAliasBeforePendingRollback() {
        val events = mutableListOf<String>()

        val settlement = settleEnrollmentFailure(
            error = DefinitiveEnrollmentRejection(403),
            stagedAlias = "staged",
            persistRollbackJournal = { alias ->
                events += "journal:$alias"
                true
            },
            retryRollback = {
                events += "clear-pending-then-delete"
                EnrollmentCleanupResult(true, emptySet(), false)
            }
        )

        assertEquals(EnrollmentFailureDisposition.RejectedRolledBack, settlement.disposition)
        assertEquals(listOf("journal:staged", "clear-pending-then-delete"), events)
    }

    @Test
    fun requestNotStartedJournalsStagedAliasAndRollsBackPendingState() {
        val events = mutableListOf<String>()

        val settlement = settleEnrollmentFailure(
            error = EnrollmentRequestNotStarted(IllegalArgumentException("invalid URL")),
            stagedAlias = "staged",
            persistRollbackJournal = { alias ->
                events += "journal:$alias"
                true
            },
            retryRollback = {
                events += "clear-pending-then-delete"
                EnrollmentCleanupResult(true, emptySet(), false)
            }
        )

        assertEquals(EnrollmentFailureDisposition.RejectedRolledBack, settlement.disposition)
        assertEquals(listOf("journal:staged", "clear-pending-then-delete"), events)
    }

    @Test
    fun ambiguousTransportFailurePreservesPendingStateAndBothKeys() {
        var journalWritten = false
        var retryCalled = false

        val settlement = settleEnrollmentFailure(
            error = IOException("connection lost"),
            stagedAlias = "staged",
            persistRollbackJournal = {
                journalWritten = true
                true
            },
            retryRollback = {
                retryCalled = true
                EnrollmentCleanupResult(true, emptySet(), false)
            }
        )

        assertEquals(EnrollmentFailureDisposition.UncertainPreserved, settlement.disposition)
        assertFalse(journalWritten)
        assertFalse(retryCalled)
    }

    @Test
    fun failedRollbackJournalKeepsPendingRecordAndStagedKeyUntouched() {
        var retryCalled = false

        val settlement = settleEnrollmentFailure(
            error = DefinitiveEnrollmentRejection(409),
            stagedAlias = "staged",
            persistRollbackJournal = { false },
            retryRollback = {
                retryCalled = true
                EnrollmentCleanupResult(true, emptySet(), false)
            }
        )

        assertEquals(EnrollmentFailureDisposition.RejectedRollbackFailed, settlement.disposition)
        assertFalse(retryCalled)
        assertEquals(null, settlement.cleanup)
    }

    @Test
    fun stagedKeyDeletionFailureAfterPendingRollbackRemainsRetryable() {
        val cleanup = EnrollmentCleanupResult(
            recordsCleared = true,
            remainingAliases = setOf("staged"),
            journalPending = true
        )

        val settlement = settleEnrollmentFailure(
            error = DefinitiveEnrollmentRejection(403),
            stagedAlias = "staged",
            persistRollbackJournal = { true },
            retryRollback = { cleanup }
        )

        assertEquals(EnrollmentFailureDisposition.RejectedCleanupPending, settlement.disposition)
        assertEquals(cleanup, settlement.cleanup)
    }

    @Test
    fun interruptedActivationPromotesExpectedPendingAliasBeforeOldKeyDeletion() {
        assertEquals(
            EnrollmentRecordCleanupAction.Apply,
            activationCleanupAction(
                expectedAlias = "staged",
                hasCompleteActiveEnrollment = true,
                activeAlias = "previous",
                hasCompletePendingEnrollment = true,
                pendingAlias = "staged"
            )
        )
        assertEquals(
            EnrollmentRecordCleanupAction.AlreadyApplied,
            activationCleanupAction(
                expectedAlias = "staged",
                hasCompleteActiveEnrollment = true,
                activeAlias = "staged",
                hasCompletePendingEnrollment = false,
                pendingAlias = null
            )
        )
    }

    @Test
    fun activationRefusesToDeleteOldKeyWhenExpectedReplacementIsNotDurable() {
        assertEquals(
            EnrollmentRecordCleanupAction.Refuse,
            activationCleanupAction(
                expectedAlias = "staged",
                hasCompleteActiveEnrollment = true,
                activeAlias = "previous",
                hasCompletePendingEnrollment = false,
                pendingAlias = null
            )
        )
    }

    @Test
    fun pendingRollbackIsIdempotentButNeverDeletesAnActiveStagedAlias() {
        assertEquals(
            EnrollmentRecordCleanupAction.Apply,
            pendingRollbackCleanupAction(
                stagedAlias = "staged",
                hasActiveEnrollment = true,
                activeAlias = "previous",
                hasPendingEnrollment = true,
                pendingAlias = "staged"
            )
        )
        assertEquals(
            EnrollmentRecordCleanupAction.AlreadyApplied,
            pendingRollbackCleanupAction(
                stagedAlias = "staged",
                hasActiveEnrollment = true,
                activeAlias = "previous",
                hasPendingEnrollment = false,
                pendingAlias = null
            )
        )
        assertEquals(
            EnrollmentRecordCleanupAction.Refuse,
            pendingRollbackCleanupAction(
                stagedAlias = "staged",
                hasActiveEnrollment = true,
                activeAlias = "staged",
                hasPendingEnrollment = false,
                pendingAlias = null
            )
        )
    }

    @Test
    fun clearEnrollmentPersistsAliasesBeforeClearingRecordsOrKeys() {
        val events = mutableListOf<String>()

        val result = startEnrollmentCleanup(
            signingKeyAliases = setOf("active", "staged"),
            persistCleanupJournal = { aliases ->
                events += "journal:${aliases.sorted().joinToString()}"
                true
            },
            retryCleanup = {
                events += "clear-records-and-keys"
                EnrollmentCleanupResult(true, emptySet(), false)
            }
        )

        assertTrue(result.complete)
        assertEquals(
            listOf("journal:active, staged", "clear-records-and-keys"),
            events
        )
    }

    @Test
    fun failedCleanupJournalWriteDoesNotClearRecordsOrKeys() {
        var retryCalled = false

        val result = startEnrollmentCleanup(
            signingKeyAliases = setOf("active", "staged"),
            persistCleanupJournal = { false },
            retryCleanup = {
                retryCalled = true
                EnrollmentCleanupResult(true, emptySet(), false)
            }
        )

        assertFalse(result.complete)
        assertFalse(result.recordsCleared)
        assertFalse(retryCalled)
        assertEquals(setOf("active", "staged"), result.remainingAliases)
    }

    @Test
    fun failedTransitionJournalWritesRemainRecreatableInProcess() {
        val failedWrite = EnrollmentCleanupResult(
            recordsCleared = false,
            remainingAliases = setOf("staged"),
            journalPending = false
        )

        assertEquals(
            SigningKeyCleanupMode.ActivatePending,
            failedCleanupJournalRecreationMode(
                failedWrite,
                SigningKeyCleanupMode.ActivatePending
            )
        )
        assertEquals(
            SigningKeyCleanupMode.RollbackPending,
            failedCleanupJournalRecreationMode(
                failedWrite,
                SigningKeyCleanupMode.RollbackPending
            )
        )
        assertEquals(
            null,
            failedCleanupJournalRecreationMode(
                failedWrite.copy(journalPending = true),
                SigningKeyCleanupMode.RollbackPending
            )
        )
    }

    @Test
    fun failedEnrollmentRecordClearDoesNotDeleteAnySigningKey() {
        val clearedKeys = mutableListOf<String>()

        val result = retryEnrollmentCleanup(
            loadCleanupAliases = { setOf("active", "staged") },
            clearEnrollmentRecords = { false },
            clearSigningKey = { alias ->
                clearedKeys += alias
                true
            },
            acknowledgeDeletedAlias = { true },
            finishEmptyJournal = { true },
            hasCleanupJournal = { true }
        )

        assertFalse(result.complete)
        assertFalse(result.recordsCleared)
        assertEquals(emptyList<String>(), clearedKeys)
    }

    @Test
    fun keyDeletionFailureRemainsJournaledAndNeverReportsComplete() {
        val journal = mutableSetOf("active", "staged")
        val attempted = mutableListOf<String>()

        val result = retryEnrollmentCleanup(
            loadCleanupAliases = { journal.toSet() },
            clearEnrollmentRecords = { true },
            clearSigningKey = { alias ->
                attempted += alias
                alias == "active"
            },
            acknowledgeDeletedAlias = { alias -> journal.remove(alias) },
            finishEmptyJournal = { false },
            hasCleanupJournal = { true }
        )

        assertFalse(result.complete)
        assertTrue(result.recordsCleared)
        assertEquals(listOf("active", "staged"), attempted)
        assertEquals(setOf("staged"), result.remainingAliases)
    }

    @Test
    fun failedDeletionIsRetriedAndCompletesOnNextStartup() {
        val journal = mutableSetOf("generated-uuid-alias")
        var journalPending = true
        var deletionAttempts = 0
        val retry = {
            retryEnrollmentCleanup(
                loadCleanupAliases = { journal.toSet() },
                clearEnrollmentRecords = { true },
                clearSigningKey = {
                    deletionAttempts += 1
                    deletionAttempts >= 2
                },
                acknowledgeDeletedAlias = { alias -> journal.remove(alias) },
                finishEmptyJournal = {
                    journalPending = false
                    true
                },
                hasCleanupJournal = { journalPending }
            )
        }

        val interrupted = retry()
        val recovered = retry()

        assertFalse(interrupted.complete)
        assertEquals(setOf("generated-uuid-alias"), interrupted.remainingAliases)
        assertTrue(recovered.complete)
        assertEquals(2, deletionAttempts)
    }

    @Test
    fun interruptionAfterKeyDeletionBeforeJournalAckRetriesIdempotently() {
        val journal = mutableSetOf("generated-uuid-alias")
        var journalPending = true
        var keyPresent = true
        var ackAttempts = 0
        val retry = {
            retryEnrollmentCleanup(
                loadCleanupAliases = { journal.toSet() },
                clearEnrollmentRecords = { true },
                clearSigningKey = {
                    // Deleting an already absent key is a successful retry.
                    keyPresent = false
                    true
                },
                acknowledgeDeletedAlias = { alias ->
                    ackAttempts += 1
                    if (ackAttempts == 1) false else journal.remove(alias)
                },
                finishEmptyJournal = {
                    journalPending = false
                    true
                },
                hasCleanupJournal = { journalPending }
            )
        }

        val interrupted = retry()
        val recovered = retry()

        assertFalse(interrupted.complete)
        assertFalse(keyPresent)
        assertEquals(setOf("generated-uuid-alias"), interrupted.remainingAliases)
        assertTrue(recovered.complete)
        assertEquals(2, ackAttempts)
    }

    @Test
    fun failedJournalAckCannotReportCompleteEvenIfProcessReadbackLooksEmpty() {
        val journal = mutableSetOf("generated-uuid-alias")

        val result = retryEnrollmentCleanup(
            loadCleanupAliases = { journal.toSet() },
            clearEnrollmentRecords = { true },
            clearSigningKey = { true },
            acknowledgeDeletedAlias = {
                // SharedPreferences commit can fail after its in-memory view changes.
                journal.clear()
                false
            },
            finishEmptyJournal = { true },
            hasCleanupJournal = { false }
        )

        assertFalse(result.complete)
        assertTrue(result.journalPending)
        assertEquals(setOf("generated-uuid-alias"), result.remainingAliases)
    }

    @Test
    fun emptyJournalMustBeDurablyFinishedBeforeReportingComplete() {
        var finishAttempts = 0
        var journalPending = true
        val retry = {
            retryEnrollmentCleanup(
                loadCleanupAliases = { emptySet() },
                clearEnrollmentRecords = { true },
                clearSigningKey = { true },
                acknowledgeDeletedAlias = { true },
                finishEmptyJournal = {
                    finishAttempts += 1
                    if (finishAttempts >= 2) journalPending = false
                    finishAttempts >= 2
                },
                hasCleanupJournal = { journalPending }
            )
        }

        assertFalse(retry().complete)
        assertTrue(retry().complete)
    }

    @Test
    fun legacyEnrollmentDefaultAliasIsJournaledAndDeleted() {
        val aliases = persistedEnrollmentSigningKeyAliases(
            hasActiveEnrollment = true,
            activeAlias = null,
            hasPendingEnrollment = true,
            pendingAlias = ""
        )
        val journal = aliases.toMutableSet()
        var journalPending = true
        val deleted = mutableListOf<String>()

        val result = retryEnrollmentCleanup(
            loadCleanupAliases = { journal.toSet() },
            clearEnrollmentRecords = { true },
            clearSigningKey = { alias ->
                deleted += alias
                true
            },
            acknowledgeDeletedAlias = { alias -> journal.remove(alias) },
            finishEmptyJournal = {
                journalPending = false
                true
            },
            hasCleanupJournal = { journalPending }
        )

        assertTrue(result.complete)
        assertEquals(listOf(WearKeyStore.DEFAULT_ALIAS), deleted)
    }

    @Test
    fun persistedAliasesIncludeActiveAndPendingWithLegacyFallback() {
        assertEquals(
            setOf("active", "staged"),
            persistedEnrollmentSigningKeyAliases(
                hasActiveEnrollment = true,
                activeAlias = "active",
                hasPendingEnrollment = true,
                pendingAlias = "staged"
            )
        )
        assertEquals(
            setOf(WearKeyStore.DEFAULT_ALIAS),
            persistedEnrollmentSigningKeyAliases(
                hasActiveEnrollment = true,
                activeAlias = null,
                hasPendingEnrollment = false,
                pendingAlias = null
            )
        )
    }


    @Test
    fun generatedStagedAliasesAreDiscoverableAcrossKeyBackends() {
        val androidAlias = "${WearKeyStore.STAGED_ALIAS_PREFIX}11111111-1111-1111-1111-111111111111"
        val softwareAlias = "${WearKeyStore.STAGED_ALIAS_PREFIX}22222222-2222-2222-2222-222222222222"

        val discovered = discoverGeneratedStagedSigningKeyAliases(
            androidAliases = setOf(
                androidAlias,
                WearKeyStore.DEFAULT_ALIAS,
                "${WearKeyStore.STAGED_ALIAS_PREFIX}not-a-uuid"
            ),
            softwarePreferenceKeys = setOf(
                "$softwareAlias.private.raw",
                "$softwareAlias.public.raw",
                "unrelated.preference",
                "${WearKeyStore.DEFAULT_ALIAS}.private.raw"
            )
        )

        assertEquals(setOf(androidAlias, softwareAlias), discovered)
    }

    @Test
    fun stagedDiscoveryIncludesIncompleteSoftwareKeyWrites() {
        val rawPrivateOnly = "${WearKeyStore.STAGED_ALIAS_PREFIX}33333333-3333-3333-3333-333333333333"
        val legacyPublicOnly = "${WearKeyStore.STAGED_ALIAS_PREFIX}44444444-4444-4444-4444-444444444444"

        assertEquals(
            setOf(rawPrivateOnly, legacyPublicOnly),
            discoverGeneratedStagedSigningKeyAliases(
                androidAliases = emptySet(),
                softwarePreferenceKeys = setOf(
                    "$rawPrivateOnly.private.raw",
                    "$legacyPublicOnly.public.x509"
                )
            )
        )
    }

    @Test
    fun orphanRecoveryExcludesAliasesReferencedByActiveOrPendingRecords() {
        val activeAlias = "${WearKeyStore.STAGED_ALIAS_PREFIX}11111111-1111-1111-1111-111111111111"
        val pendingAlias = "${WearKeyStore.STAGED_ALIAS_PREFIX}22222222-2222-2222-2222-222222222222"
        val orphanAlias = "${WearKeyStore.STAGED_ALIAS_PREFIX}33333333-3333-3333-3333-333333333333"

        assertEquals(
            setOf(orphanAlias),
            orphanedStagedSigningKeyAliases(
                discoveredAliases = setOf(activeAlias, pendingAlias, orphanAlias),
                referencedAliases = setOf(activeAlias, pendingAlias)
            )
        )
    }

    @Test
    fun orphanRecoveryDurablyJournalsBeforeDeletingDiscoveredAlias() {
        val orphanAlias = "${WearKeyStore.STAGED_ALIAS_PREFIX}33333333-3333-3333-3333-333333333333"
        val events = mutableListOf<String>()

        val result = startEnrollmentCleanup(
            signingKeyAliases = orphanedStagedSigningKeyAliases(
                discoveredAliases = setOf(orphanAlias),
                referencedAliases = emptySet()
            ),
            persistCleanupJournal = { aliases ->
                events += "journal:${aliases.single()}"
                true
            },
            retryCleanup = {
                events += "delete:$orphanAlias"
                EnrollmentCleanupResult(true, emptySet(), false)
            }
        )

        assertTrue(result.complete)
        assertEquals(listOf("journal:$orphanAlias", "delete:$orphanAlias"), events)
    }

    private fun enrollment(alias: String) = WearEnrollment(
        serverUrl = "https://pushgate.example",
        deviceId = "watch-1",
        enrollmentToken = "",
        enrollApi = "/api/v1/devices/{id}/enroll",
        decisionApi = "/api/v1/auth/requests/{id}/decision",
        signingKeyAlias = alias
    )
}
