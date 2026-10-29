package org.pushgate.wear

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class WearDecisionCompletionTest {
    @Test
    fun terminalResultCancelsNotificationPath() {
        var terminal: WearDecisionOutcome? = null
        var retained = false

        handleWearNotificationDecisionResult(
            Result.success(WearDecisionOutcome.Denied),
            onTerminal = { terminal = it },
            onRetained = { retained = true }
        )

        assertEquals(WearDecisionOutcome.Denied, terminal)
        assertFalse(retained)
    }

    @Test
    fun pendingAndFailureRetainNotificationForRetry() {
        var terminalCount = 0
        var retainedCount = 0
        val handler: (Result<WearDecisionOutcome>) -> Unit = { result ->
            handleWearNotificationDecisionResult(
                result,
                onTerminal = { terminalCount += 1 },
                onRetained = { retainedCount += 1 }
            )
        }

        handler(Result.success(WearDecisionOutcome.Pending))
        handler(Result.failure(IOException("biometric canceled")))

        assertEquals(0, terminalCount)
        assertEquals(2, retainedCount)
    }

    @Test
    fun resolvedChallengeIsBoundToEnrollmentAndRequestId() {
        val requestId = "resolved-${System.nanoTime()}"
        val resolved = enrollment("alias-a").decisionBinding(requestId)
        val otherEnrollment = enrollment("alias-b").decisionBinding(requestId)
        val otherRequest = enrollment("alias-a").decisionBinding("other-$requestId")

        WearResolvedChallenges.mark(resolved)

        assertFalse(WearResolvedChallenges.consume(otherEnrollment))
        assertFalse(WearResolvedChallenges.consume(otherRequest))
        assertTrue(WearResolvedChallenges.consume(resolved))
        assertFalse(WearResolvedChallenges.consume(resolved))
    }

    @Test
    fun completionRequiresMatchingEnrollmentAndRequest() {
        val enrollmentA = enrollment("alias-a")
        val enrollmentB = enrollment("alias-b")
        val binding = enrollmentA.decisionBinding("request-a")

        assertTrue(binding.matches(enrollmentA, "request-a"))
        assertFalse(binding.matches(enrollmentA, "request-b"))
        assertFalse(binding.matches(enrollmentB, "request-a"))
        assertFalse(binding.matches(null, "request-a"))
    }

    @Test
    fun inFlightOwnershipAllowsOnlyOneDecisionPerEnrollmentRequest() {
        val binding = enrollment("alias-${System.nanoTime()}").decisionBinding("request-1")

        assertTrue(WearInFlightDecisions.tryAcquire(binding))
        assertFalse(WearInFlightDecisions.tryAcquire(binding))
        WearInFlightDecisions.release(binding)
        assertTrue(WearInFlightDecisions.tryAcquire(binding))
        WearInFlightDecisions.release(binding)
    }

    @Test
    fun callbacksFromClosedOrReplacedInboxesCannotApply() {
        val current = TestInbox()
        val replaced = TestInbox()

        assertTrue(shouldHandleWearInboxEvent(current, current))
        assertFalse(shouldHandleWearInboxEvent(current, replaced))
        assertFalse(shouldHandleWearInboxEvent(null, replaced))
    }

    private class TestInbox : WearChallengeInbox {
        override fun start(onChallenge: (WearChallenge) -> Unit, onError: (Throwable) -> Unit) = Unit
        override fun close() = Unit
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
