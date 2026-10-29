package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class PendingDenialTest {
    private val bindingA = NotificationEnrollmentBinding("phone-a", "key-a")
    private val bindingB = NotificationEnrollmentBinding("phone-b", "key-b")

    @Test
    fun denialRoundTripRetainsEnrollmentBindingAndChallenge() {
        val denial = PendingDenial(challenge("request-1", "2099-01-01T00:00:00Z"), bindingA)

        assertEquals(denial, PendingDenial.fromJson(denial.toJson()))
    }

    @Test
    fun queueDeduplicatesOnlySameChallengeAndEnrollment() {
        val original = PendingDenial(challenge("request-1", "2099-01-01T00:00:00Z"), bindingA)
        val replacement = original.copy(challenge = original.challenge.copy(system = "new-host"))
        val otherEnrollment = PendingDenial(original.challenge, bindingB)

        val result = deduplicatePendingDenials(listOf(original, otherEnrollment), replacement)

        assertEquals(2, result.size)
        assertEquals("new-host", result.single { it.binding == bindingA }.challenge.system)
        assertEquals(bindingB, result.single { it.binding == bindingB }.binding)
    }

    @Test
    fun queuedDenialRequiresSameEnrollmentAndUnexpiredChallenge() {
        val denial = PendingDenial(challenge("request-1", "2026-07-21T21:00:00Z"), bindingA)

        assertTrue(denial.isDeliverable(bindingA, Instant.parse("2026-07-21T20:59:59Z")))
        assertFalse(denial.isDeliverable(bindingB, Instant.parse("2026-07-21T20:59:59Z")))
        assertFalse(denial.isDeliverable(bindingA, Instant.parse("2026-07-21T21:00:00Z")))
        assertFalse(denial.isDeliverable(null, Instant.parse("2026-07-21T20:59:59Z")))
    }

    @Test
    fun decisionClaimRoundTripAndConflictAreBoundToEnrollmentAndRequest() {
        val deny = DecisionClaim("request-1", "2099-01-01T00:00:00Z", bindingA, Decision.Deny)
        val approveSameRequest = deny.copy(decision = Decision.Approve)
        val approveOtherEnrollment = approveSameRequest.copy(binding = bindingB)

        assertEquals(deny, DecisionClaim.fromJson(deny.toJson()))
        assertTrue(deny.conflictsWith(approveSameRequest))
        assertFalse(deny.conflictsWith(approveOtherEnrollment))
        assertTrue(deny.isActive(bindingA, Instant.parse("2026-07-21T20:59:59Z")))
        assertFalse(deny.isActive(bindingB, Instant.parse("2026-07-21T20:59:59Z")))
    }

    @Test
    fun failedJobSchedulingRollsBackPendingDenialAndDecisionClaim() {
        val rollbacks = mutableListOf<String>()

        val result = finishPendingDenialScheduling(
            schedule = { false },
            removePendingDenial = { rollbacks += "pending denial" },
            releaseDecisionClaim = { rollbacks += "decision claim" }
        )

        assertFalse(result)
        assertEquals(listOf("pending denial", "decision claim"), rollbacks)
    }

    @Test
    fun successfulJobSchedulingKeepsPendingDenialAndDecisionClaim() {
        var rollbackCalled = false

        val result = finishPendingDenialScheduling(
            schedule = { true },
            removePendingDenial = { rollbackCalled = true },
            releaseDecisionClaim = { rollbackCalled = true }
        )

        assertTrue(result)
        assertFalse(rollbackCalled)
    }

    @Test
    fun thrownJobSchedulingRollsBackPendingDenialAndDecisionClaim() {
        val rollbacks = mutableListOf<String>()

        val result = finishPendingDenialScheduling(
            schedule = { throw IllegalStateException("scheduler rejected job") },
            removePendingDenial = { rollbacks += "pending denial" },
            releaseDecisionClaim = { rollbacks += "decision claim" }
        )

        assertFalse(result)
        assertEquals(listOf("pending denial", "decision claim"), rollbacks)
    }

    private fun challenge(id: String, expiresAt: String) = AuthChallenge(
        id = id,
        username = "alice",
        system = "host",
        pamService = "sshd",
        sourceIp = "192.0.2.10",
        geolocation = null,
        requestedAt = "2026-07-21T20:00:00Z",
        expiresAt = expiresAt,
        requireBiometric = false
    )
}
