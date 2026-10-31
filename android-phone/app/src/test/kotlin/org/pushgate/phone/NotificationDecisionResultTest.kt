package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Test

class NotificationDecisionResultTest {
    @Test
    fun successfulDecisionCancelsNotification() {
        val events = mutableListOf<String>()

        handleNotificationDecisionResult(
            result = Result.success("approved"),
            onSuccess = { events += "cancel" },
            onFailure = { events += "retain" }
        )

        assertEquals(listOf("cancel"), events)
    }

    @Test
    fun failedOrCanceledDecisionRetainsNotification() {
        val events = mutableListOf<String>()

        handleNotificationDecisionResult(
            result = Result.failure(SecurityException("canceled")),
            onSuccess = { events += "cancel" },
            onFailure = { events += "retain" }
        )

        assertEquals(listOf("retain"), events)
    }

    @Test
    fun alreadySettledApproveIsNotRetryable() {
        val failure = approveFailure(DecisionResponseException("x", "timeout"), stillActionable = true)

        assertEquals(ApproveFailure("Not approved: request was already timeout.", retryable = false), failure)
    }

    @Test
    fun expiredApproveIsNotRetryable() {
        val failure = approveFailure(java.io.IOException("offline"), stillActionable = false)

        assertEquals(false, failure.retryable)
        assertEquals("Not approved: request expired.", failure.message)
    }

    @Test
    fun transportFailureOnLiveRequestIsRetryable() {
        val failure = approveFailure(java.io.IOException("offline"), stillActionable = true)

        assertEquals(true, failure.retryable)
    }
}
