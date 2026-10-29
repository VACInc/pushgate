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
}
