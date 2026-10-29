package org.pushgate.wear

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WearAuthNotificationDispatcherTest {
    @Test
    fun formatsConcisePushGateRequest() {
        assertEquals(
            "alice requests sshd on bastion from 192.0.2.10",
            wearNotificationText(challenge(pamService = "ssh", sourceIp = "192.0.2.10"))
        )
    }

    @Test
    fun usesSafeLabelsForMissingFields() {
        assertEquals(
            "Unknown user requests authentication on unknown device from unknown IP",
            wearNotificationText(challenge(username = "", pamService = "", system = "", sourceIp = ""))
        )
    }

    @Test
    fun notificationActionsAreBoundToTheEnrollmentSigningIdentity() {
        val current = enrollment("staged-current")

        assertTrue(isWearNotificationEnrollmentCurrent("staged-current", current))
        assertFalse(isWearNotificationEnrollmentCurrent("staged-previous", current))
        assertFalse(isWearNotificationEnrollmentCurrent(null, current))
        assertFalse(isWearNotificationEnrollmentCurrent("staged-current", null))
    }

    @Test
    fun notificationTimeoutUsesOnlyValidRemainingChallengeLifetime() {
        val challenge = challenge().copy(expiresAt = "2030-01-01T00:00:10Z")
        val now = 1_893_456_000_000L

        assertEquals(10_000L, wearChallengeRemainingMillis(challenge, now))
        assertEquals(null, wearChallengeRemainingMillis(challenge, now + 10_000L))
        assertEquals(null, wearChallengeRemainingMillis(challenge.copy(expiresAt = "invalid"), now))
        assertEquals(null, wearChallengeRemainingMillis(challenge.copy(id = ""), now))
    }

    private fun challenge(
        username: String = "alice",
        pamService: String = "sshd",
        system: String = "bastion",
        sourceIp: String? = null
    ) = WearChallenge(
        id = "request-1",
        username = username,
        system = system,
        pamService = pamService,
        sourceIp = sourceIp,
        geolocation = null,
        requestedAt = null,
        expiresAt = "2099-01-01T00:00:00Z",
        requireBiometric = true
    )

    private fun enrollment(alias: String) = WearEnrollment(
        serverUrl = "https://pushgate.example",
        deviceId = "watch-1",
        enrollmentToken = "",
        enrollApi = "/api/v1/devices/{id}/enroll",
        decisionApi = "/api/v1/auth/requests/{id}/decision",
        signingKeyAlias = alias
    )
}
