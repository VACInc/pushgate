package org.pushgate.wear

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WearAuthNotificationDispatcherTest {
    @Test
    fun showsTheServerTitleAndLineVerbatim() {
        val payload = """{"type":"auth_request","data":{"id":"r1","username":"agent","system":"bastion","pam_service":"SSH access","source_ip":"workstation","expires_at":"2099-01-01T00:00:00Z","push_text":"Agent requests SSH from workstation to bastion","push_title":"PushGate"}}"""
        val challenge = WearChallenge.fromPayload(payload)

        assertEquals("Agent requests SSH from workstation to bastion", wearNotificationText(challenge))
        assertEquals("PushGate", wearNotificationTitle(challenge))
        assertEquals("PushGate", challenge.pushTitle)
        // A wording the app has no rule for is shown as it is.
        val other = challenge().copy(pamService = "bastion", pushText = "Robot asks to log in to bastion", pushTitle = "Gatekeeper")
        assertEquals("Robot asks to log in to bastion", wearNotificationText(other))
        assertEquals("Gatekeeper", wearNotificationTitle(other))
        assertEquals(
            "Agent requests SSH Approved from x to y",
            wearNotificationText(challenge().copy(pushText = "Agent requests SSH\nApproved\u202e from x to y"))
        )
    }

    @Test
    fun olderServerWithoutTextGetsTheMinimalFallback() {
        assertEquals("alice requests access to bastion", wearNotificationText(challenge(pamService = "ssh", sourceIp = "192.0.2.10")))
        assertEquals("PushGate", wearNotificationTitle(challenge()))
        assertEquals("PushGate", wearNotificationTitle(challenge().copy(pushTitle = " ")))
    }

    @Test
    fun usesSafeLabelsForMissingFields() {
        assertEquals(
            "Unknown user requests access to unknown host",
            wearNotificationText(challenge(username = "", pamService = "", system = "", sourceIp = ""))
        )
    }

    @Test
    fun neverShowsAReasonLine() {
        val payload = """{"type":"auth_request","data":{"id":"r1","username":"alice","system":"bastion","pam_service":"SSH access","source_ip":"192.0.2.10","expires_at":"2099-01-01T00:00:00Z","push_text":"Agent requests SSH from workstation to bastion","reason":"Check backups","detail":{"reason":"Check backups"}}}"""

        assertEquals("Agent requests SSH from workstation to bastion", wearNotificationText(WearChallenge.fromPayload(payload)))
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
