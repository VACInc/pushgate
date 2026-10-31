package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/** The server owns every word of request text; the phone shows it exactly as sent. */
class AuthNotificationTextTest {
    @Test
    fun showsTheServerTitleAndLineVerbatim() {
        val challenge = challenge(pushText = "Agent requests SSH from workstation to server01", pushTitle = "PushGate")

        assertEquals("Agent requests SSH from workstation to server01", notificationText(challenge))
        assertEquals("PushGate", notificationTitle(challenge))
    }

    @Test
    fun anyServerWordingIsShownWithoutAnAppRule() {
        // A wording the app has never seen, with raw fields that an app-side rule would rewrite.
        val challenge = challenge(
            username = "agent",
            pamService = "server01",
            pushText = "Robot asks to log in to server01 (from desk)",
            pushTitle = "Gatekeeper"
        )

        assertEquals("Robot asks to log in to server01 (from desk)", notificationText(challenge))
        assertEquals("Gatekeeper", notificationTitle(challenge))
    }

    @Test
    fun olderServerWithoutTextGetsTheMinimalFallback() {
        val challenge = challenge(username = "alice", system = "gateway-1", pamService = "sshd")

        assertEquals("alice requests access to gateway-1", notificationText(challenge))
        assertEquals("PushGate", notificationTitle(challenge))
        assertEquals("PushGate", notificationTitle(challenge(pushTitle = " ")))
    }

    @Test
    fun fallbackPlaceholdersForMissingFields() {
        assertEquals("Unknown user requests access to unknown host", notificationText(challenge(username = "", system = "")))
    }

    @Test
    fun stripsPromptSpoofingControlsAndBidiFormatting() {
        val fallback = notificationText(challenge(username = "alice\nadmin", system = "gateway‮txt.exe"))
        assertEquals("alice admin requests access to gateway txt.exe", fallback)

        val spoofed = notificationText(challenge(pushText = "Agent requests SSH\nApproved‮ from x to y"))
        assertFalse(spoofed.contains('\n'))
        assertEquals("Agent requests SSH Approved from x to y", spoofed)
        assertEquals("Push Gate", notificationTitle(challenge(pushTitle = "Push\nGate")))
    }

    @Test
    fun neverAddsAReasonLine() {
        val json = org.json.JSONObject()
            .put("id", "request-1")
            .put("username", "serviceuser")
            .put("system", "server01")
            .put("pam_service", "SSH access")
            .put("source_ip", "192.0.2.10")
            .put("expires_at", "2099-01-01T00:00:00Z")
            .put("push_text", "Agent requests SSH from workstation to server01")
            .put("reason", "Check backups")
            .put("detail", org.json.JSONObject().put("reason", "Check backups"))

        assertEquals("Agent requests SSH from workstation to server01", notificationText(AuthChallenge.fromJson(json)))
    }

    @Test
    fun serverTextParsesAndRidesToTheWatch() {
        val json = org.json.JSONObject()
            .put("id", "request-1")
            .put("username", "serviceuser")
            .put("system", "server01")
            .put("pam_service", "SSH access")
            .put("source_ip", "192.0.2.10")
            .put("expires_at", "2099-01-01T00:00:00Z")
            .put("push_text", "Agent requests SSH from workstation to server01")
            .put("push_title", "PushGate")
        val challenge = AuthChallenge.fromJson(json)

        assertEquals("Agent requests SSH from workstation to server01", challenge.pushText)
        assertEquals("PushGate", challenge.pushTitle)
        val relayed = org.json.JSONObject(PhoneWearRelayProtocol.challengePayload(challenge)).getJSONObject("data")
        assertEquals("Agent requests SSH from workstation to server01", relayed.getString("push_text"))
        assertEquals("PushGate", relayed.getString("push_title"))
        assertFalse(relayed.has("reason"))
    }

    @Test
    fun pendingDenialKeepsTheServerText() {
        val denial = PendingDenial(
            challenge(pushText = "Agent requests SSH from workstation to server01", pushTitle = "PushGate"),
            NotificationEnrollmentBinding("phone-1", "alias-1")
        )
        val restored = PendingDenial.fromJson(denial.toJson()).challenge

        assertEquals("Agent requests SSH from workstation to server01", restored.pushText)
        assertEquals("PushGate", restored.pushTitle)
    }

    private fun challenge(
        username: String = "serviceuser",
        system: String = "server01",
        pamService: String = "SSH access",
        sourceIp: String? = "192.0.2.10",
        pushText: String? = null,
        pushTitle: String? = null
    ) = AuthChallenge(
        id = "request-1",
        username = username,
        system = system,
        pamService = pamService,
        sourceIp = sourceIp,
        geolocation = null,
        requestedAt = null,
        expiresAt = "2099-01-01T00:00:00Z",
        requireBiometric = true,
        pushText = pushText,
        pushTitle = pushTitle
    )
}
