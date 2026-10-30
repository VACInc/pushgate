package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Test

class AuthNotificationTextTest {
    @Test
    fun formatsCompactSshRequest() {
        val challenge = AuthChallenge(
            id = "request-1",
            username = "alice",
            system = "gateway-1",
            pamService = "ssh",
            sourceIp = "192.0.2.10",
            geolocation = "Example City",
            requestedAt = "2026-07-21T15:00:00Z",
            expiresAt = "2026-07-21T15:01:00Z",
            requireBiometric = true
        )

        assertEquals(
            "alice requests gateway-1 from 192.0.2.10",
            notificationText(challenge)
        )
    }

    @Test
    fun stripsPromptSpoofingControlsAndBidiFormatting() {
        val challenge = AuthChallenge(
            id = "request-1",
            username = "alice\nadmin",
            system = "gateway\u202Etxt.exe",
            pamService = "ss\u2066h",
            sourceIp = "192.0.2.10\rTrusted",
            geolocation = null,
            requestedAt = null,
            expiresAt = "2099-01-01T00:00:00Z",
            requireBiometric = true
        )

        assertEquals(
            "alice admin requests gateway txt.exe from 192.0.2.10 Trusted",
            notificationText(challenge)
        )
    }

    @Test
    fun namesTheHostOnceWhenTheServiceIsTheHostName() {
        val challenge = challenge(system = "server01", pamService = "server01")

        assertEquals("serviceuser requests server01 from 192.0.2.10", notificationText(challenge))
    }

    @Test
    fun putsAGivenReasonOnASecondLine() {
        val challenge = challenge(reason = "Read disk health\nnow")

        assertEquals(
            "serviceuser requests server01 from 192.0.2.10\nRead disk health now",
            notificationText(challenge)
        )
    }

    @Test
    fun readsTheReasonFromTheServerEventDetail() {
        val json = org.json.JSONObject()
            .put("id", "request-1")
            .put("username", "serviceuser")
            .put("system", "server01")
            .put("pam_service", "server01")
            .put("source_ip", "192.0.2.10")
            .put("expires_at", "2099-01-01T00:00:00Z")
            .put("detail", org.json.JSONObject().put("reason", "Check backups"))

        assertEquals(
            "serviceuser requests server01 from 192.0.2.10\nCheck backups",
            notificationText(AuthChallenge.fromJson(json))
        )
        assertEquals(
            "Check backups",
            org.json.JSONObject(PhoneWearRelayProtocol.challengePayload(AuthChallenge.fromJson(json)))
                .getJSONObject("data").getString("reason")
        )
    }

    private fun challenge(
        system: String = "server01",
        pamService: String = "server01",
        reason: String? = null
    ) = AuthChallenge(
        id = "request-1",
        username = "serviceuser",
        system = system,
        pamService = pamService,
        sourceIp = "192.0.2.10",
        geolocation = null,
        requestedAt = null,
        expiresAt = "2099-01-01T00:00:00Z",
        requireBiometric = true,
        reason = reason
    )
}
