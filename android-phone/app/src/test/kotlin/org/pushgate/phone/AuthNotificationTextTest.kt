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
            "alice requests sshd on gateway-1 from 192.0.2.10",
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
            "alice admin requests ss h on gateway txt.exe from 192.0.2.10 Trusted",
            notificationText(challenge)
        )
    }
}
