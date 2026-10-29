package org.pushgate.phone

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class PhoneWearRelayProtocolTest {
    @Test
    fun challengePayloadUsesWearDataLayerContract() {
        val payload = JSONObject(PhoneWearRelayProtocol.challengePayload(challenge()))
        val data = payload.getJSONObject("data")

        assertEquals("auth_request", payload.getString("type"))
        assertEquals("request-1", data.getString("id"))
        assertEquals("alice", data.getString("username"))
        assertEquals("labbox", data.getString("system"))
        assertEquals("sshd", data.getString("pam_service"))
        assertEquals("10.0.0.5", data.getString("source_ip"))
        assertEquals("New York, US", data.getString("geolocation"))
        assertEquals("2026-06-17T11:59:58Z", data.getString("requested_at"))
        assertEquals("2026-06-17T12:00:00Z", data.getString("expires_at"))
        assertEquals(true, data.getBoolean("require_biometric"))
    }

    @Test
    fun decisionPayloadBecomesServerDecisionBody() {
        val relayed = PhoneWearRelayProtocol.decisionFromPayload(
            """
            {
              "request_id":"request-1",
              "device_id":"watch-1",
              "decision":"approve",
              "biometric_verified":true,
              "signature":"sig-1"
            }
            """.trimIndent().toByteArray(Charsets.UTF_8)
        )
        val body = JSONObject(relayed.body)

        assertEquals("request-1", relayed.requestId)
        assertEquals("watch-1", body.getString("device_id"))
        assertEquals("approve", body.getString("decision"))
        assertEquals(true, body.getBoolean("biometric_verified"))
        assertEquals("sig-1", body.getString("signature"))
        assertFalse(body.has("request_id"))
    }

    @Test
    fun decisionResultPayloadAcknowledgesTerminalServerStatus() {
        val payload = JSONObject(
            PhoneWearRelayProtocol.decisionResultPayload(
                "request-1",
                Result.success("""{"data":{"status":"approved"}}""")
            )
        )

        assertEquals("request-1", payload.getString("request_id"))
        assertEquals("approved", payload.getString("status"))
        assertFalse(payload.has("error"))
    }

    @Test
    fun decisionResultPayloadFailsClosedWithoutKnownServerStatus() {
        val malformed = JSONObject(
            PhoneWearRelayProtocol.decisionResultPayload(
                "request-1",
                Result.success("""{"data":{"ok":true}}""")
            )
        )
        val failed = JSONObject(
            PhoneWearRelayProtocol.decisionResultPayload(
                "request-1",
                Result.failure<String>(IllegalStateException("sensitive detail"))
            )
        )

        assertEquals("invalid_server_response", malformed.getString("error"))
        assertEquals("relay_failed", failed.getString("error"))
        assertFalse(failed.toString().contains("sensitive detail"))
    }

    private fun challenge(): AuthChallenge =
        AuthChallenge(
            id = "request-1",
            username = "alice",
            system = "labbox",
            pamService = "sshd",
            sourceIp = "10.0.0.5",
            geolocation = "New York, US",
            requestedAt = "2026-06-17T11:59:58Z",
            expiresAt = "2026-06-17T12:00:00Z",
            requireBiometric = true
        )
}
