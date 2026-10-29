package org.pushgate.wear

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.PublicKey
import java.util.Base64

class WearWireFormatTest {
    @Test
    fun enrollmentPayloadUsesApiDefaultsAndTrimsServerUrl() {
        val enrollment = WearEnrollment.fromPayload(
            "https://pushgate.example/",
            """{"device_id":"watch-1","enrollment_token":"token-1"}"""
        )

        assertEquals("https://pushgate.example", enrollment.serverUrl)
        assertEquals("watch-1", enrollment.deviceId)
        assertEquals("token-1", enrollment.enrollmentToken)
        assertEquals("/api/v1/devices/{id}/enroll", enrollment.enrollApi)
        assertEquals("/api/v1/auth/requests/{id}/decision", enrollment.decisionApi)
    }

    @Test
    fun apiEndpointsRemainOnTheConfiguredOrigin() {
        val endpoint = resolveWearEndpoint(
            "https://pushgate.example",
            "/custom/auth/{id}/decision",
            "request/with/slash"
        )

        assertEquals("pushgate.example", endpoint.host)
        assertEquals("/custom/auth/request%2Fwith%2Fslash/decision", endpoint.encodedPath)
    }

    @Test
    fun apiEndpointsPreserveTheConfiguredServerPathPrefix() {
        val endpoint = resolveWearEndpoint(
            "https://pushgate.example/pushgate/",
            "/api/v1/auth/requests/{id}/decision",
            "request/with/slash"
        )

        assertEquals("pushgate.example", endpoint.host)
        assertEquals(
            "/pushgate/api/v1/auth/requests/request%2Fwith%2Fslash/decision",
            endpoint.encodedPath
        )
    }

    @Test
    fun enrollmentRejectsCrossOriginAndAmbiguousApiPaths() {
        val rejectedPaths = listOf(
            "@evil.example/enroll",
            "//evil.example/enroll",
            "https://evil.example/enroll",
            "/\\evil.example/enroll",
            "/enroll#fragment",
            "/enroll?next=//evil.example",
            "/../api/v1/enroll",
            "/%2e%2e/api/v1/enroll",
            "/.%2E/api/v1/enroll"
        )

        rejectedPaths.forEach { path ->
            val result = runCatching {
                WearEnrollment.fromPayload(
                    "https://pushgate.example",
                    """{"device_id":"watch-1","enrollment_token":"token-1","enroll_api":"$path"}"""
                )
            }
            assertTrue("path should be rejected: $path", result.isFailure)
        }
        assertTrue(
            runCatching {
                WearEnrollment.fromPayload(
                    "https://trusted.example@evil.example",
                    """{"device_id":"watch-1","enrollment_token":"token-1"}"""
                )
            }.isFailure
        )
    }

    @Test
    fun websocketAuthRequestPayloadLoadsChallengeData() {
        val challenge = WearChallenge.fromPayload(
            """
            {
              "type":"auth_request",
              "data":{
                "id":"request-1",
                "username":"alice",
                "system":"labbox",
                "pam_service":"login",
                "source_ip":"10.0.0.5",
                "geolocation":"New York, US",
                "requested_at":"2026-06-17T11:59:58Z",
                "expires_at":"2026-06-17T12:00:00Z",
                "require_biometric":false
              }
            }
            """
        )

        assertEquals("request-1", challenge.id)
        assertEquals("alice", challenge.username)
        assertEquals("labbox", challenge.system)
        assertEquals("login", challenge.pamService)
        assertEquals("10.0.0.5", challenge.sourceIp)
        assertEquals("New York, US", challenge.geolocation)
        assertEquals("2026-06-17T11:59:58Z", challenge.requestedAt)
        assertEquals("2026-06-17T12:00:00Z", challenge.expiresAt)
        assertEquals(false, challenge.requireBiometric)
    }

    @Test
    fun websocketAuthRequestReadsLocationAndTimestampFromDetailFallback() {
        val challenge = WearChallenge.fromPayload(
            """
            {
              "id":"request-1",
              "created_at":"2026-06-17T11:58:00Z",
              "detail":{"geolocation":"Paris, FR","timestamp":"2026-06-17T11:59:00Z"}
            }
            """
        )

        assertEquals("Paris, FR", challenge.geolocation)
        assertEquals("2026-06-17T11:59:00Z", challenge.requestedAt)
    }

    @Test
    fun websocketAuthRequestDefaultsToBiometricRequiredWhenMissing() {
        val challenge = WearChallenge.fromPayload("""{"id":"request-1"}""")

        assertEquals(true, challenge.requireBiometric)
        assertEquals(null, challenge.geolocation)
        assertEquals(null, challenge.requestedAt)
    }

    @Test
    fun challengeActionabilityFailsClosedOnExpiredOrMalformedExpiration() {
        val valid = WearChallenge.fromPayload(
            """{"id":"request-1","expires_at":"2099-01-01T00:00:00Z"}"""
        )
        val expired = WearChallenge.fromPayload(
            """{"id":"request-2","expires_at":"2020-01-01T00:00:00Z"}"""
        )
        val malformed = WearChallenge.fromPayload(
            """{"id":"request-3","expires_at":"not-a-time"}"""
        )
        val missing = WearChallenge.fromPayload("""{"id":"request-4"}""")

        assertTrue(isWearChallengeActionable(valid, nowEpochMillis = 1_800_000_000_000L))
        assertFalse(isWearChallengeActionable(expired, nowEpochMillis = 1_800_000_000_000L))
        assertFalse(isWearChallengeActionable(malformed, nowEpochMillis = 1_800_000_000_000L))
        assertFalse(isWearChallengeActionable(missing, nowEpochMillis = 1_800_000_000_000L))
    }

    @Test
    fun wearDecisionSignerSignsServerCanonicalMessage() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val signature = WearDecisionSigner.sign(keyPair.private, "request-1", WearDecision.Approve, biometricVerified = true)

        assertValidSignature(keyPair.public, signature, "request-1.approve.true")
    }

    @Test
    fun wearDenySignatureIncludesExplicitNoBiometricAssertion() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val signature = WearDecisionSigner.sign(
            keyPair.private,
            "request-2",
            WearDecision.Deny,
            biometricVerified = false
        )

        assertValidSignature(keyPair.public, signature, "request-2.deny.false")
    }

    private fun assertValidSignature(publicKey: PublicKey, encodedSignature: String, message: String) {
        assertTrue(
            Ed25519Crypto.verifyRawPublicKey(
                Ed25519Crypto.rawPublicKey(publicKey),
                message.toByteArray(Charsets.UTF_8),
                Base64.getDecoder().decode(encodedSignature)
            )
        )
    }
}
