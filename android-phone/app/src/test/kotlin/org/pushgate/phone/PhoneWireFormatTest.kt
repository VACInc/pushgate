package org.pushgate.phone

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.PublicKey
import java.time.Instant
import java.util.Base64

class PhoneWireFormatTest {
    @Test
    fun enrollmentPayloadUsesApiDefaultsAndTrimsServerUrl() {
        val enrollment = Enrollment.fromQr(
            "https://pushgate.example.invalid/",
            """{"device_id":"phone-1","enrollment_token":"token-1"}"""
        )

        assertEquals("https://pushgate.example.invalid", enrollment.serverUrl)
        assertEquals("phone-1", enrollment.deviceId)
        assertEquals("token-1", enrollment.enrollmentToken)
        assertEquals("/api/v1/devices/{id}/enroll", enrollment.enrollApi)
        assertEquals("/api/v1/auth/requests/{id}/decision", enrollment.decisionApi)
    }

    @Test
    fun releaseServerUrlRequiresHttpsWithoutCredentialsQueryOrFragment() {
        assertEquals(
            "https://pushgate.example.invalid/base",
            canonicalServerUrl(" https://pushgate.example.invalid/base/ ", allowDebugCleartext = false)
        )
        listOf(
            "http://pushgate.example.invalid",
            "https://" + "user:pass@pushgate.example.invalid",
            "https://pushgate.example.invalid?redirect=evil",
            "https://pushgate.example.invalid/#fragment",
            "wss://pushgate.example.invalid"
        ).forEach { value ->
            assertThrows(IllegalArgumentException::class.java) {
                canonicalServerUrl(value, allowDebugCleartext = false)
            }
        }
        assertEquals(
            "http://10.0.2.2:8000",
            canonicalServerUrl("http://10.0.2.2:8000", allowDebugCleartext = true)
        )
        assertThrows(IllegalArgumentException::class.java) {
            canonicalServerUrl("http://192.0.2.20", allowDebugCleartext = true)
        }
    }

    @Test
    fun qrApiPathsCannotEscapeOrAmbiguouslyRewriteConfiguredOrigin() {
        listOf(
            "@evil.example/enroll/{id}",
            "https://evil.example/enroll/{id}",
            "//evil.example/enroll/{id}",
            "\\\\evil.example/enroll/{id}",
            "/api/enroll/{id}#fragment",
            "/api/enroll/{id}?next=evil",
            "/%2f%2fevil.example/enroll/{id}",
            "/api/%5cevil/{id}"
        ).forEach { path ->
            assertThrows(IllegalArgumentException::class.java) {
                Enrollment.fromQr(
                    "https://pushgate.example.invalid",
                    JSONObject()
                        .put("device_id", "phone-1")
                        .put("enrollment_token", "token-1")
                        .put("enroll_api", path)
                        .toString()
                )
            }
        }
    }

    @Test
    fun endpointEncodesIdsAndRemainsOnConfiguredOrigin() {
        val enrollment = Enrollment.fromQr(
            "https://pushgate.example.invalid:8443/base",
            """{"device_id":"phone/../other","enrollment_token":"token-1"}"""
        )

        val endpoint = enrollment.endpointUrl(enrollment.enrollApi, enrollment.deviceId)

        assertEquals("https", endpoint.scheme)
        assertEquals("pushgate.example.invalid", endpoint.host)
        assertEquals(8443, endpoint.port)
        assertEquals("/base/api/v1/devices/phone%2F..%2Fother/enroll", endpoint.encodedPath)
    }

    @Test
    fun challengePayloadKeepsSourceIpAndPamService() {
        val challenge = AuthChallenge.fromJson(
            JSONObject(
                """
                {
                  "id":"request-1",
                  "username":"alice",
                  "system":"labbox",
                  "pam_service":"sshd",
                  "source_ip":"10.0.0.5",
                  "geolocation":"New York, US",
                  "requested_at":"2026-06-17T11:59:58Z",
                  "expires_at":"2026-06-17T12:00:00Z",
                  "require_biometric":false
                }
                """
            )
        )

        assertEquals("request-1", challenge.id)
        assertEquals("alice", challenge.username)
        assertEquals("labbox", challenge.system)
        assertEquals("sshd", challenge.pamService)
        assertEquals("10.0.0.5", challenge.sourceIp)
        assertEquals("New York, US", challenge.geolocation)
        assertEquals("2026-06-17T11:59:58Z", challenge.requestedAt)
        assertEquals("2026-06-17T12:00:00Z", challenge.expiresAt)
        assertEquals(false, challenge.requireBiometric)
    }

    @Test
    fun challengePayloadReadsLocationAndTimestampFromDetailFallback() {
        val challenge = AuthChallenge.fromJson(
            JSONObject(
                """
                {
                  "id":"request-1",
                  "created_at":"2026-06-17T11:58:00Z",
                  "detail":{"geolocation":"Paris, FR","timestamp":"2026-06-17T11:59:00Z"}
                }
                """
            )
        )

        assertEquals("Paris, FR", challenge.geolocation)
        assertEquals("2026-06-17T11:59:00Z", challenge.requestedAt)
    }

    @Test
    fun challengePayloadDefaultsToBiometricRequiredWhenMissing() {
        val challenge = AuthChallenge.fromJson(JSONObject("""{"id":"request-1"}"""))

        assertEquals(true, challenge.requireBiometric)
        assertEquals(null, challenge.geolocation)
        assertEquals(null, challenge.requestedAt)
    }

    @Test
    fun challengeFreshnessFailsClosed() {
        val base = AuthChallenge(
            id = "request-1",
            username = "alice",
            system = "host",
            pamService = "sshd",
            sourceIp = null,
            geolocation = null,
            requestedAt = null,
            expiresAt = "2026-07-21T21:00:00Z",
            requireBiometric = true
        )

        assertTrue(base.isActionable(Instant.parse("2026-07-21T20:59:59Z")))
        assertFalse(base.isActionable(Instant.parse("2026-07-21T21:00:00Z")))
        assertFalse(base.copy(id = "").isActionable(Instant.parse("2026-07-21T20:00:00Z")))
        assertFalse(base.copy(expiresAt = "").isActionable(Instant.parse("2026-07-21T20:00:00Z")))
        assertFalse(base.copy(expiresAt = "not-a-time").isActionable(Instant.parse("2026-07-21T20:00:00Z")))
        assertEquals(1_000L, base.remainingLifetimeMillis(Instant.parse("2026-07-21T20:59:59Z")))
        assertEquals(null, base.remainingLifetimeMillis(Instant.parse("2026-07-21T21:00:00Z")))
    }

    @Test
    fun displayTextRemovesControlsBidiAndExcessLength() {
        val value = "alice\n\u202Eevil\u2066" + "x".repeat(200)
        val cleaned = safeDisplayText(value, maxLength = 24)

        assertEquals("alice evil xxxxxxxxxxxxx", cleaned)
        assertEquals(24, cleaned.length)
    }

    @Test
    fun decisionSignerSignsServerCanonicalMessage() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val signature = DecisionSigner.sign(keyPair.private, "request-1", Decision.Approve, biometricVerified = true)

        assertValidSignature(keyPair.public, signature, "request-1.approve.true")
    }

    @Test
    fun denySignatureDefaultsToNoBiometricAssertion() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val signature = DecisionSigner.sign(keyPair.private, "request-2", Decision.Deny)

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
