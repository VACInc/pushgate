package org.pushgate.wear

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.security.PublicKey
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class WearDecisionSenderTest {
    @Test
    fun directSenderPostsWatchSignedApproveDecision() {
        withServer { server ->
            server.enqueue(MockResponse().setBody("""{"data":{"status":"approved"}}"""))
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
            val result = await { callback ->
                DirectWearDecisionSender().send(
                    enrollment(server),
                    challenge(),
                    WearDecision.Approve,
                    keyPair.private,
                    callback,
                    biometricVerified = true
                )
            }

            assertTrue(result.isSuccess)
            assertEquals(WearDecisionOutcome.Approved, result.getOrThrow())
            val request = server.takeRequest(2, TimeUnit.SECONDS)!!
            val body = JSONObject(request.body.readUtf8())
            assertEquals("/custom/auth/request-1/decision", request.path)
            assertEquals("watch-1", body.getString("device_id"))
            assertEquals("approve", body.getString("decision"))
            assertEquals(true, body.getBoolean("biometric_verified"))
            assertValidSignature(keyPair.public, body.getString("signature"), "request-1.approve.true")
        }
    }

    @Test
    fun directSenderPostsWatchSignedDenyDecision() {
        withServer { server ->
            server.enqueue(MockResponse().setBody("""{"data":{"status":"denied"}}"""))
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
            val result = await { callback ->
                DirectWearDecisionSender().send(
                    enrollment(server),
                    challenge(),
                    WearDecision.Deny,
                    keyPair.private,
                    callback,
                    biometricVerified = false
                )
            }

            assertTrue(result.isSuccess)
            assertEquals(WearDecisionOutcome.Denied, result.getOrThrow())
            val request = server.takeRequest(2, TimeUnit.SECONDS)!!
            val body = JSONObject(request.body.readUtf8())
            assertEquals("/custom/auth/request-1/decision", request.path)
            assertEquals("watch-1", body.getString("device_id"))
            assertEquals("deny", body.getString("decision"))
            assertEquals(false, body.getBoolean("biometric_verified"))
            assertValidSignature(keyPair.public, body.getString("signature"), "request-1.deny.false")
        }
    }

    @Test
    fun directSenderRejectsUnknownTerminalStatus() {
        withServer { server ->
            server.enqueue(MockResponse().setBody("""{"data":{"status":"rejected"}}"""))
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
            val result = await { callback ->
                DirectWearDecisionSender().send(enrollment(server), challenge(), WearDecision.Approve, keyPair.private, callback, biometricVerified = false)
            }

            assertTrue(result.isFailure)
            val request = server.takeRequest(2, TimeUnit.SECONDS)!!
            val body = JSONObject(request.body.readUtf8())
            assertEquals("approve", body.getString("decision"))
            assertEquals(false, body.getBoolean("biometric_verified"))
            assertValidSignature(keyPair.public, body.getString("signature"), "request-1.approve.false")
        }
    }

    @Test
    fun directSenderFailsClosedWhenSuccessfulResponseHasNoStatus() {
        withServer { server ->
            server.enqueue(MockResponse().setBody("""{"data":{"ok":true}}"""))
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()

            val result = await { callback ->
                DirectWearDecisionSender().send(
                    enrollment(server),
                    challenge(),
                    WearDecision.Deny,
                    keyPair.private,
                    callback,
                    biometricVerified = false
                )
            }

            assertTrue(result.isFailure)
        }
    }

    @Test
    fun directSenderReturnsActualServerStatusInsteadOfRequestedAction() {
        withServer { server ->
            server.enqueue(MockResponse().setBody("""{"data":{"status":"denied","first_response_wins":true}}"""))
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()

            val result = await { callback ->
                DirectWearDecisionSender().send(
                    enrollment(server),
                    challenge(),
                    WearDecision.Approve,
                    keyPair.private,
                    callback,
                    biometricVerified = true
                )
            }

            assertEquals(WearDecisionOutcome.Denied, result.getOrThrow())
        }
    }

    @Test
    fun directSenderReportsSynchronousRequestFailureExactlyOnce() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        var callbackCount = 0
        var result: Result<WearDecisionOutcome>? = null

        DirectWearDecisionSender().send(
            enrollmentFromUrl("://invalid"),
            challenge(),
            WearDecision.Deny,
            keyPair.private,
            {
                callbackCount += 1
                result = it
            },
            biometricVerified = false
        )

        assertEquals(1, callbackCount)
        assertTrue(requireNotNull(result).isFailure)
    }

    @Test
    fun directSenderDoesNotFollowSignedDecisionRedirects() {
        withServer { server ->
            server.enqueue(
                MockResponse()
                    .setResponseCode(307)
                    .setHeader("Location", server.url("/redirected"))
            )
            server.enqueue(MockResponse().setBody("""{"data":{"status":"denied"}}"""))
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()

            val result = await { callback ->
                DirectWearDecisionSender().send(
                    enrollment(server),
                    challenge(),
                    WearDecision.Deny,
                    keyPair.private,
                    callback,
                    biometricVerified = false
                )
            }

            assertTrue(result.isFailure)
            assertEquals(1, server.requestCount)
        }
    }

    @Test
    fun directSenderBoundsNoResponseForBroadcastCompletion() {
        withServer { server ->
            server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()

            val result = await { callback ->
                DirectWearDecisionSender(callTimeoutMillis = 100L).send(
                    enrollment(server),
                    challenge(),
                    WearDecision.Deny,
                    keyPair.private,
                    callback,
                    biometricVerified = false
                )
            }

            assertTrue(result.isFailure)
        }
    }

    @Test
    fun approvalFlowConvertsThrowingSenderIntoSingleFailureCallback() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val flow = WearApprovalFlow(sender = throwingSender())
        var callbackCount = 0
        var result: Result<WearDecisionOutcome>? = null

        flow.deny(
            enrollmentFromUrl("https://pushgate.example"),
            challenge(),
            keyPair.private
        ) {
            callbackCount += 1
            result = it
        }

        assertEquals(1, callbackCount)
        assertTrue(requireNotNull(result).isFailure)
    }

    @Test
    fun approvalFlowDoesNotSignOrSendExpiredChallenge() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        var sendCount = 0
        val sender = object : WearDecisionSender {
            override fun send(enrollment: WearEnrollment, challenge: WearChallenge, decision: WearDecision, privateKey: java.security.PrivateKey, callback: (Result<WearDecisionOutcome>) -> Unit, biometricVerified: Boolean) {
                sendCount += 1
                callback(Result.success(WearDecisionOutcome.Denied))
            }
        }
        var result: Result<WearDecisionOutcome>? = null

        WearApprovalFlow(sender = sender).deny(
            enrollmentFromUrl("https://pushgate.example"),
            challenge().copy(expiresAt = "2020-01-01T00:00:00Z"),
            keyPair.private
        ) { result = it }

        assertEquals(0, sendCount)
        assertTrue(requireNotNull(result).isFailure)
    }

    @Test
    fun relayProtocolBuildsWatchSignedDecisionPayload() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val body = JSONObject(
            WearRelayProtocol.decisionPayload(
                enrollmentFromUrl("https://pushgate.example"),
                challenge(),
                WearDecision.Approve,
                keyPair.private,
                biometricVerified = true
            )
        )

        assertEquals("request-1", body.getString("request_id"))
        assertEquals("watch-1", body.getString("device_id"))
        assertEquals("approve", body.getString("decision"))
        assertEquals(true, body.getBoolean("biometric_verified"))
        assertValidSignature(keyPair.public, body.getString("signature"), "request-1.approve.true")
    }

    @Test
    fun relayProtocolParsesTerminalPhoneAcknowledgement() {
        val result = WearRelayProtocol.decisionResultFromPayload(
            """{"request_id":"request-1","status":"denied"}""".toByteArray(Charsets.UTF_8)
        )

        assertEquals("request-1", result.requestId)
        assertEquals(WearDecisionOutcome.Denied, result.outcome)
        assertEquals(false, result.failed)
    }

    @Test
    fun relayProtocolTreatsPhoneFailureAsNonTerminalAcknowledgement() {
        val result = WearRelayProtocol.decisionResultFromPayload(
            """{"request_id":"request-1","error":"relay_failed"}""".toByteArray(Charsets.UTF_8)
        )

        assertEquals("request-1", result.requestId)
        assertEquals(null, result.outcome)
        assertEquals(true, result.failed)
    }

    @Test
    fun relayProtocolRejectsUnknownAcknowledgementStatus() {
        val result = runCatching {
            WearRelayProtocol.decisionResultFromPayload(
                """{"request_id":"request-1","status":"unexpected"}""".toByteArray(Charsets.UTF_8)
            )
        }

        assertTrue(result.isFailure)
    }

    @Test
    fun fallbackSenderUsesDirectSenderWhenRelayFails() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val sender = FallbackWearDecisionSender(
            failingSender(),
            succeedingSender(WearDecisionOutcome.Denied)
        )

        val result = await { callback ->
            sender.send(
                enrollmentFromUrl("https://pushgate.example"),
                challenge(),
                WearDecision.Deny,
                keyPair.private,
                callback,
                biometricVerified = false
            )
        }

        assertTrue(result.isSuccess)
        assertEquals(WearDecisionOutcome.Denied, result.getOrThrow())
    }

    @Test
    fun fallbackSenderUsesDirectSenderWhenRelayThrows() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val sender = FallbackWearDecisionSender(
            throwingSender(),
            succeedingSender(WearDecisionOutcome.Denied)
        )

        val result = await { callback ->
            sender.send(
                enrollmentFromUrl("https://pushgate.example"),
                challenge(),
                WearDecision.Deny,
                keyPair.private,
                callback,
                biometricVerified = false
            )
        }

        assertTrue(result.isSuccess)
        assertEquals(WearDecisionOutcome.Denied, result.getOrThrow())
    }

    @Test
    fun fallbackSenderConfirmsRelayedDecisionThroughDirectServerResponse() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val sender = FallbackWearDecisionSender(
            succeedingSender(WearDecisionOutcome.Pending),
            succeedingSender(WearDecisionOutcome.Approved)
        )

        val result = await { callback ->
            sender.send(
                enrollmentFromUrl("https://pushgate.example"),
                challenge(),
                WearDecision.Approve,
                keyPair.private,
                callback,
                biometricVerified = true
            )
        }

        assertEquals(WearDecisionOutcome.Approved, result.getOrThrow())
    }

    @Test
    fun fallbackSenderKeepsRelayedDecisionPendingWhenDirectConfirmationFails() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val sender = FallbackWearDecisionSender(
            succeedingSender(WearDecisionOutcome.Pending),
            failingSender()
        )

        val result = await { callback ->
            sender.send(
                enrollmentFromUrl("https://pushgate.example"),
                challenge(),
                WearDecision.Approve,
                keyPair.private,
                callback,
                biometricVerified = true
            )
        }

        assertEquals(WearDecisionOutcome.Pending, result.getOrThrow())
    }

    private fun enrollment(server: MockWebServer): WearEnrollment =
        enrollmentFromUrl(server.url("/").toString().trimEnd('/'))

    private fun enrollmentFromUrl(serverUrl: String): WearEnrollment =
        WearEnrollment(
            serverUrl = serverUrl,
            deviceId = "watch-1",
            enrollmentToken = "token-1",
            enrollApi = "/custom/devices/{id}/enroll",
            decisionApi = "/custom/auth/{id}/decision"
        )

    private fun failingSender(): WearDecisionSender =
        object : WearDecisionSender {
            override fun send(enrollment: WearEnrollment, challenge: WearChallenge, decision: WearDecision, privateKey: java.security.PrivateKey, callback: (Result<WearDecisionOutcome>) -> Unit, biometricVerified: Boolean) {
                callback(Result.failure(IOException("relay unavailable")))
            }
        }

    private fun throwingSender(): WearDecisionSender =
        object : WearDecisionSender {
            override fun send(enrollment: WearEnrollment, challenge: WearChallenge, decision: WearDecision, privateKey: java.security.PrivateKey, callback: (Result<WearDecisionOutcome>) -> Unit, biometricVerified: Boolean) {
                throw IOException("relay unavailable")
            }
        }

    private fun succeedingSender(outcome: WearDecisionOutcome): WearDecisionSender =
        object : WearDecisionSender {
            override fun send(enrollment: WearEnrollment, challenge: WearChallenge, decision: WearDecision, privateKey: java.security.PrivateKey, callback: (Result<WearDecisionOutcome>) -> Unit, biometricVerified: Boolean) {
                callback(Result.success(outcome))
            }
        }

    private fun withServer(block: (MockWebServer) -> Unit) {
        val server = MockWebServer()
        try {
            block(server)
        } finally {
            runCatching { server.shutdown() }
        }
    }

    private fun challenge(): WearChallenge =
        WearChallenge(
            id = "request-1",
            username = "alice",
            system = "labbox",
            pamService = "login",
            sourceIp = "10.0.0.5",
            geolocation = "New York, US",
            requestedAt = "2026-06-17T11:59:58Z",
            expiresAt = "2099-06-17T12:00:00Z",
            requireBiometric = true
        )

    private fun await(start: ((Result<WearDecisionOutcome>) -> Unit) -> Unit): Result<WearDecisionOutcome> {
        val latch = CountDownLatch(1)
        var result: Result<WearDecisionOutcome>? = null
        start {
            result = it
            latch.countDown()
        }
        assertTrue("callback timed out", latch.await(2, TimeUnit.SECONDS))
        return result ?: Result.failure(AssertionError("missing callback result"))
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
