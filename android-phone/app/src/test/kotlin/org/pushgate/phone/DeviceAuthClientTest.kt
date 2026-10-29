package org.pushgate.phone

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import okhttp3.OkHttpClient
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.security.PublicKey
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class DeviceAuthClientTest {
    @Test
    fun enrollPostsEnrollmentTokenPublicKeyAndPushToken() {
        withServer { server ->
            server.enqueue(MockResponse().setBody("""{"data":{"ok":true}}"""))
            val enrollment = enrollment(server)
            val result = await { callback ->
                DeviceAuthClient().enroll(enrollment, "public-key-1", "fcm-token-1", callback)
            }

            assertTrue(result.isSuccess)
            val request = server.takeRequest(2, TimeUnit.SECONDS)!!
            val body = JSONObject(request.body.readUtf8())
            assertEquals("/custom/devices/phone-1/enroll", request.path)
            assertEquals("token-1", body.getString("enrollment_token"))
            assertEquals("public-key-1", body.getString("public_key"))
            assertEquals("ed25519", body.getString("key_type"))
            assertEquals("fcm-token-1", body.getString("push_token"))
        }
    }

    @Test
    fun enrollment4xxIsDefinitiveAndCanDiscardRecoveryState() {
        withServer { server ->
            server.enqueue(MockResponse().setResponseCode(403))

            val result = await { callback ->
                DeviceAuthClient().enroll(enrollment(server), "public-key-1", callback = callback)
            }

            val error = result.exceptionOrNull()
            assertTrue(error is EnrollmentHttpException)
            assertEquals(403, (error as EnrollmentHttpException).statusCode)
            assertTrue(!shouldPreserveEnrollmentRecovery(error))
        }
    }

    @Test
    fun enrollment5xxRemainsAmbiguousAndPreservesRecoveryState() {
        withServer { server ->
            server.enqueue(MockResponse().setResponseCode(500))

            val result = await { callback ->
                DeviceAuthClient().enroll(enrollment(server), "public-key-1", callback = callback)
            }

            val error = result.exceptionOrNull()
            assertTrue(error is EnrollmentHttpException)
            assertEquals(500, (error as EnrollmentHttpException).statusCode)
            assertTrue(shouldPreserveEnrollmentRecovery(error))
        }
    }

    @Test
    fun enrollmentTransportFailurePreservesRecoveryState() {
        assertTrue(shouldPreserveEnrollmentRecovery(IOException("connection interrupted")))
        assertTrue(shouldPreserveEnrollmentRecovery(EnrollmentHttpException(408)))
    }

    @Test
    fun enrollmentCallCanBeCanceledWhenActivityOwnerIsDestroyed() {
        withServer { server ->
            server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
            val latch = CountDownLatch(1)
            var result: Result<String>? = null

            val call = DeviceAuthClient().enroll(enrollment(server), "public-key-1") {
                result = it
                latch.countDown()
            }
            assertTrue(server.takeRequest(2, TimeUnit.SECONDS) != null)
            call.cancel()

            assertTrue("canceled enrollment did not finish", latch.await(2, TimeUnit.SECONDS))
            assertTrue(result?.isFailure == true)
        }
    }

    @Test
    fun deviceTransportDisablesAutomaticRetriesAndRedirectsOnlyOnDerivedClient() {
        val base = OkHttpClient.Builder()
            .retryOnConnectionFailure(true)
            .followRedirects(true)
            .followSslRedirects(true)
            .build()

        val hardenedHttp = hardenedDeviceHttpClient(base)

        assertTrue(base.retryOnConnectionFailure)
        assertTrue(base.followRedirects)
        assertTrue(base.followSslRedirects)
        assertTrue(!hardenedHttp.retryOnConnectionFailure)
        assertTrue(!hardenedHttp.followRedirects)
        assertTrue(!hardenedHttp.followSslRedirects)
    }

    @Test
    fun enrollmentRedirectIsReturnedWithoutReplayingTokenToRedirectDestination() {
        withServer { server ->
            server.enqueue(
                MockResponse()
                    .setResponseCode(307)
                    .addHeader("Location", server.url("/redirected-enrollment"))
            )
            server.enqueue(MockResponse().setBody("""{"data":{"ok":true}}"""))

            val result = await { callback ->
                DeviceAuthClient().enroll(enrollment(server), "public-key-1", callback = callback)
            }

            val error = result.exceptionOrNull()
            assertTrue(error is EnrollmentHttpException)
            assertEquals(307, (error as EnrollmentHttpException).statusCode)
            assertEquals(1, server.requestCount)
            assertEquals("/custom/devices/phone-1/enroll", server.takeRequest(2, TimeUnit.SECONDS)?.path)
        }
    }

    @Test
    fun decisionRedirectIsReturnedWithoutReplayingSignedBodyToRedirectDestination() {
        val redirectTarget = MockWebServer()
        try {
            withServer { server ->
                server.enqueue(
                    MockResponse()
                        .setResponseCode(302)
                        .addHeader("Location", redirectTarget.url("/captured-decision"))
                )
                redirectTarget.enqueue(MockResponse().setBody("""{"data":{"status":"approved"}}"""))
                val keyPair = Ed25519Crypto.generateSoftwareKeyPair()

                val result = await { callback ->
                    DeviceAuthClient().decide(
                        enrollment(server),
                        "request-redirect",
                        Decision.Approve,
                        keyPair.private,
                        callback,
                        biometricVerified = true
                    )
                }

                assertTrue(result.isFailure)
                assertEquals(1, server.requestCount)
                assertEquals(0, redirectTarget.requestCount)
            }
        } finally {
            runCatching { redirectTarget.shutdown() }
        }
    }

    @Test
    fun updatePushTokenPostsSignedDeviceRequest() {
        withServer { server ->
            server.enqueue(MockResponse().setBody("""{"data":{"ok":true}}"""))
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
            val enrollment = enrollment(server)
            val result = await { callback ->
                DeviceAuthClient().updatePushToken(enrollment, keyPair.private, "fcm-token-2", callback)
            }

            assertTrue(result.isSuccess)
            val request = server.takeRequest(2, TimeUnit.SECONDS)!!
            val body = JSONObject(request.body.readUtf8())
            assertEquals("/api/v1/devices/phone-1/push-token", request.path)
            assertEquals("fcm-token-2", body.getString("push_token"))
            assertValidSignature(
                keyPair.public,
                body.getString("signature"),
                "push_token.phone-1.${body.getString("timestamp")}.${body.getString("nonce")}.fcm-token-2"
            )
        }
    }

    @Test
    fun decidePostsSignedDecisionBody() {
        withServer { server ->
            server.enqueue(MockResponse().setBody("""{"data":{"status":"approved"}}"""))
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
            val enrollment = enrollment(server)
            val result = await { callback ->
                DeviceAuthClient().decide(enrollment, "request-1", Decision.Approve, keyPair.private, callback, biometricVerified = true)
            }

            assertTrue(result.isSuccess)
            val request = server.takeRequest(2, TimeUnit.SECONDS)!!
            val body = JSONObject(request.body.readUtf8())
            assertEquals("/custom/auth/request-1/decision", request.path)
            assertEquals("phone-1", body.getString("device_id"))
            assertEquals("approve", body.getString("decision"))
            assertEquals(true, body.getBoolean("biometric_verified"))
            assertValidSignature(keyPair.public, body.getString("signature"), "request-1.approve.true")
        }
    }

    @Test
    fun decisionRequiresMatchingTerminalServerStatus() {
        listOf(
            """{"data":{"status":"pending"}}""",
            """{"data":{"status":"denied"}}""",
            """{"data":{"status":"timeout"}}""",
            """{"data":{"status":"already_resolved"}}""",
            """{"data":{"status":"unknown"}}""",
            "{}",
            "not-json"
        ).forEach { responseBody ->
            val result = validateDecisionResponse(responseBody, Decision.Approve)
            assertTrue("Expected failure for $responseBody", result.isFailure)
        }

        assertTrue(
            validateDecisionResponse("""{"data":{"status":"approved"}}""", Decision.Approve).isSuccess
        )
        assertTrue(
            validateDecisionResponse("""{"data":{"status":"denied"}}""", Decision.Deny).isSuccess
        )
    }

    @Test
    fun postDecisionBodyForwardsSignedWearDecisionBody() {
        withServer { server ->
            server.enqueue(MockResponse().setBody("""{"data":{"status":"approved"}}"""))
            val body = """{"device_id":"watch-1","decision":"approve","biometric_verified":true,"signature":"sig-1"}"""
            val result = await { callback ->
                DeviceAuthClient().postDecisionBody(enrollment(server), "request-1", body, callback)
            }

            assertTrue(result.isSuccess)
            val request = server.takeRequest(2, TimeUnit.SECONDS)!!
            assertEquals("/custom/auth/request-1/decision", request.path)
            assertEquals(body, request.body.readUtf8())
        }
    }

    private fun enrollment(server: MockWebServer): Enrollment =
        Enrollment(
            serverUrl = server.url("/").toString().trimEnd('/'),
            deviceId = "phone-1",
            enrollmentToken = "token-1",
            enrollApi = "/custom/devices/{id}/enroll",
            decisionApi = "/custom/auth/{id}/decision"
        )

    private fun withServer(block: (MockWebServer) -> Unit) {
        val server = MockWebServer()
        try {
            block(server)
        } finally {
            runCatching { server.shutdown() }
        }
    }

    private fun await(start: ((Result<String>) -> Unit) -> Unit): Result<String> {
        val latch = CountDownLatch(1)
        var result: Result<String>? = null
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
