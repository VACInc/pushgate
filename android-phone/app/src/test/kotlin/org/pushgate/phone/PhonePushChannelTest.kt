package org.pushgate.phone

import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.PublicKey
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class PhonePushChannelTest {
    @Test
    fun fcmEntrypointParsesWrappedAndRawChallengePayloads() {
        val wrapped = FcmPushEntrypoint.challengeFromData(
            mapOf(
                "challenge" to """
                {
                  "type":"auth_request",
                  "data":{
                    "id":"request-1",
                    "username":"alice",
                    "system":"labbox",
                    "pam_service":"sshd",
                    "source_ip":"10.0.0.5",
                    "expires_at":"2026-06-17T12:00:00Z"
                  }
                }
                """
            )
        )
        val raw = FcmPushEntrypoint.challengeFromData(
            mapOf(
                "id" to "request-2",
                "username" to "bob",
                "system" to "nas",
                "pam_service" to "sudo",
                "expires_at" to "2026-06-17T12:01:00Z"
            )
        )

        assertEquals("request-1", wrapped.id)
        assertEquals("alice", wrapped.username)
        assertEquals("sshd", wrapped.pamService)
        assertEquals("10.0.0.5", wrapped.sourceIp)
        assertEquals("request-2", raw.id)
        assertEquals("bob", raw.username)
        assertEquals("sudo", raw.pamService)
        assertNull(raw.sourceIp)
    }

    @Test
    fun fcmEntrypointReportsMalformedPayloadWithoutThrowing() {
        var delivered = false
        val errors = mutableListOf<Throwable>()
        val subscription = FcmPushEntrypoint.register(
            deviceId = "phone-1",
            onChallenge = { delivered = true },
            onError = errors::add
        )

        try {
            FcmPushEntrypoint.onMessageData(mapOf("challenge" to "{not-json"))
        } finally {
            subscription.close()
        }

        assertEquals(false, delivered)
        assertEquals(1, errors.size)
    }

    @Test
    fun fcmBackgroundHandlerDispatchesNotificationFromDataPayloadWithoutForegroundListener() {
        val notified = mutableListOf<AuthChallenge>()
        val result = FcmBackgroundMessageHandler.showNotification(
            mapOf(
                "device_id" to "phone-1",
                "challenge" to """
                {
                  "type":"auth_request",
                  "data":{
                    "id":"request-background",
                    "username":"carol",
                    "system":"buildhost",
                    "pam_service":"sudo",
                    "source_ip":"10.0.0.9",
                    "expires_at":"2099-06-17T12:02:00Z"
                  }
                }
                """
            ),
            expectedDeviceId = "phone-1",
            notify = notified::add
        )

        assertTrue(result.isSuccess)
        assertEquals(listOf("request-background"), notified.map { it.id })
        assertEquals(listOf("buildhost"), notified.map { it.system })
        assertEquals(listOf("sudo"), notified.map { it.pamService })
    }

    @Test
    fun fcmBackgroundHandlerFailsSoftForMalformedPayload() {
        val notified = mutableListOf<AuthChallenge>()
        val result = FcmBackgroundMessageHandler.showNotification(
            mapOf("challenge" to "{not-json"),
            expectedDeviceId = "phone-1",
            notify = notified::add
        )

        assertTrue(result.isFailure)
        assertEquals(emptyList<AuthChallenge>(), notified)
    }

    @Test
    fun delayedFcmPayloadForPreviousEnrollmentIsIgnored() {
        val delivered = mutableListOf<String>()
        val errors = mutableListOf<Throwable>()
        val subscription = FcmPushEntrypoint.register(
            deviceId = "new-phone",
            onChallenge = { delivered += it.id },
            onError = errors::add
        )

        try {
            FcmPushEntrypoint.onMessageData(
                mapOf(
                    "device_id" to "old-phone",
                    "id" to "stale-request",
                    "expires_at" to "2099-06-17T12:01:00Z"
                )
            )
        } finally {
            subscription.close()
        }

        assertTrue(delivered.isEmpty())
        assertTrue(errors.isEmpty())
    }

    @Test
    fun websocketPushChannelUsesSignedHandshakeAndDeliversChallenge() {
        withServer { server ->
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
            val delivered = CountDownLatch(1)
            var challenge: AuthChallenge? = null
            server.enqueue(
                MockResponse().withWebSocketUpgrade(
                    object : WebSocketListener() {
                        override fun onOpen(webSocket: WebSocket, response: Response) {
                            webSocket.send(
                                """
                                {
                                  "type":"auth_request",
                                  "data":{
                                    "id":"request-1",
                                    "username":"alice",
                                    "system":"labbox",
                                    "pam_service":"login",
                                    "source_ip":"10.0.0.5",
                                    "expires_at":"2099-06-17T12:00:00Z"
                                  }
                                }
                                """
                            )
                        }
                    }
                )
            )

            val channel = WebSocketPushChannel(enrollment(server), keyPair.private, OkHttpClient())
            try {
                channel.start(
                    onChallenge = {
                        challenge = it
                        delivered.countDown()
                    },
                    onError = { throw AssertionError(it) }
                )

                val request = server.takeRequest(2, TimeUnit.SECONDS)!!
                val url = request.requestUrl!!
                assertEquals("/api/v1/devices/phone-1/ws", url.encodedPath)
                assertValidSignature(
                    keyPair.public,
                    url.queryParameter("signature")!!,
                    "ws.phone-1.${url.queryParameter("timestamp")}.${url.queryParameter("nonce")}"
                )
                assertTrue("challenge timed out", delivered.await(2, TimeUnit.SECONDS))
                assertEquals("request-1", challenge?.id)
                assertEquals("login", challenge?.pamService)
            } finally {
                channel.close()
            }
        }
    }

    @Test
    fun websocketReportsRemoteCleanClosureButNotLocalClose() {
        withServer { server ->
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
            val ready = CountDownLatch(1)
            val closed = CountDownLatch(1)
            val errors = CopyOnWriteArrayList<Throwable>()
            server.enqueue(
                MockResponse().withWebSocketUpgrade(
                    object : WebSocketListener() {
                        override fun onOpen(webSocket: WebSocket, response: Response) {
                            webSocket.send("""{"type":"pending","data":[]}""")
                            webSocket.close(1000, "server maintenance")
                        }
                    }
                )
            )
            val channel = WebSocketPushChannel(enrollment(server), keyPair.private, OkHttpClient())

            channel.start(
                onChallenge = {},
                onError = {
                    errors += it
                    closed.countDown()
                },
                onReady = ready::countDown
            )

            assertTrue("websocket never opened", ready.await(2, TimeUnit.SECONDS))
            assertTrue("clean remote closure was silent", closed.await(2, TimeUnit.SECONDS))
            assertEquals(1, errors.size)
            channel.close()
            Thread.sleep(100)
            assertEquals(1, errors.size)
        }
    }

    @Test
    fun firebaseTokenSyncReportsUnavailableProviderWithoutThrowing() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val failures = mutableListOf<Throwable>()
        val sync = FirebaseTokenSync(
            tokenProvider = object : FcmTokenProvider {
                override fun refreshCurrentToken(callback: (Result<String>) -> Unit) {
                    throw IllegalStateException("Default FirebaseApp is not initialized")
                }
            }
        )

        sync.start(enrollmentFromUrl("http://pushgate.test"), keyPair.private) { result ->
            result.onFailure(failures::add)
        }

        assertEquals(listOf("Default FirebaseApp is not initialized"), failures.map { it.message })
        sync.close()
    }

    @Test
    fun firebaseTokenSyncCloseDropsDelayedTokenBeforeUpload() {
        withServer { server ->
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
            var delayedResult: ((Result<String>) -> Unit)? = null
            val sync = FirebaseTokenSync(
                tokenProvider = object : FcmTokenProvider {
                    override fun refreshCurrentToken(callback: (Result<String>) -> Unit) {
                        delayedResult = callback
                    }
                }
            )

            sync.start(enrollment(server), keyPair.private)
            sync.close()
            delayedResult?.invoke(Result.success("late-token"))
            Thread.sleep(200)

            assertEquals(0, server.requestCount)
        }
    }

    @Test
    fun phonePushChannelSuppressesDuplicatePrimaryAndFallbackChallenges() {
        val primary = FakePushChannel()
        val fallback = FakePushChannel()
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val channel = PhonePushChannel(enrollmentFromUrl("http://pushgate.test"), keyPair.private, primary, fallback)
        val delivered = CopyOnWriteArrayList<AuthChallenge>()
        channel.start(onChallenge = delivered::add, onError = { throw AssertionError(it) })

        val challenge = AuthChallenge(
            id = "request-1",
            username = "alice",
            system = "labbox",
            pamService = "sshd",
            sourceIp = "10.0.0.5",
            geolocation = "New York, US",
            requestedAt = "2026-06-17T11:59:58Z",
            expiresAt = "2026-06-17T12:00:00Z",
            requireBiometric = false
        )
        primary.emit(challenge)
        fallback.emit(challenge.copy(system = "duplicate-source"))

        assertEquals(listOf("labbox"), delivered.map { it.system })

        channel.close()
        channel.start(onChallenge = delivered::add, onError = { throw AssertionError(it) })
        fallback.emit(challenge)
        assertEquals(listOf("labbox", "labbox"), delivered.map { it.system })
        channel.close()
    }

    @Test
    fun phonePushChannelStartsFallbackWhenPrimaryStartupFails() {
        val primary = FakePushChannel(startError = IllegalStateException("FCM unavailable"))
        val fallback = FakePushChannel()
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val channel = PhonePushChannel(enrollmentFromUrl("http://pushgate.test"), keyPair.private, primary, fallback)
        val delivered = mutableListOf<AuthChallenge>()
        val errors = mutableListOf<Throwable>()

        channel.start(onChallenge = delivered::add, onError = errors::add)
        fallback.emit(challenge("request-1", "labbox"))

        assertEquals(1, fallback.startCount)
        assertEquals(1, primary.startCount)
        assertEquals(listOf("labbox"), delivered.map { it.system })
        assertEquals(listOf("FCM unavailable"), errors.map { it.message })
        channel.close()
    }

    private fun enrollment(server: MockWebServer): Enrollment =
        enrollmentFromUrl(server.url("/").toString().trimEnd('/'))

    private fun enrollmentFromUrl(serverUrl: String): Enrollment =
        Enrollment(
            serverUrl = serverUrl,
            deviceId = "phone-1",
            enrollmentToken = "token-1",
            enrollApi = "/api/v1/devices/{id}/enroll",
            decisionApi = "/api/v1/auth/requests/{id}/decision"
        )

    private fun withServer(block: (MockWebServer) -> Unit) {
        val server = MockWebServer()
        try {
            block(server)
        } finally {
            runCatching { server.shutdown() }
        }
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

    private fun challenge(id: String, system: String): AuthChallenge =
        AuthChallenge(
            id = id,
            username = "alice",
            system = system,
            pamService = "sshd",
            sourceIp = "10.0.0.5",
            geolocation = "New York, US",
            requestedAt = "2026-06-17T11:59:58Z",
            expiresAt = "2026-06-17T12:00:00Z",
            requireBiometric = false
        )

    private class FakePushChannel(private val startError: RuntimeException? = null) : PushChannel {
        private var onChallenge: (AuthChallenge) -> Unit = {}
        var startCount = 0
            private set

        override fun start(onChallenge: (AuthChallenge) -> Unit, onError: (Throwable) -> Unit, onReady: () -> Unit) {
            startCount += 1
            startError?.let { throw it }
            this.onChallenge = onChallenge
        }

        override fun close() {
            onChallenge = {}
        }

        fun emit(challenge: AuthChallenge) {
            onChallenge(challenge)
        }
    }
}
