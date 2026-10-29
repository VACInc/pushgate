package org.pushgate.wear

import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.PublicKey
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class WearChallengeInboxTest {
    @Test
    fun standaloneInboxUsesSignedHandshakeAndDeliversPendingChallenges() {
        withServer { server ->
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
            val delivered = CountDownLatch(2)
            val challenges = mutableListOf<WearChallenge>()
            server.enqueue(
                MockResponse().withWebSocketUpgrade(
                    object : WebSocketListener() {
                        override fun onOpen(webSocket: WebSocket, response: Response) {
                            webSocket.send(
                                """
                                {
                                  "type":"pending",
                                  "data":[
                                    {
                                      "id":"request-1",
                                      "username":"alice",
                                      "system":"labbox",
                                      "pam_service":"login",
                                      "source_ip":"10.0.0.5",
                                      "expires_at":"2026-06-17T12:00:00Z"
                                    },
                                    {
                                      "id":"request-2",
                                      "username":"alice",
                                      "system":"nas",
                                      "pam_service":"sudo",
                                      "expires_at":"2026-06-17T12:01:00Z"
                                    }
                                  ]
                                }
                                """
                            )
                        }
                    }
                )
            )

            val inbox = StandaloneWebSocketChallengeInbox(enrollment(server), keyPair.private, OkHttpClient())
            try {
                inbox.start(
                    onChallenge = {
                        challenges.add(it)
                        delivered.countDown()
                    },
                    onError = { throw AssertionError(it) }
                )

                val request = server.takeRequest(2, TimeUnit.SECONDS)!!
                val url = request.requestUrl!!
                assertEquals("/api/v1/devices/watch-1/ws", url.encodedPath)
                assertValidSignature(
                    keyPair.public,
                    url.queryParameter("signature")!!,
                    "ws.watch-1.${url.queryParameter("timestamp")}.${url.queryParameter("nonce")}"
                )
                assertTrue("challenges timed out", delivered.await(2, TimeUnit.SECONDS))
                assertEquals(listOf("request-1", "request-2"), challenges.map { it.id })
                assertEquals(listOf("login", "sudo"), challenges.map { it.pamService })
            } finally {
                inbox.close()
            }
        }
    }

    @Test
    fun standaloneInboxReportsMalformedMessageAndKeepsListening() {
        withServer { server ->
            val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
            val failed = CountDownLatch(1)
            val delivered = CountDownLatch(1)
            val reportedError = AtomicReference<Throwable>()
            server.enqueue(
                MockResponse().withWebSocketUpgrade(
                    object : WebSocketListener() {
                        override fun onOpen(webSocket: WebSocket, response: Response) {
                            webSocket.send("""{"type":"auth_request","data":{}}""")
                            webSocket.send(
                                """{"type":"auth_request","data":{"id":"request-after-error","expires_at":"2099-01-01T00:00:00Z"}}"""
                            )
                        }
                    }
                )
            )

            val inbox = StandaloneWebSocketChallengeInbox(enrollment(server), keyPair.private)
            try {
                inbox.start(
                    onChallenge = { challenge ->
                        if (challenge.id == "request-after-error") delivered.countDown()
                    },
                    onError = { error ->
                        reportedError.set(error)
                        failed.countDown()
                    }
                )

                assertTrue("malformed message was not reported", failed.await(2, TimeUnit.SECONDS))
                assertTrue(reportedError.get() is RecoverableWearChallengeMessageException)
                assertTrue("listener stopped after malformed message", delivered.await(2, TimeUnit.SECONDS))
            } finally {
                inbox.close()
            }
        }
    }

    @Test
    fun phoneRelayInboxParsesRelayedPayloadAndReportsBadPayloads() {
        val delivered = CountDownLatch(1)
        val failed = CountDownLatch(1)
        val challenge = AtomicReference<WearChallenge>()
        lateinit var relayPayload: (String) -> Unit
        val inbox = PhoneRelayChallengeInbox { onPayload, _ ->
            relayPayload = onPayload
            TestCloseable {}
        }

        inbox.start(
            onChallenge = {
                challenge.set(it)
                delivered.countDown()
            },
            onError = { failed.countDown() }
        )

        relayPayload(
            """
            {
              "type":"auth_request",
              "data":{
                "id":"request-1",
                "username":"alice",
                "system":"labbox",
                "pam_service":"login",
                "source_ip":"10.0.0.5",
                "expires_at":"2026-06-17T12:00:00Z"
              }
            }
            """
        )
        relayPayload("""{"type":"auth_request","data":{}}""")

        assertTrue("relayed challenge timed out", delivered.await(2, TimeUnit.SECONDS))
        assertTrue("bad payload error timed out", failed.await(2, TimeUnit.SECONDS))
        assertEquals("request-1", challenge.get().id)
        assertEquals("login", challenge.get().pamService)
        inbox.close()
    }

    @Test
    fun deduplicatingInboxSuppressesRepeatedChallengeIdsAcrossSources() {
        val first = FakeInbox()
        val second = FakeInbox()
        val delivered = mutableListOf<WearChallenge>()
        val inbox = DeduplicatingWearChallengeInbox(listOf(first, second))

        inbox.start(onChallenge = delivered::add, onError = { throw AssertionError(it) })
        first.emit(challenge("request-1", "labbox"))
        second.emit(challenge("request-1", "duplicate"))
        second.emit(challenge("request-2", "nas"))

        assertEquals(listOf("labbox", "nas"), delivered.map { it.system })
        inbox.close()
    }

    @Test
    fun deduplicatingInboxContinuesWhenOneSourceFailsToStart() {
        val failing = FakeInbox(startError = IllegalStateException("Wear Data Layer unavailable"))
        val standalone = FakeInbox()
        val delivered = mutableListOf<WearChallenge>()
        val errors = mutableListOf<Throwable>()
        val inbox = DeduplicatingWearChallengeInbox(listOf(failing, standalone))

        inbox.start(onChallenge = delivered::add, onError = errors::add)
        standalone.emit(challenge("request-1", "labbox"))

        assertEquals(1, failing.startCount)
        assertEquals(1, standalone.startCount)
        assertEquals(listOf("labbox"), delivered.map { it.system })
        assertEquals(listOf("Wear Data Layer unavailable"), errors.map { it.message })
        inbox.close()
    }

    private fun enrollment(server: MockWebServer): WearEnrollment =
        WearEnrollment(
            serverUrl = server.url("/").toString().trimEnd('/'),
            deviceId = "watch-1",
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

    private fun challenge(id: String, system: String): WearChallenge =
        WearChallenge(
            id = id,
            username = "alice",
            system = system,
            pamService = "login",
            sourceIp = "10.0.0.5",
            geolocation = null,
            requestedAt = null,
            expiresAt = "2026-06-17T12:00:00Z",
            requireBiometric = true
        )

    private class FakeInbox(private val startError: RuntimeException? = null) : WearChallengeInbox {
        private var onChallenge: (WearChallenge) -> Unit = {}
        var startCount = 0
            private set

        override fun start(onChallenge: (WearChallenge) -> Unit, onError: (Throwable) -> Unit) {
            startCount += 1
            startError?.let { throw it }
            this.onChallenge = onChallenge
        }

        override fun close() {
            onChallenge = {}
        }

        fun emit(challenge: WearChallenge) {
            onChallenge(challenge)
        }
    }

    private class TestCloseable(private val block: () -> Unit) : java.io.Closeable {
        override fun close() = block()
    }
}
