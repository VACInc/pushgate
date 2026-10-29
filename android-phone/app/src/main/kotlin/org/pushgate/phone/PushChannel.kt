package org.pushgate.phone

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.io.Closeable
import java.security.PrivateKey
import java.util.UUID
import java.io.IOException

interface PushChannel : Closeable {
    fun start(
        onChallenge: (AuthChallenge) -> Unit,
        onError: (Throwable) -> Unit,
        onReady: () -> Unit = {}
    )
}

class PhonePushChannel(
    enrollment: Enrollment,
    privateKey: PrivateKey,
    private val primary: PushChannel = FcmPushChannel(enrollment.deviceId),
    private val fallback: PushChannel = RecoveringPushChannel({ WebSocketPushChannel(enrollment, privateKey) })
) : PushChannel {
    private val seenChallengeIds = mutableSetOf<String>()

    override fun start(onChallenge: (AuthChallenge) -> Unit, onError: (Throwable) -> Unit, onReady: () -> Unit) {
        val deliverOnce: (AuthChallenge) -> Unit = { challenge ->
            val isNew = synchronized(seenChallengeIds) { seenChallengeIds.add(challenge.id) }
            if (isNew) onChallenge(challenge)
        }
        listOf(fallback, primary).forEach { channel ->
            runCatching { channel.start(deliverOnce, onError, onReady) }
                .onFailure { error -> reportError(onError, error) }
        }
    }

    override fun close() {
        runCatching { primary.close() }
        runCatching { fallback.close() }
        synchronized(seenChallengeIds) { seenChallengeIds.clear() }
    }

    private fun reportError(onError: (Throwable) -> Unit, error: Throwable) {
        runCatching { onError(error) }
    }
}

class WebSocketPushChannel(
    private val enrollment: Enrollment,
    private val privateKey: PrivateKey,
    http: OkHttpClient = OkHttpClient()
) : WebSocketListener(), PushChannel {
    private val http = hardenedDeviceHttpClient(http).newBuilder()
        .pingInterval(15, java.util.concurrent.TimeUnit.SECONDS).build()
    @Volatile
    private var socket: WebSocket? = null
    private var onChallenge: (AuthChallenge) -> Unit = {}
    private var onError: (Throwable) -> Unit = {}
    private var onReady: () -> Unit = {}
    @Volatile
    private var closedByClient = false
    @Volatile
    private var terminalReported = false

    override fun start(onChallenge: (AuthChallenge) -> Unit, onError: (Throwable) -> Unit, onReady: () -> Unit) {
        socket?.close(1000, "restarted")
        socket = null
        this.onChallenge = onChallenge
        this.onError = onError
        this.onReady = onReady
        closedByClient = false
        terminalReported = false
        socket = http.newWebSocket(Request.Builder().url(wsUrl()).build(), this)
    }

    override fun onOpen(webSocket: WebSocket, response: Response) {
        // A 101 response alone does not prove the server's delivery subscription.
        // Readiness follows the authenticated pending snapshot instead.
    }

    override fun onMessage(webSocket: WebSocket, text: String) {
        if (webSocket !== socket) return
        runCatching {
            require(text.length <= MAX_MESSAGE_CHARACTERS) { "Push message is too large" }
            val message = JSONObject(text)
            when (message.optString("type")) {
                "auth_request" -> AuthChallenge.fromJson(message.getJSONObject("data"))
                    .takeIf { it.isActionable() }
                    ?.let(onChallenge)
                "auth_decided" -> ChallengeResolution.fromJson(message)?.let(ChallengeResolutions::publish)
                "pending" -> {
                    val data = message.optJSONArray("data") ?: return@runCatching
                    onReady()
                    for (index in 0 until data.length()) {
                        AuthChallenge.fromJson(data.getJSONObject(index))
                            .takeIf { it.isActionable() }
                            ?.let(onChallenge)
                    }
                }
            }
        }.onFailure { error ->
            reportTerminal(PermanentPushFailure("Invalid push message", error))
            webSocket.close(1002, "invalid push message")
        }
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        if (webSocket !== socket) return
        reportTerminal(
            if (response != null && response.code in 400..499 && response.code !in setOf(408, 425, 429)) {
                PermanentPushFailure("Push authentication rejected (${response.code})", t)
            } else t
        )
    }

    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
        if (webSocket !== socket) return
        webSocket.close(code, reason)
    }

    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
        if (webSocket !== socket) return
        reportTerminal(
            if (code in setOf(1002, 1003, 1007, 1008)) PermanentPushFailure("Push connection rejected ($code)")
            else IOException("Push connection closed ($code)")
        )
    }

    override fun close() {
        closedByClient = true
        socket?.close(1000, "closed")
        socket = null
    }

    private fun reportTerminal(error: Throwable) {
        if (closedByClient || terminalReported) return
        terminalReported = true
        socket = null
        onError(error)
    }

    private fun wsUrl(): String {
        val timestamp = (System.currentTimeMillis() / 1000).toString()
        val nonce = UUID.randomUUID().toString()
        val signature = DecisionSigner.signMessage(privateKey, "ws.${enrollment.deviceId}.$timestamp.$nonce")
        val httpUrl = enrollment.endpointUrl("/api/v1/devices/{id}/ws", enrollment.deviceId)
            .newBuilder()
            .addQueryParameter("timestamp", timestamp)
            .addQueryParameter("nonce", nonce)
            .addQueryParameter("signature", signature)
            .build()
        return httpUrl.toString().replaceFirst(
            if (httpUrl.isHttps) "https://" else "http://",
            if (httpUrl.isHttps) "wss://" else "ws://"
        )
    }

    private companion object {
        const val MAX_MESSAGE_CHARACTERS = 65_536
    }
}
