package org.pushgate.wear

import android.content.Context
import com.google.android.gms.wearable.MessageClient
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.Wearable
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.io.Closeable
import java.io.IOException
import java.security.PrivateKey
import java.util.UUID

interface WearChallengeInbox : Closeable {
    fun start(onChallenge: (WearChallenge) -> Unit, onError: (Throwable) -> Unit)
}

internal class RecoverableWearChallengeMessageException(cause: Throwable) :
    IOException("Invalid push message", cause)

class StandaloneWebSocketChallengeInbox(
    private val enrollment: WearEnrollment,
    private val privateKey: PrivateKey,
    http: OkHttpClient = OkHttpClient()
) : WebSocketListener(), WearChallengeInbox {
    private val http = hardenedWearHttpClient(http)
    @Volatile
    private var socket: WebSocket? = null
    @Volatile
    private var acceptingEvents = false
    private var onChallenge: (WearChallenge) -> Unit = {}
    private var onError: (Throwable) -> Unit = {}

    override fun start(onChallenge: (WearChallenge) -> Unit, onError: (Throwable) -> Unit) {
        this.onChallenge = onChallenge
        this.onError = onError
        acceptingEvents = true
        runCatching {
            socket = http.newWebSocket(Request.Builder().url(wsUrl()).build(), this)
        }.onFailure { error ->
            acceptingEvents = false
            socket = null
            reportError(onError, error)
        }
    }

    override fun onMessage(webSocket: WebSocket, text: String) {
        if (!acceptingEvents || (socket != null && socket !== webSocket)) return
        runCatching { WearResolution.fromServerEvent(JSONObject(text)) }.getOrNull()?.let { resolution ->
            WearResolutions.publish(resolution)
            return
        }
        runCatching { wearChallengesFromWebSocketPayload(text) }
            .onSuccess { challenges -> challenges.forEach(onChallenge) }
            .onFailure { error ->
                reportError(onError, RecoverableWearChallengeMessageException(error))
            }
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        if (!acceptingEvents || (socket != null && socket !== webSocket)) return
        acceptingEvents = false
        socket = null
        reportError(onError, t)
    }

    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
        if (!acceptingEvents || (socket != null && socket !== webSocket)) return
        acceptingEvents = false
        socket = null
        reportError(onError, IOException("Push connection closed: $code"))
    }

    override fun close() {
        acceptingEvents = false
        val closingSocket = socket
        socket = null
        onChallenge = {}
        onError = {}
        closingSocket?.close(1000, "closed")
    }

    private fun wsUrl(): String {
        val timestamp = (System.currentTimeMillis() / 1000).toString()
        val nonce = UUID.randomUUID().toString()
        val signature = WearDecisionSigner.signMessage(privateKey, "ws.${enrollment.deviceId}.$timestamp.$nonce")
        return resolveWearEndpoint(
            enrollment.serverUrl,
            "/api/v1/devices/{id}/ws",
            enrollment.deviceId
        ).newBuilder()
            .addQueryParameter("timestamp", timestamp)
            .addQueryParameter("nonce", nonce)
            .addQueryParameter("signature", signature)
            .build()
            .toString()
    }
}

internal fun wearChallengesFromWebSocketPayload(text: String): List<WearChallenge> {
    val message = JSONObject(text)
    return when (message.optString("type")) {
        "auth_request" ->
            listOf(WearChallenge.fromPayload(message.getJSONObject("data").toString()))
        "pending" -> {
            val data = message.optJSONArray("data") ?: return emptyList()
            List(data.length()) { index ->
                WearChallenge.fromPayload(data.getJSONObject(index).toString())
            }
        }
        else -> emptyList()
    }
}

class PhoneRelayChallengeInbox(
    private val subscribe: (onPayload: (String) -> Unit, onError: (Throwable) -> Unit) -> Closeable
) : WearChallengeInbox {
    private var subscription: Closeable? = null

    override fun start(onChallenge: (WearChallenge) -> Unit, onError: (Throwable) -> Unit) {
        runCatching {
            subscription = subscribe(
                { payload ->
                    runCatching { WearChallenge.fromPayload(payload) }
                        .onSuccess(onChallenge)
                        .onFailure(onError)
                },
                onError
            )
        }.onFailure { error -> reportError(onError, error) }
    }

    override fun close() {
        subscription?.close()
        subscription = null
    }
}

class WearDataLayerChallengeInbox(private val context: Context) : WearChallengeInbox, MessageClient.OnMessageReceivedListener {
    private var onChallenge: (WearChallenge) -> Unit = {}
    private var onError: (Throwable) -> Unit = {}

    override fun start(onChallenge: (WearChallenge) -> Unit, onError: (Throwable) -> Unit) {
        this.onChallenge = onChallenge
        this.onError = onError
        runCatching { Wearable.getMessageClient(context).addListener(this).addOnFailureListener(onError) }
            .onFailure { error -> reportError(onError, error) }
    }

    override fun onMessageReceived(event: MessageEvent) {
        if (event.path == WearRelayProtocol.RESOLUTION_PATH) {
            WearResolution.fromRelayPayload(event.data)?.let(WearResolutions::publish)
            return
        }
        if (event.path != WearRelayProtocol.CHALLENGE_PATH) return
        runCatching { WearChallenge.fromPayload(String(event.data, Charsets.UTF_8)) }
            .onSuccess(onChallenge)
            .onFailure(onError)
    }

    override fun close() {
        runCatching { Wearable.getMessageClient(context).removeListener(this) }
        onChallenge = {}
        onError = {}
    }
}

class DeduplicatingWearChallengeInbox(private val inboxes: List<WearChallengeInbox>) : WearChallengeInbox {
    private val seenChallengeIds = mutableSetOf<String>()

    override fun start(onChallenge: (WearChallenge) -> Unit, onError: (Throwable) -> Unit) {
        inboxes.forEach { inbox ->
            runCatching {
                inbox.start(
                    onChallenge = { challenge ->
                        val isNew = synchronized(seenChallengeIds) { seenChallengeIds.add(challenge.id) }
                        if (isNew) onChallenge(challenge)
                    },
                    onError = onError
                )
            }.onFailure { error -> reportError(onError, error) }
        }
    }

    override fun close() {
        inboxes.forEach { inbox -> runCatching { inbox.close() } }
        synchronized(seenChallengeIds) { seenChallengeIds.clear() }
    }
}

private fun reportError(onError: (Throwable) -> Unit, error: Throwable) {
    runCatching { onError(error) }
}
