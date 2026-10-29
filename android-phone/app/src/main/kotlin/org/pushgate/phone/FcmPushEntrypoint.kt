package org.pushgate.phone

import android.content.Context
import org.json.JSONObject
import java.io.Closeable
import java.util.concurrent.CopyOnWriteArraySet
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

object FcmPushEntrypoint {
    private val listeners = CopyOnWriteArraySet<Listener>()
    private val tokenListeners = CopyOnWriteArraySet<(String) -> Unit>()

    fun onMessageData(data: Map<String, String>) {
        ChallengeResolution.fromData(data)?.let { resolution ->
            ChallengeResolutions.publish(resolution)
            return
        }
        val result = runCatching {
            val deviceId = deviceIdFromData(data)
                ?: throw SecurityException("FCM payload is not bound to an enrolled device")
            FcmAuthMessage(deviceId, challengeFromData(data).also {
                require(it.isActionable()) { "Challenge is expired or malformed" }
            })
        }
        listeners.forEach { listener ->
            result
                .onSuccess { message ->
                    if (message.deviceId == listener.deviceId) listener.onChallenge(message.challenge)
                }
                .onFailure(listener.onError)
        }
    }

    fun register(deviceId: String, onChallenge: (AuthChallenge) -> Unit, onError: (Throwable) -> Unit): Closeable {
        require(deviceId.isNotBlank()) { "FCM listener device ID is blank" }
        val listener = Listener(deviceId, onChallenge, onError)
        listeners.add(listener)
        return Closeable { listeners.remove(listener) }
    }

    fun onNewToken(token: String) {
        tokenListeners.forEach { listener -> listener(token) }
    }

    fun registerTokenListener(listener: (String) -> Unit): Closeable {
        tokenListeners.add(listener)
        return Closeable { tokenListeners.remove(listener) }
    }

    fun challengeFromData(data: Map<String, String>): AuthChallenge {
        val rawJson = data["challenge"] ?: data["data"] ?: data["payload"]
        val json = if (rawJson != null) JSONObject(rawJson) else JSONObject(data)
        return when (json.optString("type")) {
            "auth_request" -> AuthChallenge.fromJson(json.getJSONObject("data"))
            else -> AuthChallenge.fromJson(json)
        }
    }

    fun deviceIdFromData(data: Map<String, String>): String? {
        data["device_id"]?.takeIf(String::isNotBlank)?.let { return it }
        val rawJson = data["challenge"] ?: data["data"] ?: data["payload"] ?: return null
        val json = JSONObject(rawJson)
        return json.optString("device_id").takeIf(String::isNotBlank)
            ?: json.optJSONObject("data")?.optString("device_id")?.takeIf(String::isNotBlank)
    }

    private data class FcmAuthMessage(val deviceId: String, val challenge: AuthChallenge)

    private data class Listener(
        val deviceId: String,
        val onChallenge: (AuthChallenge) -> Unit,
        val onError: (Throwable) -> Unit
    )
}

class PushGateFirebaseMessagingService : FirebaseMessagingService() {
    override fun onMessageReceived(message: RemoteMessage) {
        FcmPushEntrypoint.onMessageData(message.data)
        FcmBackgroundMessageHandler.showNotification(this, message.data)
    }

    override fun onNewToken(token: String) {
        FcmPushEntrypoint.onNewToken(token)
    }
}

object FcmBackgroundMessageHandler {
    fun showNotification(context: Context, data: Map<String, String>): Result<AuthChallenge> {
        ChallengeResolution.fromData(data)?.let { resolution ->
            AuthNotificationDispatcher(context).cancel(resolution.id)
            PendingDenialScheduler.discard(context, resolution.id)
            return Result.failure(IllegalStateException("Request ${resolution.id} is ${resolution.status}"))
        }
        val expectedDeviceId = EnrollmentStore.load(context)?.deviceId
            ?: return Result.failure(SecurityException("No active enrollment for FCM payload"))
        return showNotification(data, expectedDeviceId) { challenge ->
            AuthNotificationDispatcher(context).show(challenge)
        }
    }

    fun showNotification(
        data: Map<String, String>,
        expectedDeviceId: String,
        notify: (AuthChallenge) -> Unit
    ): Result<AuthChallenge> =
        runCatching {
            require(FcmPushEntrypoint.deviceIdFromData(data) == expectedDeviceId) {
                "FCM payload does not match the active enrollment"
            }
            FcmPushEntrypoint.challengeFromData(data).also {
                require(it.isActionable()) { "Challenge is expired or malformed" }
            }
        }
            .onSuccess(notify)
}

class FcmPushChannel(
    private val deviceId: String,
    private val entrypoint: FcmPushEntrypoint = FcmPushEntrypoint
) : PushChannel {
    private var subscription: Closeable? = null

    override fun start(onChallenge: (AuthChallenge) -> Unit, onError: (Throwable) -> Unit, onReady: () -> Unit) {
        close()
        subscription = entrypoint.register(deviceId, onChallenge, onError)
    }

    override fun close() {
        subscription?.close()
        subscription = null
    }
}
