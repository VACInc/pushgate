package org.pushgate.phone

import com.google.firebase.messaging.FirebaseMessaging
import okhttp3.Call
import java.io.Closeable
import java.security.PrivateKey
import java.util.concurrent.CopyOnWriteArraySet

interface FcmTokenProvider {
    fun refreshCurrentToken(callback: (Result<String>) -> Unit)
}

class FirebaseMessagingTokenProvider(
    private val messagingFactory: () -> FirebaseMessaging = { FirebaseMessaging.getInstance() }
) : FcmTokenProvider {
    override fun refreshCurrentToken(callback: (Result<String>) -> Unit) {
        if (!BuildConfig.FCM_CONFIGURED) {
            callback(Result.failure(IllegalStateException("FCM is not configured in this build")))
            return
        }
        val messaging = try {
            messagingFactory()
        } catch (error: RuntimeException) {
            callback(Result.failure(error))
            return
        }

        try {
            messaging.token
                .addOnSuccessListener { token -> callback(Result.success(token)) }
                .addOnFailureListener { error -> callback(Result.failure(error)) }
        } catch (error: RuntimeException) {
            callback(Result.failure(error))
        }
    }
}

class FirebaseTokenSync(
    private val client: DeviceAuthClient = DeviceAuthClient(),
    private val tokenProvider: FcmTokenProvider = FirebaseMessagingTokenProvider()
) : Closeable {
    private var subscription: Closeable? = null
    private val inFlightCalls = CopyOnWriteArraySet<Call>()
    @Volatile
    private var generation = 0

    fun start(enrollment: Enrollment, privateKey: PrivateKey, callback: (Result<String>) -> Unit = {}) {
        close()
        val activeGeneration = generation
        subscription = FcmPushEntrypoint.registerTokenListener { token ->
            upload(enrollment, privateKey, token, activeGeneration, callback)
        }
        refreshCurrentToken(enrollment, privateKey, activeGeneration, callback)
    }

    fun refreshCurrentToken(enrollment: Enrollment, privateKey: PrivateKey, callback: (Result<String>) -> Unit = {}) {
        refreshCurrentToken(enrollment, privateKey, generation, callback)
    }

    private fun refreshCurrentToken(
        enrollment: Enrollment,
        privateKey: PrivateKey,
        activeGeneration: Int,
        callback: (Result<String>) -> Unit
    ) {
        try {
            tokenProvider.refreshCurrentToken { result ->
                if (activeGeneration != generation) return@refreshCurrentToken
                result
                    .onSuccess { token -> upload(enrollment, privateKey, token, activeGeneration, callback) }
                    .onFailure { error -> callback(Result.failure(error)) }
            }
        } catch (error: RuntimeException) {
            callback(Result.failure(error))
        }
    }

    override fun close() {
        generation += 1
        subscription?.close()
        subscription = null
        inFlightCalls.forEach(Call::cancel)
        inFlightCalls.clear()
    }

    private fun upload(
        enrollment: Enrollment,
        privateKey: PrivateKey,
        token: String,
        activeGeneration: Int,
        callback: (Result<String>) -> Unit
    ) {
        if (activeGeneration != generation) return
        var call: Call? = null
        val startedCall = runCatching {
            client.updatePushToken(enrollment, privateKey, token) { result ->
                call?.let(inFlightCalls::remove)
                if (activeGeneration == generation) callback(result)
            }
        }.getOrElse {
            if (activeGeneration == generation) callback(Result.failure(it))
            return
        }
        call = startedCall
        if (activeGeneration == generation) {
            inFlightCalls += startedCall
        } else {
            startedCall.cancel()
        }
    }
}
