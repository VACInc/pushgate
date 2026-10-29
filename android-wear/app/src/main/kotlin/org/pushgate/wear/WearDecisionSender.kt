package org.pushgate.wear

import android.content.Context
import com.google.android.gms.wearable.MessageClient
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.Wearable
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import java.io.IOException
import java.security.PrivateKey
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

interface WearDecisionSender {
    fun send(
        enrollment: WearEnrollment,
        challenge: WearChallenge,
        decision: WearDecision,
        privateKey: PrivateKey,
        callback: (Result<WearDecisionOutcome>) -> Unit,
        biometricVerified: Boolean
    )
}

object WearRelayProtocol {
    const val CHALLENGE_PATH = "/pushgate/challenge"
    const val DECISION_PATH = "/pushgate/decision"
    const val DECISION_RESULT_PATH = "/pushgate/decision-result"
    const val RESOLUTION_PATH = "/pushgate/resolution"

    fun decisionPayload(enrollment: WearEnrollment, challenge: WearChallenge, decision: WearDecision, privateKey: PrivateKey, biometricVerified: Boolean): String {
        return JSONObject()
            .put("request_id", challenge.id)
            .put("device_id", enrollment.deviceId)
            .put("decision", decision.wireValue)
            .put("biometric_verified", biometricVerified)
            .put("signature", WearDecisionSigner.sign(privateKey, challenge.id, decision, biometricVerified))
            .toString()
    }

    fun decisionResultFromPayload(payload: ByteArray): RelayedDecisionResult {
        val json = JSONObject(String(payload, Charsets.UTF_8))
        val requestId = json.getString("request_id").takeIf { it.isNotBlank() }
            ?: throw IOException("Decision acknowledgement is missing request ID")
        val error = json.optString("error").takeIf { it.isNotBlank() }
        if (error != null) return RelayedDecisionResult(requestId, null, true)
        val outcome = WearDecisionOutcome.fromWire(json.optString("status"))
            ?: throw IOException("Decision acknowledgement has unknown status")
        return RelayedDecisionResult(requestId, outcome, false)
    }

    data class RelayedDecisionResult(
        val requestId: String,
        val outcome: WearDecisionOutcome?,
        val failed: Boolean
    )
}

class RelayedWearDecisionSender(private val context: Context) : WearDecisionSender {
    override fun send(enrollment: WearEnrollment, challenge: WearChallenge, decision: WearDecision, privateKey: PrivateKey, callback: (Result<WearDecisionOutcome>) -> Unit, biometricVerified: Boolean) {
        val payload = WearRelayProtocol.decisionPayload(enrollment, challenge, decision, privateKey, biometricVerified).toByteArray(Charsets.UTF_8)
        val messageClient = Wearable.getMessageClient(context)
        val done = AtomicBoolean(false)
        val timeout = AtomicReference<ScheduledFuture<*>?>(null)
        lateinit var listener: MessageClient.OnMessageReceivedListener

        fun complete(result: Result<WearDecisionOutcome>) {
            if (!done.compareAndSet(false, true)) return
            timeout.getAndSet(null)?.cancel(false)
            runCatching { messageClient.removeListener(listener) }
            callback(result)
        }

        listener = MessageClient.OnMessageReceivedListener { event: MessageEvent ->
            if (event.path != WearRelayProtocol.DECISION_RESULT_PATH) return@OnMessageReceivedListener
            val result = runCatching { WearRelayProtocol.decisionResultFromPayload(event.data) }
                .getOrNull() ?: return@OnMessageReceivedListener
            if (result.requestId != challenge.id) return@OnMessageReceivedListener
            if (result.failed || result.outcome == null) {
                complete(Result.failure(IOException("Phone relay failed to submit decision")))
            } else {
                complete(Result.success(result.outcome))
            }
        }

        runCatching {
            messageClient.addListener(listener)
                .addOnSuccessListener {
                    timeout.set(
                        acknowledgementScheduler.schedule(
                            { complete(Result.failure(IOException("Phone relay acknowledgement timed out"))) },
                            ACKNOWLEDGEMENT_TIMEOUT_SECONDS,
                            TimeUnit.SECONDS
                        )
                    )
                    Wearable.getNodeClient(context).connectedNodes
                        .addOnSuccessListener { nodes ->
                            if (nodes.isEmpty()) {
                                complete(Result.failure(IOException("No paired phone nodes")))
                                return@addOnSuccessListener
                            }
                            val remaining = AtomicInteger(nodes.size)
                            val failures = CopyOnWriteArrayList<Throwable>()
                            nodes.forEach { node ->
                                runCatching {
                                    messageClient
                                        .sendMessage(node.id, WearRelayProtocol.DECISION_PATH, payload)
                                        .addOnFailureListener { error ->
                                            failures.add(error)
                                            if (remaining.decrementAndGet() == 0) {
                                                complete(Result.failure(IOException("Decision relay failed", failures.firstOrNull())))
                                            }
                                        }
                                }.onFailure { error ->
                                    failures.add(error)
                                    if (remaining.decrementAndGet() == 0) {
                                        complete(Result.failure(IOException("Decision relay failed", failures.firstOrNull())))
                                    }
                                }
                            }
                        }
                        .addOnFailureListener { complete(Result.failure(it)) }
                }
                .addOnFailureListener { complete(Result.failure(it)) }
        }.onFailure { error -> complete(Result.failure(error)) }
    }

    private companion object {
        const val ACKNOWLEDGEMENT_TIMEOUT_SECONDS = 5L
        val acknowledgementScheduler = Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "pushgate-wear-relay-ack").apply { isDaemon = true }
        }
    }
}

class FallbackWearDecisionSender(
    private val primary: WearDecisionSender,
    private val fallback: WearDecisionSender
) : WearDecisionSender {
    override fun send(enrollment: WearEnrollment, challenge: WearChallenge, decision: WearDecision, privateKey: PrivateKey, callback: (Result<WearDecisionOutcome>) -> Unit, biometricVerified: Boolean) {
        val completed = AtomicBoolean(false)
        val fallbackStarted = AtomicBoolean(false)

        fun complete(result: Result<WearDecisionOutcome>) {
            if (completed.compareAndSet(false, true)) callback(result)
        }

        fun sendFallback(relayPending: Boolean) {
            if (!fallbackStarted.compareAndSet(false, true)) return
            val fallbackCallback: (Result<WearDecisionOutcome>) -> Unit = { result ->
                if (result.isSuccess) {
                    complete(result)
                } else if (relayPending) {
                    complete(Result.success(WearDecisionOutcome.Pending))
                } else {
                    complete(result)
                }
            }
            runCatching {
                fallback.send(
                    enrollment,
                    challenge,
                    decision,
                    privateKey,
                    fallbackCallback,
                    biometricVerified
                )
            }.onFailure { error ->
                fallbackCallback(Result.failure(error))
            }
        }

        runCatching {
            primary.send(enrollment, challenge, decision, privateKey, { result ->
                when (result.getOrNull()) {
                    WearDecisionOutcome.Approved,
                    WearDecisionOutcome.Denied,
                    WearDecisionOutcome.Timeout -> complete(result)
                    WearDecisionOutcome.Pending -> sendFallback(relayPending = true)
                    null -> sendFallback(relayPending = false)
                }
            }, biometricVerified)
        }.onFailure {
            sendFallback(relayPending = false)
        }
    }
}

class DirectWearDecisionSender(
    http: OkHttpClient = OkHttpClient(),
    callTimeoutMillis: Long = DECISION_CALL_TIMEOUT_MILLIS
) : WearDecisionSender {
    private val http = hardenedWearDecisionHttpClient(http, callTimeoutMillis)

    override fun send(enrollment: WearEnrollment, challenge: WearChallenge, decision: WearDecision, privateKey: PrivateKey, callback: (Result<WearDecisionOutcome>) -> Unit, biometricVerified: Boolean) {
        val startFailure = runCatching {
            val body = JSONObject()
                .put("device_id", enrollment.deviceId)
                .put("decision", decision.wireValue)
                .put("biometric_verified", biometricVerified)
                .put("signature", WearDecisionSigner.sign(privateKey, challenge.id, decision, biometricVerified))
                .toString()
                .toRequestBody("application/json".toMediaType())

            val request = Request.Builder()
                .url(
                    resolveWearEndpoint(
                        enrollment.serverUrl,
                        enrollment.decisionApi,
                        challenge.id
                    )
                )
                .post(body)
                .build()

            http.newCall(request).enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) = callback(Result.failure(e))

                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        if (!it.isSuccessful) callback(Result.failure(IOException("Decision failed: ${it.code}")))
                        else callback(parseDecisionOutcome(it.body?.string().orEmpty()))
                    }
                }
            })
        }.exceptionOrNull()

        if (startFailure != null) callback(Result.failure(startFailure))
    }

    private companion object {
        const val DECISION_CALL_TIMEOUT_MILLIS = 8_000L
    }
}

internal fun parseDecisionOutcome(body: String): Result<WearDecisionOutcome> = runCatching {
    val status = JSONObject(body)
        .optJSONObject("data")
        ?.optString("status")
        ?.takeIf { it.isNotBlank() }
        ?: throw IOException("Decision response is missing status")
    WearDecisionOutcome.fromWire(status)
        ?: throw IOException("Decision response has unknown status")
}
