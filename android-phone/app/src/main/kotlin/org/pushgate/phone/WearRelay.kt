package org.pushgate.phone

import android.content.Context
import com.google.android.gms.wearable.MessageClient
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.Wearable
import org.json.JSONObject
import java.io.Closeable

object PhoneWearRelayProtocol {
    const val CHALLENGE_PATH = "/pushgate/challenge"
    const val DECISION_PATH = "/pushgate/decision"
    const val DECISION_RESULT_PATH = "/pushgate/decision-result"
    const val RESOLUTION_PATH = "/pushgate/resolution"

    fun resolutionPayload(resolution: ChallengeResolution): String =
        org.json.JSONObject().put("id", resolution.id).put("status", resolution.status).toString()

    fun challengePayload(challenge: AuthChallenge): String {
        val data = JSONObject()
            .put("id", challenge.id)
            .put("username", challenge.username)
            .put("system", challenge.system)
            .put("pam_service", challenge.pamService)
            .put("expires_at", challenge.expiresAt)
            .put("require_biometric", challenge.requireBiometric)
        challenge.sourceIp?.let { data.put("source_ip", it) }
        challenge.geolocation?.let { data.put("geolocation", it) }
        challenge.requestedAt?.let { data.put("requested_at", it) }
        challenge.reason?.let { data.put("reason", it) }
        return JSONObject()
            .put("type", "auth_request")
            .put("data", data)
            .toString()
    }

    fun decisionFromPayload(payload: ByteArray): RelayedDecision {
        val json = JSONObject(String(payload, Charsets.UTF_8))
        val requestId = json.optString("request_id").ifBlank { json.getString("id") }
        val body = JSONObject()
            .put("device_id", json.getString("device_id"))
            .put("decision", json.getString("decision"))
            .put("biometric_verified", json.getBoolean("biometric_verified"))
            .put("signature", json.getString("signature"))
            .toString()
        return RelayedDecision(requestId, body)
    }

    fun decisionResultPayload(requestId: String, result: Result<String>): String {
        val payload = JSONObject().put("request_id", requestId)
        result.fold(
            onSuccess = { body ->
                val status = runCatching {
                    JSONObject(body).optJSONObject("data")?.optString("status").orEmpty()
                }.getOrDefault("")
                if (status in setOf("approved", "denied", "timeout", "pending")) {
                    payload.put("status", status)
                } else {
                    payload.put("error", "invalid_server_response")
                }
            },
            onFailure = { payload.put("error", "relay_failed") }
        )
        return payload.toString()
    }

    data class RelayedDecision(val requestId: String, val body: String)
}

class PhoneWearRelay(
    private val context: Context,
    private val client: DeviceAuthClient = DeviceAuthClient()
) : Closeable, MessageClient.OnMessageReceivedListener {
    private var activeEnrollment: Enrollment? = null
    private var onStatus: (String) -> Unit = {}
    private var onError: (Throwable) -> Unit = {}

    fun start(enrollment: Enrollment, onStatus: (String) -> Unit, onError: (Throwable) -> Unit) {
        close()
        activeEnrollment = enrollment
        this.onStatus = onStatus
        this.onError = onError
        runCatching { Wearable.getMessageClient(context).addListener(this).addOnFailureListener(onError) }
            .onFailure { error ->
                activeEnrollment = null
                onError(error)
            }
    }

    fun relayChallenge(challenge: AuthChallenge) {
        val payload = PhoneWearRelayProtocol.challengePayload(challenge).toByteArray(Charsets.UTF_8)
        runCatching {
            Wearable.getNodeClient(context).connectedNodes
                .addOnSuccessListener { nodes ->
                    nodes.forEach { node ->
                        runCatching {
                            Wearable.getMessageClient(context)
                                .sendMessage(node.id, PhoneWearRelayProtocol.CHALLENGE_PATH, payload)
                                .addOnFailureListener(onError)
                        }.onFailure(onError)
                    }
                }
                .addOnFailureListener(onError)
        }.onFailure(onError)
    }

    /** Tell the watch a request is settled so it drops its own prompt and notification. */
    fun relayResolution(resolution: ChallengeResolution) {
        val payload = PhoneWearRelayProtocol.resolutionPayload(resolution).toByteArray(Charsets.UTF_8)
        runCatching {
            Wearable.getNodeClient(context).connectedNodes
                .addOnSuccessListener { nodes ->
                    nodes.forEach { node ->
                        runCatching {
                            Wearable.getMessageClient(context)
                                .sendMessage(node.id, PhoneWearRelayProtocol.RESOLUTION_PATH, payload)
                                .addOnFailureListener(onError)
                        }.onFailure(onError)
                    }
                }
                .addOnFailureListener(onError)
        }.onFailure(onError)
    }

    override fun onMessageReceived(event: MessageEvent) {
        if (event.path != PhoneWearRelayProtocol.DECISION_PATH) return
        val enrollment = activeEnrollment ?: return
        runCatching { PhoneWearRelayProtocol.decisionFromPayload(event.data) }
            .onSuccess { decision ->
                client.postDecisionBody(enrollment, decision.requestId, decision.body) { result ->
                    sendDecisionResult(event.sourceNodeId, decision.requestId, result)
                    result
                        .onSuccess { onStatus("Wear decision relayed") }
                        .onFailure(onError)
                }
            }
            .onFailure(onError)
    }

    private fun sendDecisionResult(nodeId: String, requestId: String, result: Result<String>) {
        val payload = PhoneWearRelayProtocol.decisionResultPayload(requestId, result)
            .toByteArray(Charsets.UTF_8)
        runCatching {
            Wearable.getMessageClient(context)
                .sendMessage(nodeId, PhoneWearRelayProtocol.DECISION_RESULT_PATH, payload)
                .addOnFailureListener(onError)
        }.onFailure(onError)
    }

    override fun close() {
        runCatching { Wearable.getMessageClient(context).removeListener(this) }
        activeEnrollment = null
    }
}
