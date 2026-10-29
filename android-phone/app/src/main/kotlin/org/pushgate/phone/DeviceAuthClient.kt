package org.pushgate.phone

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
import java.util.UUID

internal class EnrollmentHttpException(val statusCode: Int) : IOException("Enrollment failed: $statusCode")
/** The server answered, but the request already had a different final status (first response wins, or timeout). */
internal class DecisionResponseException(message: String, val receivedStatus: String = "") : IOException(message)

internal fun validateDecisionResponse(body: String, expectedDecision: Decision): Result<String> = runCatching {
    val status = JSONObject(body).optJSONObject("data")?.optString("status").orEmpty()
    val expectedStatus = when (expectedDecision) {
        Decision.Approve -> "approved"
        Decision.Deny -> "denied"
    }
    if (status != expectedStatus) {
        throw DecisionResponseException("Expected decision status $expectedStatus, received ${status.ifBlank { "missing" }}", status)
    }
    body
}

internal fun shouldPreserveEnrollmentRecovery(error: Throwable): Boolean =
    error !is EnrollmentHttpException || error.statusCode !in 400..499 || error.statusCode == 408

internal fun hardenedDeviceHttpClient(base: OkHttpClient): OkHttpClient =
    base.newBuilder()
        .retryOnConnectionFailure(false)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

class DeviceAuthClient(private val http: OkHttpClient = OkHttpClient()) {
    private val hardenedHttp = hardenedDeviceHttpClient(http)

    fun enroll(
        enrollment: Enrollment,
        publicKey: String,
        pushToken: String? = null,
        callback: (Result<String>) -> Unit
    ): Call = enroll(enrollment, publicKey, pushToken, DeviceKeyType.Ed25519, callback)

    fun enroll(
        enrollment: Enrollment,
        publicKey: String,
        pushToken: String? = null,
        keyType: DeviceKeyType,
        callback: (Result<String>) -> Unit
    ): Call {
        val body = JSONObject()
            .put("enrollment_token", enrollment.enrollmentToken)
            .put("public_key", publicKey)
            .put("key_type", keyType.wireValue)
            .apply {
                if (pushToken != null) put("push_token", pushToken)
            }
            .toString()
            .toRequestBody("application/json".toMediaType())

        val request = Request.Builder()
            .url(enrollment.endpointUrl(enrollment.enrollApi, enrollment.deviceId))
            .post(body)
            .build()

        return hardenedHttp.newCall(request).also { call -> call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) = callback(Result.failure(e))

            override fun onResponse(call: Call, response: Response) {
                response.use {
                    if (!it.isSuccessful) callback(Result.failure(EnrollmentHttpException(it.code)))
                    else callback(Result.success(it.body?.string().orEmpty()))
                }
            }
        }) }
    }

    fun updatePushToken(
        enrollment: Enrollment,
        privateKey: PrivateKey,
        pushToken: String,
        callback: (Result<String>) -> Unit
    ): Call {
        val timestamp = (System.currentTimeMillis() / 1000).toString()
        val nonce = UUID.randomUUID().toString()
        val signature = DecisionSigner.signMessage(privateKey, "push_token.${enrollment.deviceId}.$timestamp.$nonce.$pushToken")
        val body = JSONObject()
            .put("push_token", pushToken)
            .put("timestamp", timestamp)
            .put("nonce", nonce)
            .put("signature", signature)
            .toString()
            .toRequestBody("application/json".toMediaType())

        val request = Request.Builder()
            .url(enrollment.endpointUrl("/api/v1/devices/{id}/push-token", enrollment.deviceId))
            .post(body)
            .build()

        return hardenedHttp.newCall(request).also { it.enqueue(callback) }
    }

    fun decide(
        enrollment: Enrollment,
        requestId: String,
        decision: Decision,
        privateKey: PrivateKey,
        callback: (Result<String>) -> Unit,
        biometricVerified: Boolean = decision == Decision.Approve
    ): Call {
        val body = JSONObject()
            .put("device_id", enrollment.deviceId)
            .put("decision", decision.wireValue)
            .put("biometric_verified", biometricVerified)
            .put("signature", DecisionSigner.sign(privateKey, requestId, decision, biometricVerified))
            .toString()
            .toRequestBody("application/json".toMediaType())

        val request = Request.Builder()
            .url(enrollment.endpointUrl(enrollment.decisionApi, requestId))
            .post(body)
            .build()

        return hardenedHttp.newCall(request).also { call -> call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) = callback(Result.failure(e))

            override fun onResponse(call: Call, response: Response) {
                response.use {
                    if (!it.isSuccessful) callback(Result.failure(IOException("Decision failed: ${it.code}")))
                    else callback(validateDecisionResponse(it.body?.string().orEmpty(), decision))
                }
            }
        }) }
    }

    fun postDecisionBody(enrollment: Enrollment, requestId: String, body: String, callback: (Result<String>) -> Unit) {
        val expectedDecision = runCatching {
            when (JSONObject(body).getString("decision")) {
                Decision.Approve.wireValue -> Decision.Approve
                Decision.Deny.wireValue -> Decision.Deny
                else -> throw DecisionResponseException("Wear decision is invalid")
            }
        }.getOrElse {
            callback(Result.failure(it))
            return
        }
        val request = Request.Builder()
            .url(enrollment.endpointUrl(enrollment.decisionApi, requestId))
            .post(body.toRequestBody("application/json".toMediaType()))
            .build()

        hardenedHttp.newCall(request).enqueue { result ->
            callback(result.fold(
                onSuccess = { validateDecisionResponse(it, expectedDecision) },
                onFailure = { Result.failure(it) }
            ))
        }
    }

    private fun Call.enqueue(callback: (Result<String>) -> Unit) {
        enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) = callback(Result.failure(e))

            override fun onResponse(call: Call, response: Response) {
                response.use {
                    if (!it.isSuccessful) callback(Result.failure(IOException("Request failed: ${it.code}")))
                    else callback(Result.success(it.body?.string().orEmpty()))
                }
            }
        })
    }
}
