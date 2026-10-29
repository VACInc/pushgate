package org.pushgate.wear

import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import java.io.IOException

internal class DefinitiveEnrollmentRejection(val statusCode: Int) :
    IOException("Enrollment rejected: HTTP $statusCode")

internal class EnrollmentRequestNotStarted(cause: Throwable) :
    IOException("Enrollment request was not started", cause)

class WearDeviceClient(http: OkHttpClient = OkHttpClient()) {
    private val http = hardenedWearHttpClient(http)

    fun enroll(enrollment: WearEnrollment, publicKey: String, callback: (Result<String>) -> Unit) {
        enroll(enrollment, publicKey, DeviceKeyType.Ed25519, callback)
    }

    fun enroll(
        enrollment: WearEnrollment,
        publicKey: String,
        keyType: DeviceKeyType,
        callback: (Result<String>) -> Unit
    ) {
        val startFailure = runCatching {
            val body = JSONObject()
                .put("enrollment_token", enrollment.enrollmentToken)
                .put("public_key", publicKey)
                .put("key_type", keyType.wireValue)
                .toString()
                .toRequestBody("application/json".toMediaType())

            val request = Request.Builder()
                .url(
                    resolveWearEndpoint(
                        enrollment.serverUrl,
                        enrollment.enrollApi,
                        enrollment.deviceId
                    )
                )
                .post(body)
                .build()

            http.newCall(request).enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) = callback(Result.failure(e))

                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        when {
                            it.isSuccessful -> callback(Result.success(it.body?.string().orEmpty()))
                            it.code in 400..499 && it.code != 408 ->
                                callback(Result.failure(DefinitiveEnrollmentRejection(it.code)))
                            else -> callback(Result.failure(IOException("Enrollment result uncertain: HTTP ${it.code}")))
                        }
                    }
                }
            })
        }.exceptionOrNull()

        // Everything above happens before OkHttp accepts the asynchronous call.
        // A synchronous failure therefore cannot have reached the server and can
        // safely take the same durable local rollback path as a definitive 4xx.
        if (startFailure != null) {
            callback(Result.failure(EnrollmentRequestNotStarted(startFailure)))
        }
    }
}
