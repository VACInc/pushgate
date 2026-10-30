package org.pushgate.wear

import org.json.JSONObject
import java.time.Instant

enum class WearDecision(val wireValue: String) {
    Approve("approve"),
    Deny("deny")
}

enum class WearDecisionOutcome(val wireValue: String, val isTerminal: Boolean) {
    Approved("approved", true),
    Denied("denied", true),
    Timeout("timeout", true),
    Pending("pending", false);

    companion object {
        fun fromWire(value: String): WearDecisionOutcome? =
            entries.firstOrNull { it.wireValue == value }
    }
}

data class WearEnrollment(
    val serverUrl: String,
    val deviceId: String,
    val enrollmentToken: String,
    val enrollApi: String,
    val decisionApi: String,
    val signingKeyAlias: String = WearKeyStore.DEFAULT_ALIAS
) {
    companion object {
        fun fromPayload(serverUrl: String, payload: String): WearEnrollment {
            val json = JSONObject(payload)
            val deviceId = json.getString("device_id").takeIf(String::isNotBlank)
                ?: throw IllegalArgumentException("Enrollment payload has no device ID")
            val enrollmentToken = json.getString("enrollment_token").takeIf(String::isNotBlank)
                ?: throw IllegalArgumentException("Enrollment payload has no token")
            val enrollApi = validateWearApiPath(
                json.optString("enroll_api", "/api/v1/devices/{id}/enroll")
            )
            val decisionApi = validateWearApiPath(
                json.optString("decision_api", "/api/v1/auth/requests/{id}/decision")
            )
            return WearEnrollment(
                serverUrl = normalizeWearServerUrl(serverUrl),
                deviceId = deviceId,
                enrollmentToken = enrollmentToken,
                enrollApi = enrollApi,
                decisionApi = decisionApi
            )
        }
    }
}

data class WearChallenge(
    val id: String,
    val username: String,
    val system: String,
    val pamService: String,
    val sourceIp: String?,
    val geolocation: String?,
    val requestedAt: String?,
    val expiresAt: String,
    val requireBiometric: Boolean,
    val reason: String? = null
) {
    companion object {
        fun fromPayload(payload: String): WearChallenge {
            val json = JSONObject(payload)
            val data = if (json.optString("type") == "auth_request") json.getJSONObject("data") else json
            val detail = data.optJSONObject("detail")
            val id = data.getString("id").takeIf(String::isNotBlank)
                ?: throw IllegalArgumentException("Challenge has no request ID")
            return WearChallenge(
                id = id,
                username = data.optString("username"),
                system = data.optString("system"),
                pamService = data.optString("pam_service"),
                sourceIp = optionalString(data, "source_ip"),
                geolocation = optionalString(data, "geolocation") ?: detail?.let { optionalString(it, "geolocation") },
                requestedAt = optionalString(data, "requested_at") ?: detail?.let { optionalString(it, "timestamp") } ?: optionalString(data, "created_at"),
                expiresAt = data.optString("expires_at"),
                requireBiometric = data.optBoolean("require_biometric", true),
                reason = optionalString(data, "reason") ?: detail?.let { optionalString(it, "reason") }
            )
        }

        private fun optionalString(json: JSONObject, key: String): String? =
            json.optString(key).takeIf { it.isNotBlank() && it != "null" }
    }
}

internal fun isWearChallengeActionable(
    challenge: WearChallenge,
    nowEpochMillis: Long = System.currentTimeMillis()
): Boolean = wearChallengeRemainingMillis(challenge, nowEpochMillis) != null

internal fun wearChallengeRemainingMillis(
    challenge: WearChallenge,
    nowEpochMillis: Long = System.currentTimeMillis()
): Long? {
    if (challenge.id.isBlank()) return null
    val expiresAt = challenge.expiresAt.takeIf(String::isNotBlank) ?: return null
    val expiration = runCatching { Instant.parse(expiresAt).toEpochMilli() }.getOrNull()
        ?: return null
    return (expiration - nowEpochMillis).takeIf { it > 0 }
}
