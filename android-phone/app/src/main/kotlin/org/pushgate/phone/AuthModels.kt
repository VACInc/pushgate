package org.pushgate.phone

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONObject
import java.time.Duration
import java.time.Instant
import java.time.OffsetDateTime

enum class Decision(val wireValue: String) {
    Approve("approve"),
    Deny("deny")
}

data class Enrollment(
    val serverUrl: String,
    val deviceId: String,
    val enrollmentToken: String,
    val enrollApi: String,
    val decisionApi: String
) {
    companion object {
        fun fromQr(serverUrl: String, qrPayload: String): Enrollment {
            val json = JSONObject(qrPayload)
            val enrollment = Enrollment(
                serverUrl = canonicalServerUrl(serverUrl, allowDebugCleartext = BuildConfig.DEBUG),
                deviceId = json.getString("device_id"),
                enrollmentToken = json.getString("enrollment_token"),
                enrollApi = json.optString("enroll_api", "/api/v1/devices/{id}/enroll"),
                decisionApi = json.optString("decision_api", "/api/v1/auth/requests/{id}/decision")
            )
            require(enrollment.deviceId.isNotBlank()) { "Enrollment device ID is blank" }
            require(enrollment.enrollmentToken.isNotBlank()) { "Enrollment token is blank" }
            enrollment.endpointUrl(enrollment.enrollApi, enrollment.deviceId)
            enrollment.endpointUrl(enrollment.decisionApi, "request-id")
            return enrollment
        }
    }
}

internal fun canonicalServerUrl(rawUrl: String, allowDebugCleartext: Boolean): String {
    val url = rawUrl.trim().toHttpUrlOrNull() ?: throw IllegalArgumentException("Server URL is invalid")
    require(url.username.isEmpty() && url.password.isEmpty()) { "Server URL must not contain credentials" }
    require(url.query == null && url.fragment == null) { "Server URL must not contain a query or fragment" }
    require(url.scheme == "https" || allowDebugCleartext && url.scheme == "http" && url.host.isDebugCleartextHost()) {
        "Server URL must use HTTPS"
    }
    return url.toString().trimEnd('/')
}

private fun String.isDebugCleartextHost(): Boolean =
    this == "localhost" ||
        this == "127.0.0.1" ||
        this == "10.0.2.2" ||
        this == "10.0.3.2" ||
        this == "host.docker.internal" ||
        endsWith(".local") ||
        endsWith(".lan") ||
        endsWith(".example.test")

internal fun Enrollment.endpointUrl(pathTemplate: String, id: String): HttpUrl {
    require(id.isNotBlank()) { "API path ID is blank" }
    require(id != "." && id != "..") { "API path ID is unsafe" }
    require(pathTemplate.startsWith('/') && !pathTemplate.startsWith("//")) {
        "API path must be root-relative"
    }
    require("{id}" in pathTemplate) { "API path must contain {id}" }
    require(pathTemplate.none { it == '\\' || it == '#' || it == '?' }) {
        "API path contains an unsafe delimiter"
    }
    val lowercaseTemplate = pathTemplate.lowercase()
    require(listOf("%2f", "%5c", "%3f", "%23").none(lowercaseTemplate::contains)) {
        "API path contains an encoded delimiter"
    }
    val base = serverUrl.toHttpUrl()
    val encodedId = HttpUrl.Builder()
        .scheme("https")
        .host("encoding.invalid")
        .addPathSegment(id)
        .build()
        .encodedPathSegments
        .single()
    val endpoint = (base.toString().trimEnd('/') + pathTemplate.replace("{id}", encodedId)).toHttpUrl()
    require(endpoint.scheme == base.scheme && endpoint.host == base.host && endpoint.port == base.port) {
        "API endpoint must remain on the configured server"
    }
    return endpoint
}

data class AuthChallenge(
    val id: String,
    val username: String,
    val system: String,
    val pamService: String,
    val sourceIp: String?,
    val geolocation: String?,
    val requestedAt: String?,
    val expiresAt: String,
    val requireBiometric: Boolean
) {
    companion object {
        fun fromJson(json: JSONObject): AuthChallenge {
            val detail = json.optJSONObject("detail")
            return AuthChallenge(
                id = json.getString("id"),
                username = json.optString("username"),
                system = json.optString("system"),
                pamService = json.optString("pam_service"),
                sourceIp = optionalString(json, "source_ip"),
                geolocation = optionalString(json, "geolocation") ?: detail?.let { optionalString(it, "geolocation") },
                requestedAt = optionalString(json, "requested_at") ?: detail?.let { optionalString(it, "timestamp") } ?: optionalString(json, "created_at"),
                expiresAt = json.optString("expires_at"),
                requireBiometric = json.optBoolean("require_biometric", true)
            )
        }

        private fun optionalString(json: JSONObject, key: String): String? =
            json.optString(key).takeIf { it.isNotBlank() && it != "null" }
    }
}

internal fun AuthChallenge.isActionable(now: Instant = Instant.now()): Boolean {
    if (id.isBlank() || id == "." || id == ".." || id.length > 512) return false
    val expiry = expiryInstant() ?: return false
    return expiry.isAfter(now)
}

internal fun AuthChallenge.expiryInstant(): Instant? =
    runCatching { OffsetDateTime.parse(expiresAt).toInstant() }.getOrNull()

internal fun AuthChallenge.remainingLifetimeMillis(now: Instant = Instant.now()): Long? {
    val expiry = expiryInstant() ?: return null
    if (!expiry.isAfter(now)) return null
    return Duration.between(now, expiry).toMillis().coerceAtLeast(1L)
}

internal fun safeDisplayText(value: String?, maxLength: Int = 160): String {
    if (value == null) return ""
    val cleaned = buildString(value.length.coerceAtMost(maxLength)) {
        value.forEach { character ->
            when {
                character.isISOControl() || character.isBidiFormattingCharacter() -> append(' ')
                else -> append(character)
            }
        }
    }
        .replace(Regex("\\s+"), " ")
        .trim()
    return cleaned.take(maxLength)
}

private fun Char.isBidiFormattingCharacter(): Boolean =
    this == '\u061c' ||
        this == '\u200e' ||
        this == '\u200f' ||
        this in '\u202a'..'\u202e' ||
        this in '\u2066'..'\u2069'
