package org.pushgate.wear

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

internal fun hardenedWearHttpClient(http: OkHttpClient): OkHttpClient =
    http.newBuilder()
        // Enrollment and decisions have explicit uncertain-result handling.
        // Transparent retries or redirects would blur which origin handled a
        // signed request.
        .retryOnConnectionFailure(false)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

internal fun hardenedWearDecisionHttpClient(
    http: OkHttpClient,
    callTimeoutMillis: Long
): OkHttpClient {
    require(callTimeoutMillis > 0) { "Decision timeout must be positive" }
    return hardenedWearHttpClient(http).newBuilder()
        .callTimeout(callTimeoutMillis, TimeUnit.MILLISECONDS)
        .build()
}

internal fun normalizeWearServerUrl(serverUrl: String): String {
    val parsed = serverUrl.trim().toHttpUrl()
    require(parsed.encodedUsername.isEmpty() && parsed.encodedPassword.isEmpty()) {
        "Server URL must not contain user information"
    }
    require(parsed.query == null && parsed.fragment == null) {
        "Server URL must not contain a query or fragment"
    }
    return parsed.toString().trimEnd('/')
}

internal fun validateWearApiPath(apiPath: String): String {
    require(apiPath.startsWith('/') && !apiPath.startsWith("//")) {
        "API path must be root-relative"
    }
    require(apiPath.none { it == '\\' || it == '?' || it == '#' || it.isISOControl() }) {
        "API path contains prohibited characters"
    }
    require(
        apiPath.split('/').none { segment ->
            Regex("(?i)(?:\\.|%2e){1,2}").matches(segment)
        }
    ) { "API path must not contain dot segments" }
    return apiPath
}

internal fun resolveWearEndpoint(
    serverUrl: String,
    apiPath: String,
    id: String
): HttpUrl {
    val base = normalizeWearServerUrl(serverUrl).toHttpUrl()
    val path = validateWearApiPath(apiPath)
    val encodedId = HttpUrl.Builder()
        .scheme("https")
        .host("endpoint.invalid")
        .addPathSegment(id)
        .build()
        .encodedPath
        .removePrefix("/")
    val endpoint = base.newBuilder()
        .addEncodedPathSegments(path.replace("{id}", encodedId).removePrefix("/"))
        .build()
    require(
        endpoint.scheme == base.scheme &&
            endpoint.host == base.host &&
            endpoint.port == base.port
    ) { "API endpoint must use the configured server origin" }
    return endpoint
}
