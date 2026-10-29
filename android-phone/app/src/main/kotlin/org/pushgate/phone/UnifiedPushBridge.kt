package org.pushgate.phone

import org.json.JSONObject

/**
 * Pure helpers for the UnifiedPush path (self-hosted ntfy as distributor).
 *
 * The server posts the same shape the FCM path carries:
 * {"type":"auth_request","device_id":"...","payload":"<auth_request event json>"}
 * so a UnifiedPush message is turned into the FCM data map and reuses every
 * existing challenge, notification, and enrollment-binding check.
 */
object UnifiedPushBridge {
    const val INSTANCE = "pushgate"
    const val PREFERRED_DISTRIBUTOR = "io.heckel.ntfy"

    fun dataFromMessage(content: ByteArray): Map<String, String> {
        val text = String(content, Charsets.UTF_8)
        val json = JSONObject(text)
        val type = json.optString("type")
        require(type == "auth_request" || type == "auth_decided") { "UnifiedPush message is not a PushGate event" }
        val data = linkedMapOf<String, String>()
        json.optString("device_id").takeIf(String::isNotBlank)?.let { data["device_id"] = it }
        if (type == "auth_decided") {
            data["type"] = "auth_decided"
            data["payload"] = json.toString()
            return data
        }
        val payload = json.optString("payload").takeIf(String::isNotBlank)
            ?: json.optJSONObject("data")?.let { JSONObject().put("type", "auth_request").put("data", it).toString() }
            ?: throw IllegalArgumentException("UnifiedPush message has no challenge payload")
        data["payload"] = payload
        return data
    }

    fun chooseDistributor(available: List<String>, saved: String?): String? = when {
        saved != null && saved in available -> saved
        PREFERRED_DISTRIBUTOR in available -> PREFERRED_DISTRIBUTOR
        else -> available.firstOrNull()
    }
}
