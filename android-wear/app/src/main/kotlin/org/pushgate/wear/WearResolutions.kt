package org.pushgate.wear

import org.json.JSONObject
import java.io.Closeable
import java.util.concurrent.CopyOnWriteArraySet

/** A request stopped being pending: decided on another surface or timed out on the server. */
data class WearResolution(val id: String, val status: String) {
    companion object {
        /** Server event: {"type":"auth_decided","data":{"id":..,"status":..}} */
        fun fromServerEvent(json: JSONObject): WearResolution? {
            if (json.optString("type") != "auth_decided") return null
            val data = json.optJSONObject("data") ?: return null
            return fromFields(data)
        }

        /** Phone relay payload: {"id":..,"status":..} */
        fun fromRelayPayload(payload: ByteArray): WearResolution? =
            runCatching { fromFields(JSONObject(String(payload, Charsets.UTF_8))) }.getOrNull()

        private fun fromFields(data: JSONObject): WearResolution? {
            val id = data.optString("id").takeIf(String::isNotBlank) ?: return null
            val status = data.optString("status").takeIf(String::isNotBlank) ?: return null
            return WearResolution(id, status)
        }
    }
}

object WearResolutions {
    private val listeners = CopyOnWriteArraySet<(WearResolution) -> Unit>()

    fun register(listener: (WearResolution) -> Unit): Closeable {
        listeners.add(listener)
        return Closeable { listeners.remove(listener) }
    }

    fun publish(resolution: WearResolution) {
        listeners.forEach { listener -> runCatching { listener(resolution) } }
    }
}
