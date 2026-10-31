package org.pushgate.phone

import org.json.JSONObject
import java.io.Closeable
import java.util.concurrent.CopyOnWriteArraySet

/** A request stopped being pending: approved or denied elsewhere, or timed out on the server. */
data class ChallengeResolution(
    val id: String,
    val status: String,
    /** Settled by this phone's own notification, watch, or background decision. */
    val decidedHere: Boolean = false
) {
    val isSuccess: Boolean get() = status == "approved"

    companion object {
        fun fromJson(json: JSONObject): ChallengeResolution? {
            val data = json.optJSONObject("data") ?: return null
            val id = data.optString("id").takeIf(String::isNotBlank) ?: return null
            val status = data.optString("status").takeIf(String::isNotBlank) ?: return null
            return ChallengeResolution(id, status)
        }

        /** Parses the FCM/UnifiedPush data map shape ({"type":"auth_decided","payload":<event json>}). */
        fun fromData(data: Map<String, String>): ChallengeResolution? {
            if (data["type"] != "auth_decided") return null
            val raw = data["payload"] ?: data["data"] ?: return null
            return runCatching { fromJson(JSONObject(raw)) }.getOrNull()
        }
    }
}

/** Process-wide bus so any delivery path (WebSocket, FCM, UnifiedPush) can clear a prompt everywhere. */
object ChallengeResolutions {
    private val listeners = CopyOnWriteArraySet<(ChallengeResolution) -> Unit>()

    fun register(listener: (ChallengeResolution) -> Unit): Closeable {
        listeners.add(listener)
        return Closeable { listeners.remove(listener) }
    }

    fun publish(resolution: ChallengeResolution) {
        listeners.forEach { listener -> runCatching { listener(resolution) } }
    }

    /**
     * A decision this phone sent outside the app screen succeeded: record it as settled, then tell
     * any open app screen so its card for the same request disappears instead of offering a
     * second Approve.
     */
    fun settledHere(context: android.content.Context, challengeId: String, decision: Decision) {
        SettledRequestStore.mark(context, challengeId)
        RequestHistoryStore.resolve(
            context,
            challengeId,
            if (decision == Decision.Approve) "approved" else "denied",
            decidedHere = true
        )
        DebugLog.log(context, "decision", "${decision.wireValue} sent for request ${challengeId.take(8)}… and accepted")
        publish(
            ChallengeResolution(
                id = challengeId,
                status = if (decision == Decision.Approve) "approved" else "denied",
                decidedHere = true
            )
        )
    }

}
