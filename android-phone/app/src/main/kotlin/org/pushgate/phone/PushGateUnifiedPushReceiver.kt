package org.pushgate.phone

import android.content.Context
import org.unifiedpush.android.connector.MessagingReceiver

/**
 * UnifiedPush entry point: the distributor (ntfy app) wakes this receiver in the background.
 *
 * Nothing thrown here may escape: an uncaught exception kills the process, and two background
 * crashes within a minute make Android treat the app as bad and drop every later push until the
 * user opens it, which looks exactly like "requests stop arriving while the app is closed".
 */
class PushGateUnifiedPushReceiver : MessagingReceiver() {
    override fun onNewEndpoint(context: Context, endpoint: String, instance: String) {
        guard(context, "new push endpoint") {
            DebugLog.log(context, "push", "Distributor sent a push endpoint ($endpoint)")
            UnifiedPushRegistration.onNewEndpoint(context.applicationContext, endpoint)
        }
    }

    override fun onMessage(context: Context, message: ByteArray, instance: String) {
        guard(context, "push message") {
            val appContext = context.applicationContext
            val data = runCatching { UnifiedPushBridge.dataFromMessage(message) }.getOrElse {
                DebugLog.error(appContext, "push", "Ignored a push that is not a PushGate event (${message.size} bytes)", it)
                return@guard
            }
            DebugLog.log(appContext, "push", "Push received over UnifiedPush: ${describePush(data)}")
            FcmPushEntrypoint.onMessageData(data)
            FcmBackgroundMessageHandler.showNotification(appContext, data)
                .onFailure { DebugLog.log(appContext, "push", "No notification for this push: ${it.message}") }
        }
    }

    override fun onRegistrationFailed(context: Context, instance: String) {
        guard(context, "registration failed") {
            DebugLog.log(context, "push", "Distributor refused the push registration")
            UnifiedPushRegistration.onFailed(context.applicationContext, "distributor refused the registration")
        }
    }

    override fun onUnregistered(context: Context, instance: String) {
        guard(context, "unregistered") {
            DebugLog.log(context, "push", "Distributor unregistered PushGate; background push is off until the app is opened")
            UnifiedPushRegistration.onUnregistered(context.applicationContext)
        }
    }

    private inline fun guard(context: Context, what: String, block: () -> Unit) {
        try {
            block()
        } catch (error: Throwable) {
            runCatching { DebugLog.error(context.applicationContext, "push", "Failed handling $what", error) }
        }
    }
}

/** "request for web-02 by deploy (request 1a2b3c4d…, expires …)" without any token or full identifier. */
internal fun describePush(data: Map<String, String>): String {
    ChallengeResolution.fromData(data)?.let { return "decision ${it.status} (request ${it.id.take(8)}…)" }
    return runCatching {
        val challenge = FcmPushEntrypoint.challengeFromData(data)
        "request for ${safeDisplayText(challenge.system).ifBlank { "unknown host" }} by " +
            "${safeDisplayText(challenge.username).ifBlank { "unknown user" }} (request ${challenge.id.take(8)}…, " +
            "expires ${challenge.expiresAt})"
    }.getOrDefault("unreadable request")
}
