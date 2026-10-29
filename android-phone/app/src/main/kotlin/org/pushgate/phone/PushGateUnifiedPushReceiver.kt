package org.pushgate.phone

import android.content.Context
import org.unifiedpush.android.connector.MessagingReceiver

/** UnifiedPush entry point: the distributor (ntfy app) wakes this receiver in the background. */
class PushGateUnifiedPushReceiver : MessagingReceiver() {
    override fun onNewEndpoint(context: Context, endpoint: String, instance: String) {
        UnifiedPushRegistration.onNewEndpoint(context.applicationContext, endpoint)
    }

    override fun onMessage(context: Context, message: ByteArray, instance: String) {
        val data = runCatching { UnifiedPushBridge.dataFromMessage(message) }.getOrElse { return }
        FcmPushEntrypoint.onMessageData(data)
        FcmBackgroundMessageHandler.showNotification(context.applicationContext, data)
    }

    override fun onRegistrationFailed(context: Context, instance: String) {
        UnifiedPushRegistration.onFailed(context.applicationContext, "distributor refused the registration")
    }

    override fun onUnregistered(context: Context, instance: String) {
        UnifiedPushRegistration.onUnregistered(context.applicationContext)
    }
}
