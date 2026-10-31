package org.pushgate.phone

import android.content.Context
import org.unifiedpush.android.connector.UnifiedPush

/**
 * Registers this app with the UnifiedPush distributor (the ntfy app) and
 * uploads the resulting endpoint through the existing signed push-token
 * route, so the server delivers approvals in the background without FCM.
 * The endpoint is an https URL; the server recognizes it by that shape.
 */
object UnifiedPushRegistration {
    private const val PREFS = "pushgate.unifiedpush"
    private const val ENDPOINT = "endpoint"
    private const val UPLOADED_ENDPOINT = "uploaded_endpoint"
    private const val LAST_ERROR = "last_error"

    /** Returns a user-facing status line when background push cannot be set up, else null. */
    fun ensureRegistered(context: Context): String? {
        val available = UnifiedPush.getDistributors(context)
        val chosen = UnifiedPushBridge.chooseDistributor(available, UnifiedPush.getSavedDistributor(context))
            ?: run {
                DebugLog.log(context, "push", "No UnifiedPush distributor installed")
                return "Background push needs the ntfy app installed and signed in."
            }
        DebugLog.log(context, "push", "Registering with push distributor $chosen")
        UnifiedPush.saveDistributor(context, chosen)
        UnifiedPush.registerApp(context, UnifiedPushBridge.INSTANCE, messageForDistributor = "PushGate approvals")
        return null
    }

    fun onNewEndpoint(context: Context, url: String) {
        prefs(context).edit().putString(ENDPOINT, url).remove(LAST_ERROR).apply()
        upload(context, url)
    }

    fun onFailed(context: Context, reason: String) {
        prefs(context).edit().putString(LAST_ERROR, reason).apply()
    }

    fun onUnregistered(context: Context) {
        prefs(context).edit().remove(ENDPOINT).remove(UPLOADED_ENDPOINT).apply()
    }

    fun endpoint(context: Context): String? = prefs(context).getString(ENDPOINT, null)

    fun isUploaded(context: Context): Boolean {
        val endpoint = endpoint(context) ?: return false
        return prefs(context).getString(UPLOADED_ENDPOINT, null) == endpoint
    }

    /** Re-upload after enrollment or key changes when the server may not have the endpoint yet. */
    fun resyncIfNeeded(context: Context) {
        val endpoint = endpoint(context) ?: return
        if (!isUploaded(context)) upload(context, endpoint)
    }

    fun statusLine(context: Context): String? {
        val endpoint = endpoint(context)
        val error = prefs(context).getString(LAST_ERROR, null)
        return when {
            endpoint != null && isUploaded(context) -> "Connected. Background push via UnifiedPush (ntfy)."
            endpoint != null -> "Background push endpoint registered; sending it to PushGate."
            error != null -> "Background push registration failed: $error"
            else -> null
        }
    }

    private fun upload(context: Context, url: String, client: DeviceAuthClient = DeviceAuthClient()) {
        val enrollment = EnrollmentStore.load(context) ?: return
        val key = PhoneKeyStore.privateKey(context) ?: return
        val appContext = context.applicationContext
        runCatching {
            client.updatePushToken(enrollment, key, url) { result ->
                result
                    .onSuccess {
                        prefs(appContext).edit().putString(UPLOADED_ENDPOINT, url).remove(LAST_ERROR).apply()
                        DebugLog.log(appContext, "push", "Push endpoint sent to PushGate server")
                    }
                    .onFailure {
                        prefs(appContext).edit().putString(LAST_ERROR, "upload: ${it.javaClass.simpleName}").apply()
                        DebugLog.error(appContext, "push", "Could not send push endpoint to PushGate server", it)
                    }
            }
        }.onFailure { prefs(appContext).edit().putString(LAST_ERROR, "upload: ${it.javaClass.simpleName}").apply() }
    }

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
