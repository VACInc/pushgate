package org.pushgate.phone

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.Uri
import android.os.Build

internal data class NotificationEnrollmentBinding(
    val deviceId: String,
    val signingKeyAlias: String
)

/**
 * One plain line naming who wants in, where, and from which address; the host is
 * named once. The login service is not repeated here (clients now send the host
 * name as the service too, which read as the host twice). A caller-supplied
 * reason, when present, goes on a second line.
 */
internal fun notificationText(challenge: AuthChallenge): String {
    val user = safeDisplayText(challenge.username).ifBlank { "Unknown user" }
    val system = safeDisplayText(challenge.system).ifBlank { "unknown device" }
    val source = safeDisplayText(challenge.sourceIp).ifBlank { "unknown IP" }
    val line = "$user requests $system from $source"
    val reason = safeDisplayText(challenge.reason)
    return if (reason.isEmpty()) line else "$line\n$reason"
}

/**
 * Only an Approve that must show the biometric/device-credential prompt needs a visible
 * surface. Every other tap is signed and sent from the background receiver so the app
 * never opens over whatever the approver is doing.
 */
internal fun decisionActionNeedsActivity(action: String, requireBiometric: Boolean): Boolean =
    action == AuthNotificationDispatcher.ACTION_APPROVE && requireBiometric

internal class AuthNotificationDispatcher(private val context: Context) {
    fun show(challenge: AuthChallenge, expectedBinding: NotificationEnrollmentBinding? = null) {
        val remainingLifetimeMillis = challenge.remainingLifetimeMillis() ?: return
        val binding = currentBinding(context) ?: return
        if (expectedBinding != null && expectedBinding != binding) return
        ensureChannel()
        val text = notificationText(challenge)
        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("PushGate")
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setCategory(Notification.CATEGORY_STATUS)
            .setColor(0xFF7C6CFF.toInt())
            .setShowWhen(true)
            .setWhen(System.currentTimeMillis())
            .setOngoing(false)
            .setAutoCancel(true)
            .setTimeoutAfter(remainingLifetimeMillis)
            .addAction(action(ACTION_APPROVE, "Approve", challenge, binding))
            .addAction(action(ACTION_DENY, "Deny", challenge, binding))
            .build()
        manager().notify(notificationTag(binding, challenge.id), NOTIFICATION_ID, notification)
    }

    fun cancel(challengeId: String, binding: NotificationEnrollmentBinding? = currentBinding(context)) {
        binding?.let { manager().cancel(notificationTag(it, challengeId), NOTIFICATION_ID) }
    }

    fun cancelAll() {
        manager().cancelAll()
    }

    private fun action(
        action: String,
        title: String,
        challenge: AuthChallenge,
        binding: NotificationEnrollmentBinding
    ): Notification.Action {
        val pendingIntent = if (decisionActionNeedsActivity(action, challenge.requireBiometric)) {
            PendingIntent.getActivity(context, 0, decisionIntent(NotificationDecisionActivity::class.java, action, challenge, binding), pendingFlags())
        } else {
            PendingIntent.getBroadcast(context, 0, decisionIntent(DecisionActionReceiver::class.java, action, challenge, binding), pendingFlags())
        }
        val icon = if (action == ACTION_APPROVE) android.R.drawable.ic_input_add else android.R.drawable.ic_menu_close_clear_cancel
        return Notification.Action.Builder(Icon.createWithResource(context, icon), title, pendingIntent).build()
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(CHANNEL_ID, "PushGate approvals", NotificationManager.IMPORTANCE_HIGH)
        manager().createNotificationChannel(channel)
    }

    private fun manager(): NotificationManager = context.getSystemService(NotificationManager::class.java)

    private fun decisionIntent(
        target: Class<*>,
        action: String,
        challenge: AuthChallenge,
        binding: NotificationEnrollmentBinding
    ): Intent =
        Intent(context, target)
            .setAction(action)
            .setData(
                Uri.Builder()
                    .scheme("pushgate")
                    .authority("decision")
                    .appendPath(binding.signingKeyAlias)
                    .appendPath(action)
                    .appendPath(challenge.id)
                    .build()
            )
            .putExtra(EXTRA_ID, challenge.id)
            .putExtra(EXTRA_USERNAME, challenge.username)
            .putExtra(EXTRA_SYSTEM, challenge.system)
            .putExtra(EXTRA_PAM_SERVICE, challenge.pamService)
            .putExtra(EXTRA_SOURCE_IP, challenge.sourceIp)
            .putExtra(EXTRA_GEOLOCATION, challenge.geolocation)
            .putExtra(EXTRA_REQUESTED_AT, challenge.requestedAt)
            .putExtra(EXTRA_EXPIRES_AT, challenge.expiresAt)
            .putExtra(EXTRA_REQUIRE_BIOMETRIC, challenge.requireBiometric)
            .putExtra(EXTRA_DEVICE_ID, binding.deviceId)
            .putExtra(EXTRA_SIGNING_KEY_ALIAS, binding.signingKeyAlias)

    private fun pendingFlags(): Int =
        PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE

    private fun notificationTag(binding: NotificationEnrollmentBinding, challengeId: String): String =
        "${binding.signingKeyAlias}:$challengeId"

    companion object {
        const val CHANNEL_ID = "pushgate.auth"
        const val ACTION_APPROVE = "org.pushgate.phone.APPROVE"
        const val ACTION_DENY = "org.pushgate.phone.DENY"
        const val EXTRA_ID = "challenge_id"
        const val EXTRA_USERNAME = "username"
        const val EXTRA_SYSTEM = "system"
        const val EXTRA_PAM_SERVICE = "pam_service"
        const val EXTRA_SOURCE_IP = "source_ip"
        const val EXTRA_GEOLOCATION = "geolocation"
        const val EXTRA_REQUESTED_AT = "requested_at"
        const val EXTRA_EXPIRES_AT = "expires_at"
        const val EXTRA_REQUIRE_BIOMETRIC = "require_biometric"
        const val EXTRA_DEVICE_ID = "device_id"
        const val EXTRA_SIGNING_KEY_ALIAS = "signing_key_alias"
        private const val NOTIFICATION_ID = 1

        internal fun currentBinding(context: Context): NotificationEnrollmentBinding? {
            val enrollment = EnrollmentStore.load(context) ?: return null
            return NotificationEnrollmentBinding(
                deviceId = enrollment.deviceId,
                signingKeyAlias = PhoneKeyStore.currentSigningKeyAlias(context)
            )
        }

        internal fun bindingFromIntent(intent: Intent): NotificationEnrollmentBinding? {
            val deviceId = intent.getStringExtra(EXTRA_DEVICE_ID)?.takeIf(String::isNotBlank) ?: return null
            val signingKeyAlias = intent.getStringExtra(EXTRA_SIGNING_KEY_ALIAS)?.takeIf(String::isNotBlank) ?: return null
            return NotificationEnrollmentBinding(deviceId, signingKeyAlias)
        }

        fun challengeFromIntent(intent: Intent): AuthChallenge? {
            val id = intent.getStringExtra(EXTRA_ID)?.takeIf(String::isNotBlank) ?: return null
            return AuthChallenge(
                id = id,
                username = intent.getStringExtra(EXTRA_USERNAME).orEmpty(),
                system = intent.getStringExtra(EXTRA_SYSTEM).orEmpty(),
                pamService = intent.getStringExtra(EXTRA_PAM_SERVICE).orEmpty(),
                sourceIp = intent.getStringExtra(EXTRA_SOURCE_IP),
                geolocation = intent.getStringExtra(EXTRA_GEOLOCATION),
                requestedAt = intent.getStringExtra(EXTRA_REQUESTED_AT),
                expiresAt = intent.getStringExtra(EXTRA_EXPIRES_AT).orEmpty(),
                requireBiometric = intent.getBooleanExtra(EXTRA_REQUIRE_BIOMETRIC, true)
            )
        }
    }
}
