package org.pushgate.wear

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.Uri
import android.os.Build

class WearAuthNotificationDispatcher(private val context: Context) {
    fun show(enrollment: WearEnrollment, challenge: WearChallenge) {
        val timeoutMillis = wearChallengeRemainingMillis(challenge) ?: return
        ensureChannel()
        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_monochrome)
            .setContentTitle("PushGate")
            .setContentText(wearNotificationText(challenge))
            .setStyle(Notification.BigTextStyle().bigText(wearNotificationText(challenge)))
            .setCategory(Notification.CATEGORY_STATUS)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setColor(0xFF7C6CFF.toInt())
            .setShowWhen(true)
            .setWhen(System.currentTimeMillis())
            .setTimeoutAfter(timeoutMillis)
            .setOnlyAlertOnce(true)
            .setOngoing(false)
            .setAutoCancel(true)
            .addAction(action(ACTION_APPROVE, "Approve", enrollment, challenge))
            .addAction(action(ACTION_DENY, "Deny", enrollment, challenge))
            .build()
        manager().notify(notificationId(challenge.id), notification)
    }

    fun cancel(challengeId: String) {
        manager().cancel(notificationId(challengeId))
    }

    fun cancelAll() {
        manager().cancelAll()
    }

    private fun action(
        action: String,
        title: String,
        enrollment: WearEnrollment,
        challenge: WearChallenge
    ): Notification.Action {
        val needsActivity = wearDecisionActionNeedsActivity(action, challenge.requireBiometric)
        val target = if (needsActivity) WearNotificationDecisionActivity::class.java else WearDecisionActionReceiver::class.java
        val intent = decisionIntent(target, action, enrollment, challenge)
        val pendingIntent = if (needsActivity) {
            PendingIntent.getActivity(context, requestCode(action, challenge.id), intent, pendingFlags())
        } else {
            PendingIntent.getBroadcast(context, requestCode(action, challenge.id), intent, pendingFlags())
        }
        val icon = if (action == ACTION_APPROVE) android.R.drawable.ic_input_add else android.R.drawable.ic_menu_close_clear_cancel
        return Notification.Action.Builder(Icon.createWithResource(context, icon), title, pendingIntent).build()
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(CHANNEL_ID, "PushGate approvals", NotificationManager.IMPORTANCE_DEFAULT)
        manager().createNotificationChannel(channel)
    }

    private fun manager(): NotificationManager = context.getSystemService(NotificationManager::class.java)

    private fun decisionIntent(
        target: Class<*>,
        action: String,
        enrollment: WearEnrollment,
        challenge: WearChallenge
    ): Intent =
        Intent(context, target)
            .setAction(action)
            // PendingIntent identity ignores extras. A unique immutable data URI
            // prevents a request-code hash collision from rebinding an action.
            .setData(
                Uri.Builder()
                    .scheme("pushgate-wear")
                    .authority("decision")
                    .appendPath(action)
                    .appendPath(challenge.id)
                    .build()
            )
            .putExtra(EXTRA_ID, challenge.id)
            .putExtra(EXTRA_SIGNING_KEY_ALIAS, enrollment.signingKeyAlias)
            .putExtra(EXTRA_USERNAME, challenge.username)
            .putExtra(EXTRA_SYSTEM, challenge.system)
            .putExtra(EXTRA_PAM_SERVICE, challenge.pamService)
            .putExtra(EXTRA_SOURCE_IP, challenge.sourceIp)
            .putExtra(EXTRA_GEOLOCATION, challenge.geolocation)
            .putExtra(EXTRA_REQUESTED_AT, challenge.requestedAt)
            .putExtra(EXTRA_EXPIRES_AT, challenge.expiresAt)
            .putExtra(EXTRA_REQUIRE_BIOMETRIC, challenge.requireBiometric)

    private fun pendingFlags(): Int = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE

    private fun requestCode(action: String, challengeId: String): Int = 31 * challengeId.hashCode() + action.hashCode()

    private fun notificationId(challengeId: String): Int = challengeId.hashCode()

    companion object {
        const val CHANNEL_ID = "pushgate.wear.auth"
        const val ACTION_APPROVE = "org.pushgate.wear.APPROVE"
        const val ACTION_DENY = "org.pushgate.wear.DENY"
        const val EXTRA_ID = "challenge_id"
        const val EXTRA_SIGNING_KEY_ALIAS = "signing_key_alias"
        const val EXTRA_USERNAME = "username"
        const val EXTRA_SYSTEM = "system"
        const val EXTRA_PAM_SERVICE = "pam_service"
        const val EXTRA_SOURCE_IP = "source_ip"
        const val EXTRA_GEOLOCATION = "geolocation"
        const val EXTRA_REQUESTED_AT = "requested_at"
        const val EXTRA_EXPIRES_AT = "expires_at"
        const val EXTRA_REQUIRE_BIOMETRIC = "require_biometric"

        fun challengeFromIntent(intent: Intent): WearChallenge? {
            val id = intent.getStringExtra(EXTRA_ID)?.takeIf(String::isNotBlank) ?: return null
            return WearChallenge(
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

        fun matchesEnrollment(intent: Intent, enrollment: WearEnrollment): Boolean =
            isWearNotificationEnrollmentCurrent(
                expectedSigningKeyAlias = intent.getStringExtra(EXTRA_SIGNING_KEY_ALIAS),
                currentEnrollment = enrollment
            )
    }
}

/**
 * Only an Approve that must show the biometric/device-credential prompt needs a visible
 * surface; every other tap is signed and sent from the background receiver.
 */
internal fun wearDecisionActionNeedsActivity(action: String, requireBiometric: Boolean): Boolean =
    action == WearAuthNotificationDispatcher.ACTION_APPROVE && requireBiometric

internal fun isWearNotificationEnrollmentCurrent(
    expectedSigningKeyAlias: String?,
    currentEnrollment: WearEnrollment?
): Boolean = expectedSigningKeyAlias != null &&
    currentEnrollment?.signingKeyAlias == expectedSigningKeyAlias

internal fun wearNotificationText(challenge: WearChallenge): String {
    val user = challenge.username.ifBlank { "Unknown user" }
    val service = challenge.pamService.ifBlank { "authentication" }.let {
        if (it.equals("ssh", ignoreCase = true)) "sshd" else it
    }
    val system = challenge.system.ifBlank { "unknown device" }
    val source = challenge.sourceIp?.takeIf { it.isNotBlank() } ?: "unknown IP"
    return "$user requests $service on $system from $source"
}
