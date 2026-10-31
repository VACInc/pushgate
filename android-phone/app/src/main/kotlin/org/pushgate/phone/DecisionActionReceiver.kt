package org.pushgate.phone

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import java.util.concurrent.atomic.AtomicBoolean

class DecisionActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        // A crash here would also count toward Android marking the app bad (see the push receiver).
        try {
            val action = when (intent.action) {
                AuthNotificationDispatcher.ACTION_DENY -> "Deny"
                AuthNotificationDispatcher.ACTION_APPROVE -> "Approve"
                else -> return
            }
            DebugLog.log(context, "decision", "$action tapped on notification (request ${intent.getStringExtra(AuthNotificationDispatcher.EXTRA_ID).orEmpty().take(8)}…)")
            when (intent.action) {
                AuthNotificationDispatcher.ACTION_DENY -> deny(context, intent)
                AuthNotificationDispatcher.ACTION_APPROVE -> approve(context, intent)
            }
        } catch (error: Throwable) {
            runCatching { DebugLog.error(context, "decision", "Notification action failed", error) }
        }
    }

    private fun deny(context: Context, intent: Intent) {
        val challenge = AuthNotificationDispatcher.challengeFromIntent(intent)
        val binding = AuthNotificationDispatcher.bindingFromIntent(intent)
        val enrollment = EnrollmentStore.load(context)
        val currentBinding = AuthNotificationDispatcher.currentBinding(context)
        if (
            challenge == null ||
            !challenge.isActionable() ||
            binding == null ||
            binding != currentBinding ||
            enrollment == null
        ) {
            challenge?.id?.let { AuthNotificationDispatcher(context).cancel(it, binding) }
            return
        }
        if (PendingDenialScheduler.enqueue(context, challenge, binding)) {
            AuthNotificationDispatcher(context).cancel(challenge.id, binding)
        } else {
            AuthNotificationDispatcher(context).show(challenge, binding)
        }
    }

    /**
     * Promptless approve straight from the notification action. The dispatcher only routes
     * Approve here when the challenge does not require biometrics; a biometric challenge that
     * still lands here is re-shown so the next tap goes through the approval screen.
     */
    private fun approve(context: Context, intent: Intent) {
        val notifications = AuthNotificationDispatcher(context)
        val challenge = AuthNotificationDispatcher.challengeFromIntent(intent)
        val binding = AuthNotificationDispatcher.bindingFromIntent(intent)
        val enrollment = EnrollmentStore.load(context)
        val currentBinding = AuthNotificationDispatcher.currentBinding(context)
        val privateKey = binding?.takeIf { it == currentBinding }?.let {
            PhoneKeyStore.privateKeyOrNull(context, it.signingKeyAlias)
        }
        if (
            challenge == null ||
            !challenge.isActionable() ||
            binding == null ||
            enrollment == null ||
            privateKey == null
        ) {
            challenge?.id?.let { notifications.cancel(it, binding) }
            return
        }
        if (challenge.requireBiometric) {
            notifications.show(challenge, binding)
            return
        }
        if (!DecisionClaimStore.tryClaim(context, challenge, binding, Decision.Approve)) return
        // Clear on tap; a failure below posts an "approve failed" notification instead.
        notifications.cancel(challenge.id, binding)

        val pending = goAsync()
        val completed = AtomicBoolean(false)
        val complete: (Result<String>) -> Unit = { result ->
            if (completed.compareAndSet(false, true)) {
                try {
                    handleNotificationDecisionResult(
                        result = result,
                        onSuccess = {
                            ChallengeResolutions.settledHere(context, challenge.id, Decision.Approve)
                            notifications.cancel(challenge.id, binding)
                        },
                        onFailure = {
                            DecisionClaimStore.release(context, challenge.id, binding, Decision.Approve)
                            DebugLog.error(context, "decision", "Approve from notification failed", result.exceptionOrNull())
                            val failure = approveFailure(result.exceptionOrNull(), challenge.isActionable())
                            if (failure.retryable) {
                                notifications.show(challenge, binding, failure.message)
                            } else {
                                notifications.showApproveFailed(challenge, binding, failure.message)
                            }
                        }
                    )
                } finally {
                    pending.finish()
                }
            }
        }
        ApprovalFlow().approveWithoutPrompt(enrollment, challenge, privateKey, complete)
    }
}
