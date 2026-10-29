package org.pushgate.phone

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import java.util.concurrent.atomic.AtomicBoolean

class DecisionActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            AuthNotificationDispatcher.ACTION_DENY -> deny(context, intent)
            AuthNotificationDispatcher.ACTION_APPROVE -> approve(context, intent)
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

        val pending = goAsync()
        val completed = AtomicBoolean(false)
        val complete: (Result<String>) -> Unit = { result ->
            if (completed.compareAndSet(false, true)) {
                try {
                    handleNotificationDecisionResult(
                        result = result,
                        onSuccess = { notifications.cancel(challenge.id, binding) },
                        onFailure = {
                            DecisionClaimStore.release(context, challenge.id, binding, Decision.Approve)
                            notifications.show(challenge, binding)
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
