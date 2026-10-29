package org.pushgate.wear

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class WearDecisionActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val decision = when (intent.action) {
            WearAuthNotificationDispatcher.ACTION_APPROVE -> WearDecision.Approve
            WearAuthNotificationDispatcher.ACTION_DENY -> WearDecision.Deny
            else -> return
        }
        val pending = goAsync()
        val challenge = WearAuthNotificationDispatcher.challengeFromIntent(intent)
        val enrollment = WearEnrollmentStore.load(context)
        if (challenge != null && !isWearChallengeActionable(challenge)) {
            WearAuthNotificationDispatcher(context).cancel(challenge.id)
            pending.finish()
            return
        }
        if (
            challenge == null ||
            enrollment == null ||
            !WearAuthNotificationDispatcher.matchesEnrollment(intent, enrollment)
        ) {
            pending.finish()
            return
        }
        val binding = enrollment.decisionBinding(challenge.id)
        if (!WearInFlightDecisions.tryAcquire(binding)) {
            pending.finish()
            return
        }

        val flow = WearApprovalFlow()
        val send: ((Result<WearDecisionOutcome>) -> Unit) -> Unit = when (decision) {
            WearDecision.Approve -> { done -> flow.approveWithDeviceKey(context, enrollment, challenge, done) }
            WearDecision.Deny -> { done -> flow.denyWithDeviceKey(context, enrollment, challenge, done) }
        }
        send { result ->
            try {
                handleWearNotificationDecisionResult(
                    result,
                    onTerminal = {
                        val currentEnrollment = runCatching {
                            WearEnrollmentStore.load(context)
                        }.getOrNull()
                        if (binding.matches(currentEnrollment, challenge.id)) {
                            WearResolvedChallenges.mark(binding)
                            WearAuthNotificationDispatcher(context).cancel(challenge.id)
                        }
                    },
                    onRetained = {}
                )
            } finally {
                WearInFlightDecisions.release(binding)
                pending.finish()
            }
        }
    }
}
