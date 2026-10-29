package org.pushgate.wear

import android.app.Activity
import android.content.Context
import java.security.PrivateKey
import java.util.concurrent.atomic.AtomicBoolean

class WearApprovalFlow(
    private val sender: WearDecisionSender = DirectWearDecisionSender(),
    private val approvalGate: WearApprovalGate = WearApprovalGate()
) {
    fun approve(activity: Activity, enrollment: WearEnrollment, challenge: WearChallenge, callback: (Result<WearDecisionOutcome>) -> Unit) {
        if (!isWearChallengeActionable(challenge)) {
            callback(Result.failure(SecurityException("Approval request is expired or invalid")))
            return
        }
        val privateKey = loadPrivateKey(activity, enrollment).getOrElse { error ->
            callback(Result.failure(error))
            return
        }
        if (!challenge.requireBiometric) {
            approve(enrollment, challenge, privateKey, biometricVerified = false, callback = callback)
            return
        }
        runCatching {
            approvalGate.requestApproval(activity, challenge) { result ->
                result
                    .onSuccess { approve(enrollment, challenge, privateKey, biometricVerified = true, callback = callback) }
                    .onFailure { callback(Result.failure(it)) }
            }
        }.onFailure { callback(Result.failure(it)) }
    }

    fun approve(enrollment: WearEnrollment, challenge: WearChallenge, privateKey: PrivateKey, biometricVerified: Boolean, callback: (Result<WearDecisionOutcome>) -> Unit) {
        sendSafely(enrollment, challenge, WearDecision.Approve, privateKey, callback, biometricVerified)
    }

    /** Background approve with no visible surface; refuses any challenge that requires the prompt. */
    fun approveWithDeviceKey(context: Context, enrollment: WearEnrollment, challenge: WearChallenge, callback: (Result<WearDecisionOutcome>) -> Unit) {
        if (challenge.requireBiometric) {
            callback(Result.failure(SecurityException("Biometric approval requires the approval screen")))
            return
        }
        if (!isWearChallengeActionable(challenge)) {
            callback(Result.failure(SecurityException("Approval request is expired or invalid")))
            return
        }
        val privateKey = loadPrivateKey(context, enrollment).getOrElse { error ->
            callback(Result.failure(error))
            return
        }
        approve(enrollment, challenge, privateKey, biometricVerified = false, callback = callback)
    }

    fun denyWithDeviceKey(context: Context, enrollment: WearEnrollment, challenge: WearChallenge, callback: (Result<WearDecisionOutcome>) -> Unit) {
        if (!isWearChallengeActionable(challenge)) {
            callback(Result.failure(SecurityException("Approval request is expired or invalid")))
            return
        }
        val privateKey = loadPrivateKey(context, enrollment).getOrElse { error ->
            callback(Result.failure(error))
            return
        }
        deny(enrollment, challenge, privateKey, callback)
    }

    fun deny(enrollment: WearEnrollment, challenge: WearChallenge, privateKey: PrivateKey, callback: (Result<WearDecisionOutcome>) -> Unit) {
        sendSafely(
            enrollment,
            challenge,
            WearDecision.Deny,
            privateKey,
            callback,
            false
        )
    }

    private fun loadPrivateKey(context: Context, enrollment: WearEnrollment): Result<PrivateKey> =
        runCatching {
            WearKeyStore.privateKey(context, enrollment.signingKeyAlias)
                ?: throw IllegalStateException("Missing watch signing key; enroll again")
        }

    private fun sendSafely(
        enrollment: WearEnrollment,
        challenge: WearChallenge,
        decision: WearDecision,
        privateKey: PrivateKey,
        callback: (Result<WearDecisionOutcome>) -> Unit,
        biometricVerified: Boolean
    ) {
        if (!isWearChallengeActionable(challenge)) {
            callback(Result.failure(SecurityException("Approval request is expired or invalid")))
            return
        }
        val completed = AtomicBoolean(false)
        val complete: (Result<WearDecisionOutcome>) -> Unit = { result ->
            if (completed.compareAndSet(false, true)) callback(result)
        }
        runCatching {
            sender.send(
                enrollment,
                challenge,
                decision,
                privateKey,
                complete,
                biometricVerified
            )
        }.onFailure { complete(Result.failure(it)) }
    }
}
