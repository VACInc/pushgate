package org.pushgate.phone

import android.app.Activity
import java.security.PrivateKey

class ApprovalFlow(
    private val client: DeviceAuthClient = DeviceAuthClient(),
    private val approvalGate: PhoneApprovalGate = PhoneApprovalGate()
) {
    fun approve(activity: Activity, enrollment: Enrollment, challenge: AuthChallenge, privateKey: PrivateKey, callback: (Result<String>) -> Unit) {
        if (!challenge.requireBiometric) {
            decideAfterFreshnessCheck(enrollment, challenge, privateKey, biometricVerified = false, callback = callback)
            return
        }
        approvalGate.requestApproval(activity, challenge) { result ->
            result
                .onSuccess { decideAfterFreshnessCheck(enrollment, challenge, privateKey, biometricVerified = true, callback = callback) }
                .onFailure { callback(Result.failure(it)) }
        }
    }

    /** Background approve with no visible surface; refuses any challenge that requires the prompt. */
    fun approveWithoutPrompt(enrollment: Enrollment, challenge: AuthChallenge, privateKey: PrivateKey, callback: (Result<String>) -> Unit) {
        if (challenge.requireBiometric) {
            callback(Result.failure(SecurityException("Biometric approval requires the approval screen")))
            return
        }
        decideAfterFreshnessCheck(enrollment, challenge, privateKey, biometricVerified = false, callback = callback)
    }

    private fun decideAfterFreshnessCheck(
        enrollment: Enrollment,
        challenge: AuthChallenge,
        privateKey: PrivateKey,
        biometricVerified: Boolean,
        callback: (Result<String>) -> Unit
    ) {
        if (!challenge.isActionable()) {
            callback(Result.failure(SecurityException("Authentication request expired")))
            return
        }
        runCatching {
            client.decide(enrollment, challenge.id, Decision.Approve, privateKey, callback, biometricVerified)
        }.onFailure { callback(Result.failure(it)) }
    }

    fun deny(enrollment: Enrollment, challenge: AuthChallenge, privateKey: PrivateKey, callback: (Result<String>) -> Unit) {
        runCatching {
            client.decide(enrollment, challenge.id, Decision.Deny, privateKey, callback)
        }.onFailure { callback(Result.failure(it)) }
    }
}
