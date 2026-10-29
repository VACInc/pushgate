package org.pushgate.phone

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DecisionActionRoutingTest {
    @Test
    fun onlyBiometricApproveNeedsAVisibleSurface() {
        assertTrue(decisionActionNeedsActivity(AuthNotificationDispatcher.ACTION_APPROVE, requireBiometric = true))
        assertFalse(decisionActionNeedsActivity(AuthNotificationDispatcher.ACTION_APPROVE, requireBiometric = false))
        assertFalse(decisionActionNeedsActivity(AuthNotificationDispatcher.ACTION_DENY, requireBiometric = true))
        assertFalse(decisionActionNeedsActivity(AuthNotificationDispatcher.ACTION_DENY, requireBiometric = false))
    }

    @Test
    fun promptlessApproveRefusesBiometricChallenges() {
        val challenge = AuthChallenge(
            id = "request-1",
            username = "alice",
            system = "bastion",
            pamService = "sshd",
            sourceIp = null,
            geolocation = null,
            requestedAt = null,
            expiresAt = "2099-01-01T00:00:00Z",
            requireBiometric = true
        )
        val enrollment = Enrollment(
            serverUrl = "https://pushgate.example",
            deviceId = "phone-1",
            enrollmentToken = "",
            enrollApi = "/api/v1/devices/{id}/enroll",
            decisionApi = "/api/v1/auth/requests/{id}/decision"
        )
        val key = java.security.KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair().private
        var outcome: Result<String>? = null

        ApprovalFlow().approveWithoutPrompt(enrollment, challenge, key) { outcome = it }

        assertTrue(outcome!!.isFailure)
        assertTrue(outcome!!.exceptionOrNull() is SecurityException)
    }
}
