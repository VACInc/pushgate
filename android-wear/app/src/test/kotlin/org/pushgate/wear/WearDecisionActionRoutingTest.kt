package org.pushgate.wear

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WearDecisionActionRoutingTest {
    @Test
    fun onlyBiometricApproveNeedsAVisibleSurface() {
        assertTrue(wearDecisionActionNeedsActivity(WearAuthNotificationDispatcher.ACTION_APPROVE, requireBiometric = true))
        assertFalse(wearDecisionActionNeedsActivity(WearAuthNotificationDispatcher.ACTION_APPROVE, requireBiometric = false))
        assertFalse(wearDecisionActionNeedsActivity(WearAuthNotificationDispatcher.ACTION_DENY, requireBiometric = true))
        assertFalse(wearDecisionActionNeedsActivity(WearAuthNotificationDispatcher.ACTION_DENY, requireBiometric = false))
    }
}
