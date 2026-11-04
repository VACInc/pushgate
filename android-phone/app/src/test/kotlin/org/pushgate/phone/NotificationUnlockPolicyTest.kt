package org.pushgate.phone

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NotificationUnlockPolicyTest {
    @Test
    fun approveFromThePhoneNotificationRequiresAnUnlockedDevice() {
        assertTrue(phoneActionRequiresUnlock(AuthNotificationDispatcher.ACTION_APPROVE))
    }

    @Test
    fun denyAndOpenStayAvailableOnTheLockScreen() {
        assertFalse(phoneActionRequiresUnlock(AuthNotificationDispatcher.ACTION_DENY))
        assertFalse(phoneActionRequiresUnlock(AuthNotificationDispatcher.ACTION_OPEN))
    }

    @Test
    fun promptlessApproveIsTheBroadcastThatTheUnlockRequirementGuards() {
        // A promptless Approve is delivered to the background receiver (no activity, so no
        // keyguard); it is exactly the action the unlock requirement must cover.
        assertFalse(decisionActionNeedsActivity(AuthNotificationDispatcher.ACTION_APPROVE, requireBiometric = false))
        assertTrue(phoneActionRequiresUnlock(AuthNotificationDispatcher.ACTION_APPROVE))
    }
}
