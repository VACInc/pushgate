package org.pushgate.phone

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PhoneDecisionResultTest {
    @Test
    fun completedDecisionAppliesOnlyToTheCurrentChallenge() {
        assertTrue(shouldApplyPhoneDecisionResult("request-a", "request-a"))
        assertFalse(shouldApplyPhoneDecisionResult("request-b", "request-a"))
        assertFalse(shouldApplyPhoneDecisionResult(null, "request-a"))
    }
}
