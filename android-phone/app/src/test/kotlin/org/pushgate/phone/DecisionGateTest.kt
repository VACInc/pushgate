package org.pushgate.phone

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DecisionGateTest {
    @Test
    fun settledRequestNeverStartsASecondDecisionEvenWithItsClaimReleased() {
        // auth_decided released every claim; a stale in-app card or notification copy must still lose.
        assertFalse(decisionMayStart(settled = true, conflictingClaim = false))
    }

    @Test
    fun inFlightClaimBlocksAConcurrentDecision() {
        assertFalse(decisionMayStart(settled = false, conflictingClaim = true))
    }

    @Test
    fun freshRequestMayBeDecided() {
        assertTrue(decisionMayStart(settled = false, conflictingClaim = false))
    }

    @Test
    fun notificationBodyTapDoesNotReopenASettledCard() {
        assertFalse(phoneCardShouldShow(settled = true, actionable = true))
        assertFalse(phoneCardShouldShow(settled = false, actionable = false))
        assertTrue(phoneCardShouldShow(settled = false, actionable = true))
    }

    @Test
    fun relayedWatchDecisionKindIsRead() {
        assertEquals(Decision.Approve, relayedDecisionKind("""{"decision":"approve"}"""))
        assertEquals(Decision.Deny, relayedDecisionKind("""{"decision":"deny"}"""))
        assertNull(relayedDecisionKind("""{"decision":"maybe"}"""))
        assertNull(relayedDecisionKind("not json"))
    }

    @Test
    fun serverResolutionsAreNotMarkedAsDecidedHere() {
        val resolution = ChallengeResolution.fromJson(
            JSONObject("""{"data":{"id":"req-1","status":"approved"}}""")
        )
        assertEquals(ChallengeResolution("req-1", "approved"), resolution)
        assertFalse(resolution!!.decidedHere)
    }
}
