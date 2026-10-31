package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SettledRequestDedupeTest {
    @Test
    fun lateCopyOfASettledRequestIsNotReposted() {
        // The tap cleared the notification, so it is no longer shown; the settled mark must win.
        assertFalse(deliveryShouldPostNotification(alreadyShown = false, settled = true))
    }

    @Test
    fun copyArrivingWhileThisPhonesDecisionIsClaimedIsNotReposted() {
        assertFalse(deliveryShouldPostNotification(alreadyShown = false, claimed = true))
    }

    @Test
    fun freshRequestIsPosted() {
        assertTrue(deliveryShouldPostNotification(alreadyShown = false, claimed = false, settled = false))
    }

    @Test
    fun settledRecordsRoundTripAndExpire() {
        val now = 1_000_000L
        val records = mapOf("req-a" to now + SettledRequestStore.RETENTION_MILLIS, "req-b" to now - 1)
        val decoded = SettledRecords.decode(SettledRecords.encode(records))
        assertEquals(records, decoded)
        assertTrue(SettledRecords.contains(decoded, "req-a", now))
        assertFalse(SettledRecords.contains(decoded, "req-b", now))
        assertFalse(SettledRecords.contains(decoded, "req-c", now))
        assertEquals(setOf("req-a"), SettledRecords.prune(decoded, now).keys)
    }

    @Test
    fun malformedRecordsAreDropped() {
        val decoded = SettledRecords.decode(setOf("garbage", "|req", "notanumber|req", "5|", "7|req|with|pipes"))
        assertEquals(mapOf("req|with|pipes" to 7L), decoded)
    }
}
