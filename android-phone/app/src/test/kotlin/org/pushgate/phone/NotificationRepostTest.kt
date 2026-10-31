package org.pushgate.phone

import android.app.PendingIntent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NotificationRepostTest {
    @Test
    fun repeatDeliveryOfAShownRequestDoesNotRepost() {
        assertFalse(deliveryShouldPostNotification(alreadyShown = true))
        assertTrue(deliveryShouldPostNotification(alreadyShown = false))
    }

    @Test
    fun repostKeepsTheWatchCopysActionTokensAlive() {
        val flags = DECISION_PENDING_INTENT_FLAGS
        assertEquals(0, flags and PendingIntent.FLAG_CANCEL_CURRENT)
        assertEquals(PendingIntent.FLAG_UPDATE_CURRENT, flags and PendingIntent.FLAG_UPDATE_CURRENT)
        assertEquals(PendingIntent.FLAG_IMMUTABLE, flags and PendingIntent.FLAG_IMMUTABLE)
        assertEquals(PendingIntent.FLAG_ONE_SHOT, flags and PendingIntent.FLAG_ONE_SHOT)
    }
}
