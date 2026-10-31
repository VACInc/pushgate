package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DeliveryHealthTest {
    private val healthy = DeliveryHealth(
        notificationsAllowed = true,
        channelImportance = 4,
        batteryUnrestricted = true,
        backgroundRestricted = false,
        standbyBucket = 10,
        pushRegistered = true,
        lastStop = null
    )

    @Test
    fun healthyPhoneHasNoWarnings() {
        assertEquals(emptyList<String>(), DeliveryWarnings.of(healthy))
    }

    @Test
    fun notificationsOffIsReportedFirstAndAloneForNotifications() {
        val warnings = DeliveryWarnings.of(healthy.copy(notificationsAllowed = false, channelImportance = 0))
        assertEquals(1, warnings.size)
        assertTrue(warnings[0].startsWith("Notifications are off for PushGate"))
    }

    @Test
    fun blockedAndSilentChannelsAreDistinct() {
        assertTrue(DeliveryWarnings.of(healthy.copy(channelImportance = 0)).single().contains("turned off"))
        assertTrue(DeliveryWarnings.of(healthy.copy(channelImportance = 2)).single().contains("silent"))
        assertTrue(DeliveryWarnings.of(healthy.copy(channelImportance = 1)).single().contains("silent"))
        assertEquals(emptyList<String>(), DeliveryWarnings.of(healthy.copy(channelImportance = 3)))
        assertEquals("channel not created yet is not a problem", emptyList<String>(), DeliveryWarnings.of(healthy.copy(channelImportance = null)))
    }

    @Test
    fun backgroundRestrictionBeatsBatteryOptimization() {
        val restricted = DeliveryWarnings.of(healthy.copy(backgroundRestricted = true, batteryUnrestricted = false))
        assertEquals(1, restricted.size)
        assertTrue(restricted[0].contains("restricts PushGate"))
        val bucket = DeliveryWarnings.of(healthy.copy(standbyBucket = 45))
        assertTrue(bucket.single().contains("restricts PushGate"))
        assertEquals(emptyList<String>(), DeliveryWarnings.of(healthy.copy(standbyBucket = 40)))
        val optimized = DeliveryWarnings.of(healthy.copy(batteryUnrestricted = false))
        assertTrue(optimized.single().contains("Battery optimization"))
    }

    @Test
    fun missingBackgroundPushIsReported() {
        assertTrue(DeliveryWarnings.of(healthy.copy(pushRegistered = false)).single().contains("only arrive while PushGate is open"))
    }

    @Test
    fun onlyStopsThatBlockPushesAreNoticed() {
        val forceStop = AppExit(AppExitReasons.USER_REQUESTED, "stop us.example due to from pid 1234", 2_000L)
        val swipe = AppExit(AppExitReasons.USER_REQUESTED, "remove task", 2_000L)
        val memory = AppExit(AppExitReasons.LOW_MEMORY, null, 2_000L)
        val crash = AppExit(AppExitReasons.CRASH, "crash", 2_000L)
        assertTrue(DeliveryWarnings.lastStopNotice(forceStop, 1_000L)!!.startsWith("Android stopped PushGate"))
        assertTrue(DeliveryWarnings.lastStopNotice(crash, 1_000L)!!.startsWith("PushGate crashed"))
        assertNull(DeliveryWarnings.lastStopNotice(swipe, 1_000L))
        assertNull(DeliveryWarnings.lastStopNotice(memory, 1_000L))
        assertNull("a stop before the app was last used is old news", DeliveryWarnings.lastStopNotice(forceStop, 3_000L))
        assertTrue("a stop exactly at the cutoff still counts", DeliveryWarnings.lastStopNotice(forceStop, 2_000L) != null)
        assertNull(DeliveryWarnings.lastStopNotice(null, 0L))
    }

    @Test
    fun exitReasonsReadAsPlainEnglish() {
        assertEquals("Android closed PushGate to free memory (normal)", AppExitReasons.plainEnglish(AppExitReasons.LOW_MEMORY, null))
        assertEquals("Android stopped PushGate (force stop or app sleeping)", AppExitReasons.plainEnglish(AppExitReasons.USER_STOPPED, null))
        assertTrue(AppExitReasons.plainEnglish(AppExitReasons.FREEZER, null).contains("froze"))
        assertTrue(AppExitReasons.blocksBackgroundDelivery(AppExitReasons.ANR, null))
        assertFalse(AppExitReasons.blocksBackgroundDelivery(AppExitReasons.SIGNALED, null))
        assertFalse(AppExitReasons.blocksBackgroundDelivery(AppExitReasons.USER_REQUESTED, null))
    }
}
