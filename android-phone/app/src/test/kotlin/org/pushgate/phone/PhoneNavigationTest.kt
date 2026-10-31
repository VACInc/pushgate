package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PhoneNavigationTest {
    @Test
    fun menuHasExactlyHomeSettingsHistoryInOrder() {
        assertEquals(listOf(PhoneScreen.Home, PhoneScreen.Settings, PhoneScreen.History), MenuScreens)
        assertEquals(listOf("Home", "Settings", "History"), MenuScreens.map(::menuLabel))
    }

    @Test
    fun backReturnsHomeFromEverySecondaryScreen() {
        assertEquals(PhoneScreen.Home, screenAfterBack(PhoneScreen.Settings, enrolled = true))
        assertEquals(PhoneScreen.Home, screenAfterBack(PhoneScreen.History, enrolled = true))
        assertEquals(PhoneScreen.Home, screenAfterBack(PhoneScreen.Enrollment, enrolled = true))
        assertEquals(PhoneScreen.Home, screenAfterBack(PhoneScreen.Settings, enrolled = false))
        assertNull(screenAfterBack(PhoneScreen.Home, enrolled = true))
        assertNull("an unenrolled phone has nowhere to go back to", screenAfterBack(PhoneScreen.Enrollment, enrolled = false))
    }

    @Test
    fun pushDescriptionNamesHostWithoutFullIds() {
        val payload = """{"type":"auth_request","data":{"id":"7c3a91d2-6e4b-4f10-8b2a-3d9e5f1a7c40","username":"deploy","system":"web-02","pam_service":"SSH access","source_ip":"bastion","expires_at":"2026-10-30T23:36:34.679197+00:00"}}"""
        val text = describePush(mapOf("device_id" to "dev", "payload" to payload))
        assertTrue(text, text.startsWith("request for web-02 by deploy (request 7c3a91d2…"))
        assertTrue(text, !text.contains("3d9e5f1a7c40"))
        val decided = describePush(
            mapOf("type" to "auth_decided", "payload" to """{"data":{"id":"7c3a91d2-6e4b-4f10-8b2a-3d9e5f1a7c40","status":"timeout"}}""")
        )
        assertEquals("decision timeout (request 7c3a91d2…)", decided)
        assertEquals("unreadable request", describePush(mapOf("payload" to "{")))
    }
}
