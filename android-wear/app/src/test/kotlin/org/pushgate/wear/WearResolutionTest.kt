package org.pushgate.wear

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class WearResolutionTest {
    @Test
    fun serverAndRelayShapesParse() {
        val event = JSONObject("""{"type":"auth_decided","data":{"id":"request-1","status":"approved","decided_at":"2026-09-22T20:40:00Z"}}""")
        assertEquals(WearResolution("request-1", "approved"), WearResolution.fromServerEvent(event))
        assertEquals(WearResolution("request-1", "timeout"), WearResolution.fromRelayPayload("""{"id":"request-1","status":"timeout"}""".toByteArray()))
        assertNull(WearResolution.fromServerEvent(JSONObject("""{"type":"auth_request","data":{"id":"request-1"}}""")))
        assertNull(WearResolution.fromRelayPayload("garbage".toByteArray()))
        assertNull(WearResolution.fromServerEvent(JSONObject("""{"type":"auth_decided","data":{"status":"approved"}}""")))
    }

    @Test
    fun listenersReceivePublishedResolutions() {
        var seen: WearResolution? = null
        WearResolutions.register { seen = it }.use {
            WearResolutions.publish(WearResolution("r", "denied"))
        }
        assertEquals(WearResolution("r", "denied"), seen)
        WearResolutions.publish(WearResolution("r2", "denied"))
        assertEquals(WearResolution("r", "denied"), seen)
    }
}
