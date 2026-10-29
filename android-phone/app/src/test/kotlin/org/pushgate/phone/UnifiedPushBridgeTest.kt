package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class UnifiedPushBridgeTest {
    private val serverBody = """
        {"device_id":"phone-1","payload":"{\"data\":{\"expires_at\":\"2099-01-01T00:00:00Z\",\"id\":\"request-1\",\"pam_service\":\"sshd\",\"source_ip\":\"192.0.2.5\",\"system\":\"server02\",\"username\":\"serviceuser\"},\"type\":\"auth_request\"}","type":"auth_request"}
    """.trimIndent()

    @Test
    fun serverMessageBecomesTheFcmDataMapAndParsesAsAChallenge() {
        val data = UnifiedPushBridge.dataFromMessage(serverBody.toByteArray())
        assertEquals("phone-1", data["device_id"])
        assertEquals("phone-1", FcmPushEntrypoint.deviceIdFromData(data))
        val challenge = FcmPushEntrypoint.challengeFromData(data)
        assertEquals("request-1", challenge.id)
        assertEquals("serviceuser", challenge.username)
        assertEquals("server02", challenge.system)
        assertTrue(challenge.isActionable())
    }

    @Test
    fun backgroundHandlerRejectsAForeignDeviceAndAcceptsTheEnrolledOne() {
        val data = UnifiedPushBridge.dataFromMessage(serverBody.toByteArray())
        var shown = 0
        assertTrue(FcmBackgroundMessageHandler.showNotification(data, "someone-else") { shown += 1 }.isFailure)
        assertEquals(0, shown)
        assertTrue(FcmBackgroundMessageHandler.showNotification(data, "phone-1") { shown += 1 }.isSuccess)
        assertEquals(1, shown)
    }

    @Test
    fun nonAuthRequestMessagesAreRefused() {
        try {
            UnifiedPushBridge.dataFromMessage("""{"type":"noise","payload":"{}"}""".toByteArray())
            fail("noise accepted")
        } catch (expected: IllegalArgumentException) {
        }
        try {
            UnifiedPushBridge.dataFromMessage("not json".toByteArray())
            fail("garbage accepted")
        } catch (expected: org.json.JSONException) {
        }
    }

    @Test
    fun distributorChoicePrefersSavedThenNtfyThenAny() {
        assertEquals("io.heckel.ntfy", UnifiedPushBridge.chooseDistributor(listOf("org.other", "io.heckel.ntfy"), null))
        assertEquals("org.other", UnifiedPushBridge.chooseDistributor(listOf("org.other", "io.heckel.ntfy"), "org.other"))
        assertEquals("org.other", UnifiedPushBridge.chooseDistributor(listOf("org.other"), "io.heckel.ntfy"))
        assertNull(UnifiedPushBridge.chooseDistributor(emptyList(), "io.heckel.ntfy"))
    }
}

class ChallengeResolutionTest {
    @Test
    fun decidedEventsAreRecognizedOnEveryDeliveryPath() {
        val event = """{"type":"auth_decided","data":{"id":"request-9","status":"timeout","decided_at":"2026-09-22T20:40:00Z"}}"""
        assertEquals(ChallengeResolution("request-9", "timeout"), ChallengeResolution.fromJson(org.json.JSONObject(event)))
        // FCM data map shape
        assertEquals(ChallengeResolution("request-9", "timeout"), ChallengeResolution.fromData(mapOf("type" to "auth_decided", "payload" to event)))
        // UnifiedPush body shape
        val up = UnifiedPushBridge.dataFromMessage("""{"type":"auth_decided","device_id":"phone-1","data":{"id":"request-9","status":"approved"}}""".toByteArray())
        assertEquals("auth_decided", up["type"])
        assertEquals(ChallengeResolution("request-9", "approved"), ChallengeResolution.fromData(up))
        assertNull(ChallengeResolution.fromData(mapOf("type" to "auth_request", "payload" to "{}")))
        assertNull(ChallengeResolution.fromJson(org.json.JSONObject("""{"type":"auth_decided","data":{"id":"x"}}""")))
    }

    @Test
    fun decidedEventsShortCircuitTheChallengeHandlerAndReachListeners() {
        var seen: ChallengeResolution? = null
        val subscription = ChallengeResolutions.register { seen = it }
        try {
            var challengeDelivered = 0
            FcmPushEntrypoint.register("phone-1", { challengeDelivered += 1 }, {}).use {
                FcmPushEntrypoint.onMessageData(mapOf("type" to "auth_decided", "payload" to """{"type":"auth_decided","data":{"id":"r","status":"denied"}}"""))
            }
            assertEquals(ChallengeResolution("r", "denied"), seen)
            assertEquals(0, challengeDelivered)
        } finally {
            subscription.close()
        }
    }

    @Test
    fun aStaleApproveIsReportedWithTheServerStatus() {
        val result = validateDecisionResponse("""{"data":{"id":"r","status":"timeout","first_response_wins":true}}""", Decision.Approve)
        assertTrue(result.isFailure)
        val error = result.exceptionOrNull() as DecisionResponseException
        assertEquals("timeout", error.receivedStatus)
    }
}
