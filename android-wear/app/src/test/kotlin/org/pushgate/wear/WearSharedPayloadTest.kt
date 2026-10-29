package org.pushgate.wear

import org.junit.Assert.assertEquals
import org.junit.Test

class WearSharedPayloadTest {
    @Test
    fun releaseExternalShareAcceptsEnrollmentPayload() {
        val disposition = classifyWearSharedPayload(
            """{"device_id":"watch-1","enrollment_token":"token-1"}""",
            allowChallenge = false
        )

        assertEquals(WearSharedPayloadDisposition.Enrollment, disposition)
    }

    @Test
    fun releaseExternalShareRejectsChallengePayload() {
        val disposition = classifyWearSharedPayload(
            """{"id":"request-1","username":"alice"}""",
            allowChallenge = false
        )

        assertEquals(WearSharedPayloadDisposition.Rejected, disposition)
    }

    @Test
    fun internalPasteCanLoadChallengePayload() {
        val disposition = classifyWearSharedPayload(
            """{"id":"request-1","username":"alice"}""",
            allowChallenge = true
        )

        assertEquals(WearSharedPayloadDisposition.Challenge, disposition)
    }
}
