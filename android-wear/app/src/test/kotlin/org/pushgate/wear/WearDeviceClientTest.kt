package org.pushgate.wear

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class WearDeviceClientTest {
    @Test
    fun clientClassifiesHttpClientErrorAsDefinitiveRejection() {
        withServer { server ->
            server.enqueue(MockResponse().setResponseCode(403))

            val result = awaitEnrollment(server)

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertTrue(error is DefinitiveEnrollmentRejection)
            assertEquals(403, (error as DefinitiveEnrollmentRejection).statusCode)
        }
    }

    @Test
    fun clientKeepsServerErrorAmbiguous() {
        withServer { server ->
            server.enqueue(MockResponse().setResponseCode(503))

            val result = awaitEnrollment(server)

            assertTrue(result.isFailure)
            assertFalse(result.exceptionOrNull() is DefinitiveEnrollmentRejection)
        }
    }

    @Test
    fun clientKeepsRequestTimeoutAmbiguous() {
        withServer { server ->
            server.enqueue(MockResponse().setResponseCode(408))

            val result = awaitEnrollment(server)

            assertTrue(result.isFailure)
            assertFalse(result.exceptionOrNull() is DefinitiveEnrollmentRejection)
        }
    }

    @Test
    fun clientAcceptsSuccessfulEnrollment() {
        withServer { server ->
            server.enqueue(MockResponse().setResponseCode(200).setBody("accepted"))

            val result = awaitEnrollment(server)

            assertEquals("accepted", result.getOrThrow())
        }
    }

    @Test
    fun synchronousRequestConstructionFailureReportsThatNoRequestStarted() {
        var callbackCount = 0
        var result: Result<String>? = null

        WearDeviceClient().enroll(
            enrollment = enrollment(
                serverUrl = "://invalid",
                deviceId = "watch-1",
                enrollmentToken = "token-1",
                enrollApi = "/api/v1/devices/{id}/enroll",
                decisionApi = "/api/v1/auth/requests/{id}/decision"
            ),
            publicKey = "public-key"
        ) {
            callbackCount += 1
            result = it
        }

        assertEquals(1, callbackCount)
        assertTrue(requireNotNull(result).exceptionOrNull() is EnrollmentRequestNotStarted)
    }

    private fun awaitEnrollment(server: MockWebServer): Result<String> {
        val latch = CountDownLatch(1)
        var result: Result<String>? = null
        WearDeviceClient().enroll(enrollment(server), "public-key") {
            result = it
            latch.countDown()
        }
        assertTrue("enrollment callback timed out", latch.await(3, TimeUnit.SECONDS))
        return requireNotNull(result)
    }

    private fun enrollment(server: MockWebServer): WearEnrollment = WearEnrollment(
        serverUrl = server.url("/").toString().trimEnd('/'),
        deviceId = "watch-1",
        enrollmentToken = "token-1",
        enrollApi = "/api/v1/devices/{id}/enroll",
        decisionApi = "/api/v1/auth/requests/{id}/decision"
    )

    private fun enrollment(
        serverUrl: String,
        deviceId: String,
        enrollmentToken: String,
        enrollApi: String,
        decisionApi: String
    ): WearEnrollment = WearEnrollment(
        serverUrl = serverUrl,
        deviceId = deviceId,
        enrollmentToken = enrollmentToken,
        enrollApi = enrollApi,
        decisionApi = decisionApi
    )

    private inline fun withServer(block: (MockWebServer) -> Unit) {
        val server = MockWebServer()
        server.start()
        try {
            block(server)
        } finally {
            server.shutdown()
        }
    }
}
