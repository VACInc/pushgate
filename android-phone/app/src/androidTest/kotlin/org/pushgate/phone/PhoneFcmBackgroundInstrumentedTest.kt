package org.pushgate.phone

import android.Manifest
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.time.Instant

@RunWith(AndroidJUnit4::class)
class PhoneFcmBackgroundInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val notificationManager: NotificationManager
        get() = context.getSystemService(NotificationManager::class.java)

    @Before
    fun setUp() {
        grantNotificationPermission()
        notificationManager.cancelAll()
        PendingDenialScheduler.clear(context)
        EnrollmentStore.save(
            context,
            Enrollment(
                serverUrl = "https://pushgate.example.invalid",
                deviceId = "androidtest-phone",
                enrollmentToken = "",
                enrollApi = "/api/v1/devices/{id}/enroll",
                decisionApi = "/api/v1/auth/requests/{id}/decision"
            )
        )
    }

    @After
    fun tearDown() {
        notificationManager.cancelAll()
        PendingDenialScheduler.clear(context)
    }

    @Test
    fun fcmDataPayloadShowsApproveDenyNotificationWithoutMainActivity() {
        val challengeId = "androidtest-fcm-background-${System.nanoTime()}"
        val result = FcmBackgroundMessageHandler.showNotification(context, challengeData(challengeId))

        assertTrue(result.isSuccess)
        val notification = waitForNotification("${PhoneKeyStore.DEFAULT_ALIAS}:$challengeId")

        assertEquals("PushGate", notification.extras.getString(Notification.EXTRA_TITLE))
        assertEquals(listOf("Approve", "Deny"), notification.actions.map { it.title.toString() })
        assertTrue(notification.actions.all { it.actionIntent != null })
        assertEquals(context.packageName, notification.smallIcon.resPackage)
    }

    @Test
    fun collidingChallengeHashesStillCreateDistinctPendingIntents() {
        val dispatcher = AuthNotificationDispatcher(context)
        val firstId = "androidtest-Aa"
        val secondId = "androidtest-BB"
        assertEquals(firstId.hashCode(), secondId.hashCode())

        dispatcher.show(challenge(firstId))
        val firstApprove = waitForNotification("${PhoneKeyStore.DEFAULT_ALIAS}:$firstId").actions[0].actionIntent
        dispatcher.show(challenge(secondId))
        val secondApprove = waitForNotification("${PhoneKeyStore.DEFAULT_ALIAS}:$secondId").actions[0].actionIntent

        assertNotEquals(firstApprove, secondApprove)
    }

    @Test
    fun staleEnrollmentActionIsRejectedAndOneShot() {
        val challenge = challenge("androidtest-stale-${System.nanoTime()}")
        val dispatcher = AuthNotificationDispatcher(context)
        dispatcher.show(challenge)
        val tag = "${PhoneKeyStore.DEFAULT_ALIAS}:${challenge.id}"
        val deny = waitForNotification(tag).actions[1].actionIntent
        EnrollmentStore.save(
            context,
            Enrollment(
                serverUrl = "https://other.example.invalid",
                deviceId = "other-phone",
                enrollmentToken = "",
                enrollApi = "/api/v1/devices/{id}/enroll",
                decisionApi = "/api/v1/auth/requests/{id}/decision"
            )
        )

        deny.send()
        waitForNotificationRemoval(tag)

        assertTrue(PendingDenialStore.loadDeliverable(context).isEmpty())
        assertThrows(PendingIntent.CanceledException::class.java) { deny.send() }
    }

    @Test
    fun denialClaimBlocksConflictingApprovalAcrossSurfaces() {
        val challenge = challenge("androidtest-conflict-${System.nanoTime()}")
        val binding = AuthNotificationDispatcher.currentBinding(context)!!

        assertTrue(DecisionClaimStore.tryClaim(context, challenge, binding, Decision.Deny))
        assertFalse(DecisionClaimStore.tryClaim(context, challenge, binding, Decision.Approve))
    }

    @Test
    fun notificationAutomaticallyDisappearsAtChallengeExpiry() {
        val challengeId = "androidtest-timeout-${System.nanoTime()}"
        val dispatcher = AuthNotificationDispatcher(context)
        dispatcher.show(challenge(challengeId, Instant.now().plusSeconds(3).toString()))
        val tag = "${PhoneKeyStore.DEFAULT_ALIAS}:$challengeId"

        val notification = waitForNotification(tag)
        assertTrue(notification.timeoutAfter in 1..5_000)
        waitForNotificationRemoval(tag)
    }

    @Test
    fun expiredFcmPayloadFailsClosedWithoutNotification() {
        val challengeId = "androidtest-expired-${System.nanoTime()}"
        val result = FcmBackgroundMessageHandler.showNotification(
            context,
            challengeData(challengeId).mapValues { (_, value) ->
                value.replace("2099-07-06T12:01:00Z", "2020-01-01T00:00:00Z")
            }
        )

        assertTrue(result.isFailure)
        assertTrue(notificationManager.activeNotifications.none { it.tag?.endsWith(":$challengeId") == true })
    }

    @Test
    fun delayedFcmPayloadForPreviousEnrollmentIsRejected() {
        val challengeId = "androidtest-stale-fcm-${System.nanoTime()}"
        val result = FcmBackgroundMessageHandler.showNotification(
            context,
            challengeData(challengeId).toMutableMap().apply { put("device_id", "previous-phone") }
        )

        assertTrue(result.isFailure)
        assertTrue(notificationManager.activeNotifications.none { it.tag?.endsWith(":$challengeId") == true })
    }

    @Test
    fun firebaseTokenProviderFailsSoftWithoutConfiguredFirebaseProject() {
        val latch = CountDownLatch(1)
        var tokenResult: Result<String>? = null

        FirebaseMessagingTokenProvider().refreshCurrentToken { result ->
            tokenResult = result
            latch.countDown()
        }

        assertTrue("unconfigured Firebase should report failure", latch.await(5, TimeUnit.SECONDS))
        assertTrue(tokenResult?.isFailure == true)
    }

    private fun waitForNotification(tag: String): Notification {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < deadline) {
            val notification = notificationManager.activeNotifications
                .firstOrNull { it.tag == tag }
                ?.notification
            if (notification != null) return notification
            Thread.sleep(100)
        }
        throw AssertionError("notification $tag did not appear")
    }

    private fun waitForNotificationRemoval(tag: String) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < deadline) {
            if (notificationManager.activeNotifications.none { it.tag == tag }) return
            Thread.sleep(100)
        }
        throw AssertionError("notification $tag remained")
    }

    private fun grantNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val command = "pm grant ${context.packageName} ${Manifest.permission.POST_NOTIFICATIONS}"
        val output = InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command)
        output.close()
        Thread.sleep(300)
    }

    private fun challengeData(challengeId: String): Map<String, String> =
        mapOf(
            "device_id" to "androidtest-phone",
            "challenge" to """
            {
              "type":"auth_request",
              "data":{
                "id":"$challengeId",
                "username":"androidtest",
                "system":"background-host",
                "pam_service":"sudo",
                "source_ip":"203.0.113.42",
                "requested_at":"2099-07-06T12:00:00Z",
                "expires_at":"2099-07-06T12:01:00Z",
                "require_biometric":false
              }
            }
            """
        )

    private fun challenge(id: String, expiresAt: String = "2099-07-06T12:01:00Z") = AuthChallenge(
        id = id,
        username = "androidtest",
        system = "background-host",
        pamService = "sudo",
        sourceIp = "203.0.113.42",
        geolocation = null,
        requestedAt = "2099-07-06T12:00:00Z",
        expiresAt = expiresAt,
        requireBiometric = false
    )
}
