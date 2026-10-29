package org.pushgate.phone

import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class RecoveringPushChannelTest {
    private class Fake : PushChannel {
        var fail: (Throwable) -> Unit = {}
        var ready: () -> Unit = {}
        var closed = false
        override fun start(onChallenge: (AuthChallenge) -> Unit, onError: (Throwable) -> Unit, onReady: () -> Unit) {
            fail = onError
            ready = onReady
        }
        override fun close() { closed = true }
    }

    @Test fun retriesNetworkLossAndIgnoresOldCallbacks() {
        val channels = CopyOnWriteArrayList<Fake>()
        val second = CountDownLatch(1)
        val errors = CopyOnWriteArrayList<Throwable>()
        var ready = 0
        val recovery = RecoveringPushChannel({ Fake().also {
            channels += it
            if (channels.size == 2) second.countDown()
        } }, baseDelayMillis = 10)
        try {
            recovery.start({}, errors::add, { ready += 1 })
            channels[0].ready()
            channels[0].fail(IOException("network lost"))
            assertTrue(second.await(2, TimeUnit.SECONDS))
            // Wait for start() to register callbacks after factory construction.
            Thread.sleep(50)
            channels[0].ready()
            channels[0].fail(IOException("late failure"))
            assertEquals(1, ready)
            channels[1].ready()
            assertEquals(2, ready)
            assertEquals(1, errors.size)
            assertTrue(errors.single() is PushReconnecting)
            assertTrue(channels[0].closed)
        } finally { recovery.close() }
        assertTrue(channels[1].closed)
    }

    @Test fun doesNotRetryAuthenticationFailure() {
        val channels = CopyOnWriteArrayList<Fake>()
        val recovery = RecoveringPushChannel({ Fake().also { channels += it } }, baseDelayMillis = 10)
        val errors = mutableListOf<Throwable>()
        recovery.start({}, errors::add)
        channels.single().fail(PermanentPushFailure("403"))
        Thread.sleep(80)
        assertEquals(1, channels.size)
        assertEquals(1, errors.size)
        assertTrue(channels.single().closed)
        recovery.close()
    }

    @Test fun closeCancelsPendingReconnect() {
        val channels = CopyOnWriteArrayList<Fake>()
        val recovery = RecoveringPushChannel({ Fake().also { channels += it } }, baseDelayMillis = 80)
        recovery.start({}, {})
        channels.single().fail(IOException("network lost"))
        recovery.close()
        Thread.sleep(150)
        assertEquals(1, channels.size)
    }

    @Test fun retriesWhenServerNeverSendsReadySnapshot() {
        val attempts = CountDownLatch(2)
        val recovery = RecoveringPushChannel({ Fake().also { attempts.countDown() } }, baseDelayMillis = 10, readyTimeoutMillis = 30)
        try {
            recovery.start({}, {})
            assertTrue(attempts.await(2, TimeUnit.SECONDS))
        } finally { recovery.close() }
    }

    @Test fun synchronousNetworkFailureRetriesWithoutLosingCloseFence() {
        val attempts = CountDownLatch(2)
        val recovery = RecoveringPushChannel({
            attempts.countDown()
            throw IOException("temporary network error")
        }, baseDelayMillis = 10)
        try {
            recovery.start({}, {})
            assertTrue(attempts.await(2, TimeUnit.SECONDS))
        } finally { recovery.close() }
    }
}
