package org.pushgate.phone

import java.io.IOException
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

class PermanentPushFailure(message: String, cause: Throwable? = null) : IOException(message, cause)
class PushReconnecting(cause: Throwable) : IOException("Push connection lost; reconnecting", cause)

/** Retry only the receive channel, never an approval or a remote command. */
class RecoveringPushChannel(
    private val createChannel: () -> PushChannel,
    private val baseDelayMillis: Long = 500,
    private val maxDelayMillis: Long = 10_000,
    private val readyTimeoutMillis: Long = 15_000
) : PushChannel {
    private val lock = Any()
    private var generation = 0L
    private var running = false
    private var attempt = 0
    private var channel: PushChannel? = null
    private var scheduled: ScheduledFuture<*>? = null
    private var watchdog: ScheduledFuture<*>? = null
    private var deliver: (AuthChallenge) -> Unit = {}
    private var error: (Throwable) -> Unit = {}
    private var ready: () -> Unit = {}

    override fun start(onChallenge: (AuthChallenge) -> Unit, onError: (Throwable) -> Unit, onReady: () -> Unit) {
        synchronized(lock) {
            close()
            running = true
            attempt = 0
            deliver = onChallenge
            error = onError
            ready = onReady
            connect(generation)
        }
    }

    private fun connect(expected: Long): Unit = synchronized(lock) {
        if (!running || generation != expected) return@synchronized
        try {
            val next = createChannel()
            channel = next
            watchdog = executor.schedule(
                { failed(expected, IOException("Push server did not become ready")) },
                readyTimeoutMillis, TimeUnit.MILLISECONDS
            )
            next.start(
                onChallenge = { challenge -> synchronized(lock) {
                    if (running && generation == expected) deliver(challenge)
                } },
                onError = { failed(expected, it) },
                onReady = { synchronized(lock) {
                    if (running && generation == expected) {
                        watchdog?.cancel(false)
                        watchdog = null
                        attempt = 0
                        ready()
                    }
                } }
            )
        } catch (failure: Exception) {
            failed(expected, failure)
        }
    }

    private fun failed(expected: Long, failure: Throwable): Unit = synchronized(lock) {
        if (!running || generation != expected) return@synchronized
        generation += 1
        watchdog?.cancel(false)
        watchdog = null
        channel?.close()
        channel = null
        if (failure is PermanentPushFailure || failure !is IOException) {
            running = false
            error(failure)
            return@synchronized
        }
        val delay = (baseDelayMillis * (1L shl attempt.coerceAtMost(15))).coerceAtMost(maxDelayMillis)
        attempt += 1
        val nextGeneration = generation
        scheduled = executor.schedule({ connect(nextGeneration) }, delay, TimeUnit.MILLISECONDS)
        error(PushReconnecting(failure))
    }

    override fun close() = synchronized(lock) {
        running = false
        generation += 1
        scheduled?.cancel(false)
        watchdog?.cancel(false)
        scheduled = null
        watchdog = null
        channel?.close()
        channel = null
        deliver = {}
        error = {}
        ready = {}
    }

    private companion object {
        val executor = Executors.newSingleThreadScheduledExecutor { task ->
            Thread(task, "pushgate-reconnect").apply { isDaemon = true }
        }
    }
}
