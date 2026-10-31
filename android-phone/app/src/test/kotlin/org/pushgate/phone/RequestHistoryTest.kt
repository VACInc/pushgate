package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.ZoneId
import java.time.ZonedDateTime

class RequestHistoryTest {
    private val request = AuthChallenge(
        id = "7c3a91d2-6e4b-4f10-8b2a-3d9e5f1a7c40",
        username = "deploy",
        system = "web-02",
        pamService = "SSH access",
        sourceIp = "bastion",
        geolocation = null,
        requestedAt = "2026-10-30T23:35:34.680976+00:00",
        expiresAt = "2026-10-30T23:36:34.679197+00:00",
        requireBiometric = false
    )
    private val requestedMillis = HistoryRecords.parseMillis(request.requestedAt)!!
    private val expiresMillis = HistoryRecords.parseMillis(request.expiresAt)!!

    @Test
    fun recordsARequestWithEveryColumn() {
        val entry = HistoryRecords.fromChallenge(request, nowMillis = requestedMillis + 500)
        assertEquals("web-02", entry.host)
        assertEquals("deploy", entry.username)
        assertEquals("bastion", entry.source)
        assertEquals("SSH access", entry.service)
        assertEquals("pending", entry.status)
        assertEquals(requestedMillis, entry.sortTimeMillis)
        assertEquals("Waiting", HistoryRecords.resultText(entry, requestedMillis + 1_000))
        assertEquals("deploy wants web-02 from bastion (SSH access)", HistoryRecords.summary(entry))
    }

    @Test
    fun repeatDeliveriesDoNotDuplicateOrResetAResult() {
        val first = HistoryRecords.fromChallenge(request, requestedMillis)
        var entries = HistoryRecords.recordRequest(emptyList(), first)
        entries = HistoryRecords.resolve(entries, request.id, "approved", decidedHere = true, nowMillis = requestedMillis + 6_000)
        entries = HistoryRecords.recordRequest(entries, HistoryRecords.fromChallenge(request, requestedMillis + 2_000))
        assertEquals(1, entries.size)
        assertEquals("approved", entries.single().status)
        assertEquals("Approved", HistoryRecords.resultText(entries.single(), requestedMillis + 10_000))
    }

    @Test
    fun firstSettledResultWins() {
        var entries = listOf(HistoryRecords.fromChallenge(request, requestedMillis))
        entries = HistoryRecords.resolve(entries, request.id, "denied", decidedHere = false, nowMillis = requestedMillis + 3_000)
        entries = HistoryRecords.resolve(entries, request.id, "approved", decidedHere = true, nowMillis = requestedMillis + 4_000)
        assertEquals("denied", entries.single().status)
        assertEquals("Denied on another device", HistoryRecords.resultText(entries.single(), requestedMillis + 5_000))
        assertEquals(requestedMillis + 3_000, entries.single().decidedAtMillis)
    }

    @Test
    fun pendingAndBlankStatusesDoNotSettle() {
        val entries = listOf(HistoryRecords.fromChallenge(request, requestedMillis))
        assertEquals(entries, HistoryRecords.resolve(entries, request.id, "pending", false, requestedMillis))
        assertEquals(entries, HistoryRecords.resolve(entries, request.id, " ", false, requestedMillis))
        assertEquals(entries, HistoryRecords.resolve(entries, "someone-else", "approved", false, requestedMillis))
    }

    @Test
    fun unansweredRequestReadsTimedOutAfterExpiry() {
        val entry = HistoryRecords.fromChallenge(request, requestedMillis)
        assertEquals("Waiting", HistoryRecords.resultText(entry, expiresMillis - 1))
        assertEquals("Timed out", HistoryRecords.resultText(entry, expiresMillis))
        val timedOut = HistoryRecords.resolve(listOf(entry), request.id, "timeout", false, expiresMillis).single()
        assertEquals("Timed out", HistoryRecords.resultText(timedOut, expiresMillis))
        assertEquals("Approved on another device", HistoryRecords.resultText(entry.copy(status = "approved"), 0))
        assertEquals("Denied", HistoryRecords.resultText(entry.copy(status = "denied", decidedHere = true), 0))
    }

    @Test
    fun newestFirstAndPrunedByAgeAndCount() {
        val now = requestedMillis + HistoryRecords.MAX_AGE_MILLIS
        val old = HistoryRecords.fromChallenge(request.copy(id = "old"), requestedMillis - 1).copy(receivedAtMillis = requestedMillis - 1)
        val kept = HistoryRecords.fromChallenge(request.copy(id = "edge"), requestedMillis).copy(receivedAtMillis = requestedMillis)
        val pruned = HistoryRecords.prune(listOf(old, kept), now)
        assertEquals(listOf("edge"), pruned.map { it.requestId })

        val many = (0 until HistoryRecords.MAX_ENTRIES + 5).map { i ->
            HistoryRecords.fromChallenge(request.copy(id = "r$i", requestedAt = null), requestedMillis + i)
        }
        val capped = HistoryRecords.prune(many, requestedMillis + 1_000)
        assertEquals(HistoryRecords.MAX_ENTRIES, capped.size)
        assertEquals("r${HistoryRecords.MAX_ENTRIES + 4}", capped.first().requestId)
        assertFalse(capped.any { it.requestId == "r0" })
        val order = HistoryRecords.newestFirst(many.take(3))
        assertEquals(listOf("r2", "r1", "r0"), order.map { it.requestId })
    }

    @Test
    fun encodesAndDecodesWithoutLosingFields() {
        val settled = HistoryRecords.resolve(
            listOf(HistoryRecords.fromChallenge(request, requestedMillis), HistoryRecords.fromChallenge(request.copy(id = "x", requestedAt = null, expiresAt = "bad"), 5L)),
            request.id, "approved", true, requestedMillis + 6_000
        )
        val decoded = HistoryRecords.decode(HistoryRecords.encode(settled))
        assertEquals(settled, decoded)
        assertNull(decoded[1].requestedAtMillis)
        assertNull(decoded[1].expiresAtMillis)
        assertEquals(emptyList<HistoryEntry>(), HistoryRecords.decode("not json"))
        assertEquals(emptyList<HistoryEntry>(), HistoryRecords.decode(null))
        assertEquals(1, HistoryRecords.decode("""[{"id":""},{"id":"ok","received":1}]""").size)
    }

    @Test
    fun summaryOmitsServiceWhenItIsJustTheHostAgain() {
        val entry = HistoryRecords.fromChallenge(request.copy(system = "web-03", pamService = "web-03"), requestedMillis)
        assertEquals("deploy wants web-03 from bastion", HistoryRecords.summary(entry))
        val blank = HistoryRecords.fromChallenge(request.copy(username = "", system = "", sourceIp = null, pamService = ""), requestedMillis)
        assertEquals("Unknown user wants unknown host from unknown address", HistoryRecords.summary(blank))
    }

    @Test
    fun historyTimesReadAsTodayYesterdayOrDate() {
        val zone = ZoneId.of("America/New_York")
        val now = ZonedDateTime.of(2026, 10, 30, 19, 50, 0, 0, zone).toInstant().toEpochMilli()
        val today = ZonedDateTime.of(2026, 10, 30, 19, 42, 0, 0, zone).toInstant().toEpochMilli()
        val yesterday = ZonedDateTime.of(2026, 10, 29, 8, 5, 0, 0, zone).toInstant().toEpochMilli()
        val older = ZonedDateTime.of(2026, 10, 20, 13, 0, 0, 0, zone).toInstant().toEpochMilli()
        assertEquals("Today 7:42 PM", historyTime(today, now, zone))
        assertEquals("Yesterday 8:05 AM", historyTime(yesterday, now, zone))
        assertEquals("Oct 20 1:00 PM", historyTime(older, now, zone))
        assertTrue(formatBytes(512).endsWith("bytes"))
        assertEquals("2 KB", formatBytes(2048))
        assertEquals("1.5 MB", formatBytes(1_572_864))
    }
}
