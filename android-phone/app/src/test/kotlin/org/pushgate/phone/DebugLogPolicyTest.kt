package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.LocalDate
import java.time.ZoneId
import java.time.ZonedDateTime

class DebugLogPolicyTest {
    private val zone = ZoneId.of("America/New_York")

    @Test
    fun retentionDefaultsToSevenDaysAndIsClamped() {
        assertEquals(7, DebugLogPolicy.DEFAULT_RETENTION_DAYS)
        assertEquals(1, DebugLogPolicy.clampRetention(0))
        assertEquals(1, DebugLogPolicy.clampRetention(-5))
        assertEquals(30, DebugLogPolicy.clampRetention(365))
        assertEquals(14, DebugLogPolicy.clampRetention(14))
        assertTrue(DebugLogPolicy.RETENTION_CHOICES.contains(DebugLogPolicy.DEFAULT_RETENTION_DAYS))
    }

    @Test
    fun oneFilePerLocalDay() {
        val lateEvening = ZonedDateTime.of(2026, 10, 30, 23, 30, 0, 0, zone).toInstant().toEpochMilli()
        assertEquals("pushgate-2026-10-30.log", DebugLogPolicy.fileNameFor(lateEvening, zone))
        assertEquals(LocalDate.of(2026, 10, 30), DebugLogPolicy.dateOf("pushgate-2026-10-30.log"))
        assertNull(DebugLogPolicy.dateOf("notes.txt"))
        assertNull(DebugLogPolicy.dateOf("pushgate-garbage.log"))
    }

    @Test
    fun retentionKeepsExactlyTheChosenNumberOfDaysIncludingToday() {
        val today = LocalDate.of(2026, 10, 30)
        val files = (0L..9L).map { "pushgate-${today.minusDays(it)}.log" } + "stray.tmp"
        val expired = DebugLogPolicy.expiredFiles(files, today, 7)
        val kept = files - expired.toSet()
        assertEquals((0L..6L).map { "pushgate-${today.minusDays(it)}.log" }.sorted(), kept.sorted())
        assertTrue("stray files are removed", "stray.tmp" in expired)
        assertTrue("pushgate-${today.minusDays(7)}.log" in expired)
    }

    @Test
    fun oneDayRetentionKeepsOnlyToday() {
        val today = LocalDate.of(2026, 10, 30)
        val expired = DebugLogPolicy.expiredFiles(listOf("pushgate-2026-10-30.log", "pushgate-2026-10-29.log"), today, 1)
        assertEquals(listOf("pushgate-2026-10-29.log"), expired)
    }

    @Test
    fun redactsPushEndpointsTokensKeysAndIds() {
        val fakeToken = listOf("0f1e2d3c", "4b5a", "4968", "8776", "a5b4c3d2e1f0").joinToString("-")
        val line = DebugLogPolicy.redact(
            "endpoint https://ntfy.example.org/upAbCdEf123456?up=1 token=$fakeToken " +
                "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig secret=hunter2 " +
                "request 5e6f7a8b-1c2d-4e3f-9a0b-c1d2e3f4a5b6 sig ${"A".repeat(44)}"
        )
        assertFalse(line, line.contains("upAbCdEf123456"))
        assertTrue(line, line.contains("https://ntfy.example.org/…"))
        assertFalse(line, line.contains("0f1e2d3c-4b5a"))
        assertFalse(line, line.contains("eyJhbGciOiJIUzI1NiJ9"))
        assertFalse(line, line.contains("hunter2"))
        assertFalse(line, line.contains("A".repeat(44)))
        assertTrue("ids keep a short prefix for correlation: $line", line.contains("5e6f7a8b…"))
        assertFalse(line, line.contains("9a0b-c1d2e3f4a5b6"))
    }

    @Test
    fun redactsPemBlocksAndKeepsPlainWords() {
        // Built at runtime so secret scanners do not mistake the fixture for a real key.
        val kind = "PRIVATE" + " KEY"
        val pem = "-----BEGIN $kind-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n-----END $kind-----"
        assertEquals("start [key removed] end", DebugLogPolicy.redact("start $pem end"))
        val plain = "Posted notification for web-02 (on screen=true, channel importance=4)"
        assertEquals(plain, DebugLogPolicy.redact(plain))
    }

    @Test
    fun formattedLineCarriesLocalTimeTagAndRedactedMessage() {
        val at = ZonedDateTime.of(2026, 10, 30, 18, 5, 1, 123_000_000, zone).toInstant().toEpochMilli()
        val line = DebugLogPolicy.formatLine(at, zone, "push", "password=abc")
        assertEquals("2026-10-30 18:05:01.123 -04:00 [push] password=[removed]", line)
        assertTrue(DebugLogPolicy.formatLine(at, zone, "bad tag!\n", "x").contains("[badtag]"))
    }
}
