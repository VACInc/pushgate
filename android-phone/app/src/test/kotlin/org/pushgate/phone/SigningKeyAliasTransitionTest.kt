package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SigningKeyAliasTransitionTest {
    @Test
    fun failedEnrollmentDiscardsOnlyStagedKeyAndKeepsActiveKey() {
        val store = FakeAliasStore(activeAlias = "active-key")

        store.transition.discard("staged-key")

        assertEquals("active-key", store.transition.activeAlias())
        assertEquals(listOf("staged-key"), store.clearedAliases)
    }

    @Test
    fun successfulEnrollmentActivatesStagedKeyBeforeClearingPreviousKey() {
        val events = mutableListOf<String>()
        var activeAlias: String? = "active-key"
        val transition = SigningKeyAliasTransition(
            defaultAlias = "legacy-key",
            readActiveAlias = { activeAlias },
            writeActiveAlias = { alias ->
                events += "write:$alias"
                activeAlias = alias
                true
            },
            clearAlias = { alias -> events += "clear:$alias" }
        )

        transition.activate("staged-key")

        assertEquals("staged-key", transition.activeAlias())
        assertEquals(listOf("write:staged-key", "clear:active-key"), events)
    }

    @Test
    fun recoverableSelectionKeepsPreviousKeyUntilEnrollmentIsPersisted() {
        val store = FakeAliasStore(activeAlias = "active-key")

        val previousAlias = store.transition.select("staged-key")

        assertEquals("active-key", previousAlias)
        assertEquals("staged-key", store.transition.activeAlias())
        assertEquals(emptyList<String>(), store.clearedAliases)

        store.transition.finishSelection(previousAlias)

        assertEquals(listOf("active-key"), store.clearedAliases)
    }

    @Test
    fun failedAliasPersistenceDoesNotClearCurrentKey() {
        val cleared = mutableListOf<String>()
        val transition = SigningKeyAliasTransition(
            defaultAlias = "active-key",
            readActiveAlias = { null },
            writeActiveAlias = { false },
            clearAlias = cleared::add
        )

        val result = runCatching { transition.activate("staged-key") }

        assertTrue(result.isFailure)
        assertEquals(emptyList<String>(), cleared)
        assertEquals("active-key", transition.activeAlias())
    }

    @Test
    fun clearAllPersistsNoActiveAliasBeforeClearingEveryKnownKeyOnce() {
        val events = mutableListOf<String>()
        var activeAlias: String? = "active-key"
        val transition = SigningKeyAliasTransition(
            defaultAlias = "legacy-key",
            readActiveAlias = { activeAlias },
            writeActiveAlias = { alias ->
                events += "write:$alias"
                activeAlias = alias
                true
            },
            clearAlias = { alias -> events += "clear:$alias" }
        )

        transition.clearAll(setOf("staged-key", "active-key", "previous-key"))

        assertEquals(
            listOf(
                "write:null",
                "clear:active-key",
                "clear:legacy-key",
                "clear:staged-key",
                "clear:previous-key"
            ),
            events
        )
        assertEquals("legacy-key", transition.activeAlias())
    }

    @Test
    fun clearAllDoesNotDeleteKeysWhenActiveAliasPersistenceFails() {
        val cleared = mutableListOf<String>()
        val transition = SigningKeyAliasTransition(
            defaultAlias = "legacy-key",
            readActiveAlias = { "active-key" },
            writeActiveAlias = { false },
            clearAlias = cleared::add
        )

        val result = runCatching { transition.clearAll(setOf("staged-key", "previous-key")) }

        assertTrue(result.isFailure)
        assertEquals(emptyList<String>(), cleared)
    }

    private class FakeAliasStore(var activeAlias: String?) {
        val clearedAliases = mutableListOf<String>()
        val transition = SigningKeyAliasTransition(
            defaultAlias = "legacy-key",
            readActiveAlias = { activeAlias },
            writeActiveAlias = { alias ->
                activeAlias = alias
                true
            },
            clearAlias = clearedAliases::add
        )
    }
}
