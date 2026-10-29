package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import java.security.KeyPair
import java.util.Base64

class SigningKeyLifecycleTest {
    @Test
    fun regenerateDeletesExistingKeyAndPublishesFreshRawPublicKey() {
        val store = InMemoryStore()
        val first = store.lifecycle.getOrCreate()
        val reused = store.lifecycle.getOrCreate()

        assertEquals(publicKey(first), publicKey(reused))

        val rotated = store.lifecycle.regenerate()

        assertEquals(1, store.clearCount)
        assertNotEquals(publicKey(first), publicKey(rotated))
        assertEquals(publicKey(rotated), publicKey(store.lifecycle.getOrCreate()))
    }

    @Test
    fun clearThenGetOrCreatePublishesFreshRawPublicKey() {
        val store = InMemoryStore()
        val first = store.lifecycle.getOrCreate()

        store.lifecycle.clear()
        val afterClear = store.lifecycle.getOrCreate()

        assertEquals(1, store.clearCount)
        assertNotEquals(publicKey(first), publicKey(afterClear))
    }

    private fun publicKey(keyPair: KeyPair): String =
        Base64.getEncoder().encodeToString(Ed25519Crypto.rawPublicKey(keyPair.public))

    private class InMemoryStore {
        var stored: KeyPair? = null
        var clearCount = 0
        val lifecycle = SigningKeyLifecycle(
            load = { stored },
            generate = {
                Ed25519Crypto.generateSoftwareKeyPair().also { stored = it }
            },
            clearExisting = {
                clearCount += 1
                stored = null
            }
        )
    }
}
