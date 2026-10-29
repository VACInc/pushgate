package org.pushgate.wear

import java.security.KeyPair

internal class SigningKeyLifecycle(
    private val load: () -> KeyPair?,
    private val generate: () -> KeyPair,
    private val clearExisting: () -> Unit
) {
    fun getOrCreate(): KeyPair =
        load() ?: generate()

    fun regenerate(): KeyPair {
        clear()
        return generate()
    }

    fun clear() {
        clearExisting()
    }
}
