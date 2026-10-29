package org.pushgate.wear

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

class Ed25519PublicKeyEncodingTest {
    private val rawKey = ByteArray(32) { (it + 1).toByte() }

    @Test
    fun rawThirtyTwoByteKeyPassesThrough() {
        val encoded = rawKey.copyOf()
        val extracted = Ed25519PublicKeyEncoding.rawFromEncodedKey(encoded)

        assertArrayEquals(rawKey, extracted)
        encoded[0] = 99
        assertEquals(1, extracted[0].toInt())
    }

    @Test
    fun extractsBundledSoftwareRawPublicKey() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val raw = Ed25519Crypto.rawPublicKey(keyPair.public)

        assertEquals(32, raw.size)
        assertArrayEquals(raw, Ed25519PublicKeyEncoding.rawFromEncodedKey(keyPair.public.encoded))
    }

    @Test
    fun rawPublicKeyVerifiesSignatureFromBundledPrivateKey() {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair()
        val raw = Ed25519Crypto.rawPublicKey(keyPair.public)
        val message = "request-1.approve.true".toByteArray(Charsets.UTF_8)
        val signature = Ed25519Crypto.sign(keyPair.private, message)
        val verified = Ed25519Crypto.verifyRawPublicKey(raw, message, signature)

        assertEquals(32, raw.size)
        assertTrue(verified)
    }

    @Test
    fun extractsSubjectPublicKeyInfoWithNullParametersAndLongLengths() {
        val algorithm = derSequence(derOid(0x2b, 0x65, 0x70) + derNull())
        val encoded = spki(algorithm = algorithm, forceLongLengths = true)

        assertArrayEquals(rawKey, Ed25519PublicKeyEncoding.rawFromEncodedKey(encoded))
    }

    @Test
    fun rejectsMalformedSubjectPublicKeyInfo() {
        assertRejects(spki(algorithm = derSequence(derOid(0x2b, 0x65, 0x6e))))
        assertRejects(spki(unusedBits = 1))
        assertRejects(spki(raw = rawKey.copyOf(31)))
        assertRejects(spki() + byteArrayOf(0))
    }

    @Test
    fun rejectsP256SubjectPublicKeyInfo() {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        assertRejects(keyPair.public.encoded)
    }

    private fun assertRejects(encoded: ByteArray) {
        assertThrows(IllegalStateException::class.java) {
            Ed25519PublicKeyEncoding.rawFromEncodedKey(encoded)
        }
    }

    private fun spki(
        raw: ByteArray = rawKey,
        algorithm: ByteArray = derSequence(derOid(0x2b, 0x65, 0x70)),
        unusedBits: Int = 0,
        forceLongLengths: Boolean = false
    ): ByteArray {
        val subjectPublicKey = derBitString(byteArrayOf(unusedBits.toByte()) + raw, forceLongLengths)
        return derSequence(algorithm + subjectPublicKey, forceLongLengths)
    }

    private fun derSequence(value: ByteArray, forceLongLength: Boolean = false): ByteArray =
        byteArrayOf(0x30) + derLength(value.size, forceLongLength) + value

    private fun derOid(vararg value: Int): ByteArray =
        byteArrayOf(0x06) + derLength(value.size) + value.map { it.toByte() }.toByteArray()

    private fun derNull(): ByteArray = byteArrayOf(0x05, 0x00)

    private fun derBitString(value: ByteArray, forceLongLength: Boolean = false): ByteArray =
        byteArrayOf(0x03) + derLength(value.size, forceLongLength) + value

    private fun derLength(size: Int, forceLongLength: Boolean = false): ByteArray {
        if (size < 0x80 && !forceLongLength) return byteArrayOf(size.toByte())
        if (size <= 0xff) return byteArrayOf(0x81.toByte(), size.toByte())
        return byteArrayOf(0x82.toByte(), (size shr 8).toByte(), size.toByte())
    }
}
