package org.pushgate.phone

import java.security.PublicKey

internal object Ed25519PublicKeyEncoding {
    private const val RAW_KEY_SIZE = 32
    private const val TAG_SEQUENCE = 0x30
    private const val TAG_OBJECT_IDENTIFIER = 0x06
    private const val TAG_NULL = 0x05
    private const val TAG_BIT_STRING = 0x03
    private val ED25519_OID = byteArrayOf(0x2b, 0x65, 0x70)

    fun rawFromPublicKey(publicKey: PublicKey): ByteArray {
        val encoded = publicKey.encoded
            ?: throw IllegalStateException("Missing Ed25519 public key encoding")
        return rawFromEncodedKey(encoded)
    }

    fun rawFromEncodedKey(encoded: ByteArray): ByteArray {
        if (encoded.size == RAW_KEY_SIZE) return encoded.copyOf()

        return runCatching { parseSubjectPublicKeyInfo(encoded) }
            .getOrElse { throw IllegalStateException("Unexpected Ed25519 public key encoding", it) }
    }

    private fun parseSubjectPublicKeyInfo(encoded: ByteArray): ByteArray {
        val top = DerReader(encoded)
        val subjectPublicKeyInfo = DerReader(top.readValue(TAG_SEQUENCE))
        top.requireFullyRead()

        val algorithm = DerReader(subjectPublicKeyInfo.readValue(TAG_SEQUENCE))
        val oid = algorithm.readValue(TAG_OBJECT_IDENTIFIER)
        require(oid.contentEquals(ED25519_OID)) { "SubjectPublicKeyInfo is not Ed25519" }
        if (!algorithm.isFullyRead()) {
            val parameters = algorithm.readElement()
            require(parameters.tag == TAG_NULL && parameters.value.isEmpty()) {
                "Ed25519 parameters must be absent or NULL"
            }
        }
        algorithm.requireFullyRead()

        val bitString = subjectPublicKeyInfo.readValue(TAG_BIT_STRING)
        subjectPublicKeyInfo.requireFullyRead()
        require(bitString.isNotEmpty()) { "Missing BIT STRING unused-bits byte" }
        require(bitString[0].toInt() == 0) { "Ed25519 public key must be byte-aligned" }

        val rawKey = bitString.copyOfRange(1, bitString.size)
        require(rawKey.size == RAW_KEY_SIZE) { "Ed25519 public key must be 32 bytes" }
        return rawKey
    }

    private class DerReader(private val bytes: ByteArray) {
        private var offset = 0

        fun readValue(expectedTag: Int): ByteArray {
            val element = readElement()
            require(element.tag == expectedTag) { "Expected tag $expectedTag but found ${element.tag}" }
            return element.value
        }

        fun readElement(): DerElement {
            require(offset < bytes.size) { "Truncated DER tag" }
            val tag = bytes[offset++].toInt() and 0xff
            val length = readLength()
            require(length <= bytes.size - offset) { "Truncated DER value" }
            val value = bytes.copyOfRange(offset, offset + length)
            offset += length
            return DerElement(tag, value)
        }

        fun isFullyRead(): Boolean = offset == bytes.size

        fun requireFullyRead() {
            require(isFullyRead()) { "Trailing DER data" }
        }

        private fun readLength(): Int {
            require(offset < bytes.size) { "Truncated DER length" }
            val first = bytes[offset++].toInt() and 0xff
            if (first < 0x80) return first

            val lengthBytes = first and 0x7f
            require(lengthBytes in 1..4) { "Unsupported DER length" }
            require(lengthBytes <= bytes.size - offset) { "Truncated DER length" }

            var length = 0L
            repeat(lengthBytes) {
                length = (length shl 8) or (bytes[offset++].toLong() and 0xff)
            }
            require(length <= Int.MAX_VALUE) { "DER length is too large" }
            return length.toInt()
        }
    }

    private data class DerElement(val tag: Int, val value: ByteArray)
}
