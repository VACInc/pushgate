package org.pushgate.phone

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.util.PrivateKeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature

internal object Ed25519Crypto {
    const val ALGORITHM = "Ed25519"
    private const val ANDROID_KEYSTORE_SIGNATURE_PROVIDER = "AndroidKeyStoreBCWorkaround"
    private const val RAW_KEY_SIZE = 32

    fun generateSoftwareKeyPair(random: SecureRandom = SecureRandom()): KeyPair {
        val privateKey = Ed25519PrivateKeyParameters(random)
        val publicKey = privateKey.generatePublicKey()
        return KeyPair(
            RawEd25519PublicKey(publicKey.encoded),
            RawEd25519PrivateKey(privateKey.encoded)
        )
    }

    fun privateKeyFromRaw(rawSeed: ByteArray): PrivateKey =
        RawEd25519PrivateKey(rawSeed)

    fun publicKeyFromRaw(rawPublicKey: ByteArray): PublicKey =
        RawEd25519PublicKey(rawPublicKey)

    fun privateKeyFromEncoded(encoded: ByteArray): PrivateKey {
        if (encoded.size == RAW_KEY_SIZE) return privateKeyFromRaw(encoded)

        val key = PrivateKeyFactory.createKey(encoded)
        require(key is Ed25519PrivateKeyParameters) { "Stored private key is not Ed25519" }
        return privateKeyFromRaw(key.encoded)
    }

    fun publicKeyFromEncoded(encoded: ByteArray): PublicKey =
        publicKeyFromRaw(Ed25519PublicKeyEncoding.rawFromEncodedKey(encoded))

    fun rawPublicKey(publicKey: PublicKey): ByteArray =
        when (publicKey) {
            is RawEd25519PublicKey -> publicKey.rawKey()
            else -> Ed25519PublicKeyEncoding.rawFromPublicKey(publicKey)
        }

    fun rawPrivateKey(privateKey: PrivateKey): ByteArray {
        require(privateKey is RawEd25519PrivateKey) { "Private key is not a raw software Ed25519 key" }
        return privateKey.rawSeed()
    }

    fun sign(privateKey: PrivateKey, message: ByteArray): ByteArray =
        when (privateKey) {
            is RawEd25519PrivateKey -> signRaw(privateKey.rawSeed(), message)
            else -> signJca(privateKey, message)
        }

    fun verify(publicKey: PublicKey, message: ByteArray, signature: ByteArray): Boolean =
        verifyRawPublicKey(rawPublicKey(publicKey), message, signature)

    fun verifyRawPublicKey(rawPublicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        require(rawPublicKey.size == RAW_KEY_SIZE) { "Ed25519 public key must be 32 bytes" }
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(rawPublicKey, 0))
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(signature)
    }

    private fun signRaw(rawSeed: ByteArray, message: ByteArray): ByteArray {
        require(rawSeed.size == RAW_KEY_SIZE) { "Ed25519 private key seed must be 32 bytes" }
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(rawSeed, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    private fun signJca(privateKey: PrivateKey, message: ByteArray): ByteArray {
        val signer = Signature.getInstance(ALGORITHM, ANDROID_KEYSTORE_SIGNATURE_PROVIDER)
        signer.initSign(privateKey)
        signer.update(message)
        return signer.sign()
    }
}

internal class RawEd25519PrivateKey(rawSeed: ByteArray) : PrivateKey {
    private val seed = rawSeed.copyOf()

    init {
        require(seed.size == 32) { "Ed25519 private key seed must be 32 bytes" }
    }

    fun rawSeed(): ByteArray = seed.copyOf()

    override fun getAlgorithm(): String = Ed25519Crypto.ALGORITHM

    override fun getFormat(): String = "RAW"

    override fun getEncoded(): ByteArray = rawSeed()
}

internal class RawEd25519PublicKey(rawPublicKey: ByteArray) : PublicKey {
    private val key = rawPublicKey.copyOf()

    init {
        require(key.size == 32) { "Ed25519 public key must be 32 bytes" }
    }

    fun rawKey(): ByteArray = key.copyOf()

    override fun getAlgorithm(): String = Ed25519Crypto.ALGORITHM

    override fun getFormat(): String = "RAW"

    override fun getEncoded(): ByteArray = rawKey()
}
