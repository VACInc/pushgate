package org.pushgate.wear

import java.security.AlgorithmParameters
import java.security.KeyPair
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

enum class DeviceKeyType(val wireValue: String) {
    Ed25519("ed25519"),
    EcdsaP256("ecdsa_p256")
}

data class DeviceSigningKey(
    val keyPair: KeyPair,
    val keyType: DeviceKeyType,
    val enrollmentPublicKey: String
) {
    val privateKey: PrivateKey
        get() = keyPair.private
}

object DeviceKeyCrypto {
    fun signingKey(keyPair: KeyPair): DeviceSigningKey {
        val keyType = keyType(keyPair.public)
        return DeviceSigningKey(
            keyPair = keyPair,
            keyType = keyType,
            enrollmentPublicKey = enrollmentPublicKey(keyPair.public, keyType)
        )
    }

    fun sign(privateKey: PrivateKey, message: ByteArray): ByteArray =
        when (keyType(privateKey)) {
            DeviceKeyType.Ed25519 -> Ed25519Crypto.sign(privateKey, message)
            DeviceKeyType.EcdsaP256 -> EcdsaP256Crypto.sign(privateKey, message)
        }

    fun enrollmentPublicKey(publicKey: PublicKey): String =
        enrollmentPublicKey(publicKey, keyType(publicKey))

    fun keyType(privateKey: PrivateKey): DeviceKeyType =
        when {
            privateKey is RawEd25519PrivateKey -> DeviceKeyType.Ed25519
            privateKey.algorithm.equals(Ed25519Crypto.ALGORITHM, ignoreCase = true) -> DeviceKeyType.Ed25519
            privateKey.algorithm.equals("EC", ignoreCase = true) -> DeviceKeyType.EcdsaP256
            else -> throw IllegalArgumentException("Unsupported device private key algorithm: ${privateKey.algorithm}")
        }

    private fun enrollmentPublicKey(publicKey: PublicKey, keyType: DeviceKeyType): String =
        when (keyType) {
            DeviceKeyType.Ed25519 -> Base64.getEncoder().encodeToString(Ed25519Crypto.rawPublicKey(publicKey))
            DeviceKeyType.EcdsaP256 -> Base64.getEncoder().encodeToString(EcdsaP256Crypto.spkiPublicKey(publicKey))
        }

    private fun keyType(publicKey: PublicKey): DeviceKeyType {
        if (EcdsaP256Crypto.isP256PublicKey(publicKey)) return DeviceKeyType.EcdsaP256
        Ed25519Crypto.rawPublicKey(publicKey)
        return DeviceKeyType.Ed25519
    }
}

object EcdsaP256Crypto {
    const val CURVE_NAME = "secp256r1"
    private const val KEY_ALGORITHM = "EC"
    private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    fun sign(privateKey: PrivateKey, message: ByteArray): ByteArray =
        Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey)
            update(message)
            sign()
        }

    fun verify(publicKey: PublicKey, message: ByteArray, signature: ByteArray): Boolean =
        runCatching {
            val p256PublicKey = requireP256PublicKey(publicKey)
            Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initVerify(p256PublicKey)
                update(message)
                verify(signature)
            }
        }.getOrDefault(false)

    fun spkiPublicKey(publicKey: PublicKey): ByteArray {
        val p256PublicKey = requireP256PublicKey(publicKey)
        return p256PublicKey.encoded ?: throw IllegalArgumentException("P-256 public key has no X.509 encoding")
    }

    fun publicKeyFromSpki(spki: ByteArray): PublicKey {
        val publicKey = KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(X509EncodedKeySpec(spki))
        return requireP256PublicKey(publicKey)
    }

    fun isP256PublicKey(publicKey: PublicKey): Boolean =
        runCatching { requireP256PublicKey(publicKey) }.isSuccess

    fun requireP256PublicKey(publicKey: PublicKey): ECPublicKey {
        require(publicKey is ECPublicKey) { "Public key is not EC" }
        require(sameEcSpec(publicKey.params, p256Spec())) { "EC public key is not P-256" }
        return publicKey
    }

    private fun p256Spec(): ECParameterSpec =
        AlgorithmParameters.getInstance(KEY_ALGORITHM).run {
            init(ECGenParameterSpec(CURVE_NAME))
            getParameterSpec(ECParameterSpec::class.java)
        }

    private fun sameEcSpec(left: ECParameterSpec, right: ECParameterSpec): Boolean =
        left.curve.field.fieldSize == right.curve.field.fieldSize &&
            left.curve.a == right.curve.a &&
            left.curve.b == right.curve.b &&
            left.generator.affineX == right.generator.affineX &&
            left.generator.affineY == right.generator.affineY &&
            left.order == right.order &&
            left.cofactor == right.cofactor
}
