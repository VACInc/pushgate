package org.pushgate.phone

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class EcdsaP256CryptoTest {
    @Test
    fun p256SpkiPublicKeyRoundTripsThroughBase64() {
        val keyPair = generateP256KeyPair()
        val spki = EcdsaP256Crypto.spkiPublicKey(keyPair.public)
        val encoded = Base64.getEncoder().encodeToString(spki)
        val parsed = EcdsaP256Crypto.publicKeyFromSpki(Base64.getDecoder().decode(encoded))

        assertArrayEquals(spki, parsed.encoded)
        assertEquals(DeviceKeyType.EcdsaP256, DeviceKeyCrypto.signingKey(keyPair).keyType)
        assertEquals(encoded, DeviceKeyCrypto.signingKey(keyPair).enrollmentPublicKey)
    }

    @Test
    fun sha256WithEcdsaSignatureVerifiesAgainstSpkiPublicKey() {
        val keyPair = generateP256KeyPair()
        val message = "request-1.approve.true".toByteArray(Charsets.UTF_8)
        val signature = DeviceKeyCrypto.sign(keyPair.private, message)
        val parsed = EcdsaP256Crypto.publicKeyFromSpki(EcdsaP256Crypto.spkiPublicKey(keyPair.public))

        assertTrue(EcdsaP256Crypto.verify(parsed, message, signature))
    }

    private fun generateP256KeyPair() =
        KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec(EcdsaP256Crypto.CURVE_NAME))
            generateKeyPair()
        }
}
