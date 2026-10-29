package org.pushgate.phone

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class PhoneOnDeviceCryptoInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val aliases = mutableListOf<String>()

    @After
    fun tearDown() {
        aliases.forEach(::deleteAliasData)
        aliases.clear()
        EnrollmentStore.clear(context)
    }

    @Test
    fun phoneKeyStoreReturnsP256EnrollmentKeyAndPersists() {
        val alias = uniqueAlias("keystore")
        val firstSigningKey = PhoneKeyStore.getOrCreateDeviceSigningKey(context, alias, preferStrongBox = false)
        val firstSpkiPublicKey = enrollmentPublicKeyBytes(alias)

        assertEquals(DeviceKeyType.EcdsaP256, firstSigningKey.keyType)
        assertTrue(firstSpkiPublicKey.size > 32)
        assertArrayEquals(EcdsaP256Crypto.spkiPublicKey(firstSigningKey.keyPair.public), firstSpkiPublicKey)
        assertEcdsaSignatureVerifies(firstSigningKey.keyPair.public, firstSigningKey.privateKey, "androidtest-request-1.approve.true")

        val secondEnrollmentSpkiPublicKey = enrollmentPublicKeyBytes(alias)
        val secondSigningKey = PhoneKeyStore.getOrCreateDeviceSigningKey(context, alias, preferStrongBox = false)

        assertArrayEquals(firstSpkiPublicKey, secondEnrollmentSpkiPublicKey)
        assertArrayEquals(firstSpkiPublicKey, EcdsaP256Crypto.spkiPublicKey(secondSigningKey.keyPair.public))
        assertEcdsaSignatureVerifies(secondSigningKey.keyPair.public, secondSigningKey.privateKey, "androidtest-request-2.deny.false")
    }

    @Test
    fun softwareEncryptedKeyStoreReloadsPersistedEd25519Key() {
        val alias = uniqueAlias("software")
        val generatedKeyPair = generatePersistedSoftwareKey(alias)
        val rawPublicKey = Ed25519Crypto.rawPublicKey(generatedKeyPair.public)
        val privateEnvelope = softwarePrefs().getString("$alias.private.raw", null)
        val publicEnvelope = softwarePrefs().getString("$alias.public.raw", null)

        assertNotNull(privateEnvelope)
        assertNotNull(publicEnvelope)
        assertTrue(privateEnvelope!!.contains(":"))
        assertTrue(publicEnvelope!!.contains(":"))
        assertTrue(privateEnvelope != Base64.getEncoder().encodeToString(Ed25519Crypto.rawPrivateKey(generatedKeyPair.private)))

        val reloadedKeyPair = PhoneKeyStore.getOrCreateSigningKey(context, alias, preferStrongBox = false)

        assertArrayEquals(rawPublicKey, Ed25519Crypto.rawPublicKey(reloadedKeyPair.public))
        assertArrayEquals(rawPublicKey, enrollmentRawPublicKey(alias))
        assertSignatureVerifies(rawPublicKey, reloadedKeyPair.private, "androidtest-software-reload.approve.true")
    }

    @Test
    fun corruptSoftwareKeyEnvelopeFailsClosedForActionEntrypoints() {
        val alias = uniqueAlias("corrupt-software")
        generatePersistedSoftwareKey(alias)
        softwarePrefs().edit().putString("$alias.private.raw", "not-an-encryption-envelope").commit()

        assertNull(PhoneKeyStore.privateKeyOrNull(context, alias))
    }

    @Test
    fun persistedEnrollmentAndKeySurviveFreshStoreLoads() {
        val alias = uniqueAlias("persisted")
        val enrollment = Enrollment(
            serverUrl = "https://pushgate.example.invalid",
            deviceId = "phone-persisted-${System.nanoTime()}",
            enrollmentToken = "unused-after-enrollment",
            enrollApi = "/api/v1/devices/{id}/enroll",
            decisionApi = "/api/v1/auth/requests/{id}/decision"
        )
        val signingKey = PhoneKeyStore.deviceSigningKeyForNewEnrollment(context, alias, preferStrongBox = false)
        val enrolledPublicKey = signingKey.enrollmentPublicKey
        val spkiPublicKey = Base64.getDecoder().decode(enrolledPublicKey)
        EnrollmentStore.save(context, enrollment)

        val loadedEnrollment = EnrollmentStore.load(context)
        val reloadedSigningKey = PhoneKeyStore.getOrCreateDeviceSigningKey(context, alias, preferStrongBox = false)
        val reloadedEnrollment = EnrollmentStore.load(context)
        val signature = DecisionSigner.sign(
            reloadedSigningKey.privateKey,
            "androidtest-persisted-request",
            Decision.Approve,
            biometricVerified = true
        )

        assertNotNull(loadedEnrollment)
        assertEquals(enrollment.serverUrl, loadedEnrollment!!.serverUrl)
        assertEquals(enrollment.deviceId, loadedEnrollment.deviceId)
        assertEquals(enrollment.decisionApi, loadedEnrollment.decisionApi)
        assertEquals("", loadedEnrollment.enrollmentToken)
        assertEquals(DeviceKeyType.EcdsaP256, reloadedSigningKey.keyType)
        assertTrue(spkiPublicKey.size > 32)
        assertArrayEquals(spkiPublicKey, EcdsaP256Crypto.spkiPublicKey(reloadedSigningKey.keyPair.public))
        assertArrayEquals(spkiPublicKey, enrollmentPublicKeyBytes(alias))
        assertEcdsaSignatureVerifies(reloadedSigningKey.keyPair.public, signature, "androidtest-persisted-request.approve.true")
        assertEquals(loadedEnrollment, reloadedEnrollment)
    }

    @Test
    fun phoneKeyStoreRegeneratesEnrollmentKeyAfterRotateOrClear() {
        val alias = uniqueAlias("rotate")
        val firstPublicKey = PhoneKeyStore.publicKeyForNewEnrollment(context, alias, preferStrongBox = false)
        val reusedPublicKey = PhoneKeyStore.publicKeyForEnrollment(context, alias)

        assertTrue(Base64.getDecoder().decode(firstPublicKey).size > 32)
        assertEquals(firstPublicKey, reusedPublicKey)

        val rotatedPublicKey = PhoneKeyStore.publicKeyForNewEnrollment(context, alias, preferStrongBox = false)

        assertTrue(Base64.getDecoder().decode(rotatedPublicKey).size > 32)
        assertNotEquals(firstPublicKey, rotatedPublicKey)

        PhoneKeyStore.clearSigningKey(context, alias)
        val afterClearPublicKey = PhoneKeyStore.publicKeyForEnrollment(context, alias)

        assertTrue(Base64.getDecoder().decode(afterClearPublicKey).size > 32)
        assertNotEquals(rotatedPublicKey, afterClearPublicKey)
    }

    @Test
    fun rawEd25519ExtractionAcceptsSoftwareKeyAndRejectsP256Spki() {
        val alias = uniqueAlias("encoding")
        val keyPair = generatePersistedSoftwareKey(alias)
        val rawPublicKey = Ed25519Crypto.rawPublicKey(keyPair.public)

        assertEquals(32, rawPublicKey.size)
        assertArrayEquals(rawPublicKey, Ed25519PublicKeyEncoding.rawFromPublicKey(keyPair.public))
        assertArrayEquals(rawPublicKey, Ed25519PublicKeyEncoding.rawFromEncodedKey(keyPair.public.encoded))

        val p256KeyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        assertRejectsEd25519Extraction {
            Ed25519PublicKeyEncoding.rawFromEncodedKey(p256KeyPair.public.encoded)
        }
    }

    @Test
    fun decisionSigningAndDeviceAuthRequestBodiesVerifyWithEnrolledP256PublicKey() {
        val alias = uniqueAlias("requests")
        val signingKey = PhoneKeyStore.deviceSigningKeyForNewEnrollment(context, alias, preferStrongBox = false)
        val enrollmentPublicKey = signingKey.enrollmentPublicKey
        val spkiPublicKey = Base64.getDecoder().decode(enrollmentPublicKey)
        val directSignature = DecisionSigner.sign(
            signingKey.privateKey,
            "androidtest-request-3",
            Decision.Approve,
            biometricVerified = true
        )

        assertEquals(DeviceKeyType.EcdsaP256, signingKey.keyType)
        assertTrue(spkiPublicKey.size > 32)
        assertEcdsaSignatureVerifies(signingKey.keyPair.public, directSignature, "androidtest-request-3.approve.true")

        withServer { server ->
            val enrollment = enrollment(server)
            server.enqueue(MockResponse().setBody("""{"data":{"ok":true}}"""))

            val enrollResult = await { callback ->
                DeviceAuthClient().enroll(enrollment, enrollmentPublicKey, "fcm-androidtest", signingKey.keyType, callback)
            }

            assertTrue(enrollResult.isSuccess)
            val enrollRequest = server.takeRequest(5, TimeUnit.SECONDS)!!
            val enrollBody = JSONObject(enrollRequest.body.readUtf8())
            assertEquals("/custom/devices/phone-androidtest/enroll", enrollRequest.path)
            assertEquals("token-androidtest", enrollBody.getString("enrollment_token"))
            assertEquals(enrollmentPublicKey, enrollBody.getString("public_key"))
            assertEquals("ecdsa_p256", enrollBody.getString("key_type"))
            assertEquals("fcm-androidtest", enrollBody.getString("push_token"))

            server.enqueue(MockResponse().setBody("""{"data":{"status":"denied"}}"""))
            val decisionResult = await { callback ->
                DeviceAuthClient().decide(
                    enrollment,
                    "androidtest-request-4",
                    Decision.Deny,
                    signingKey.privateKey,
                    callback,
                    biometricVerified = false
                )
            }

            assertTrue(decisionResult.isSuccess)
            val decisionRequest = server.takeRequest(5, TimeUnit.SECONDS)!!
            val decisionBody = JSONObject(decisionRequest.body.readUtf8())
            assertEquals("/custom/auth/androidtest-request-4/decision", decisionRequest.path)
            assertEquals("phone-androidtest", decisionBody.getString("device_id"))
            assertEquals("deny", decisionBody.getString("decision"))
            assertEquals(false, decisionBody.getBoolean("biometric_verified"))
            assertEcdsaSignatureVerifies(
                signingKey.keyPair.public,
                decisionBody.getString("signature"),
                "androidtest-request-4.deny.false"
            )
        }
    }

    private fun enrollmentRawPublicKey(alias: String): ByteArray =
        Base64.getDecoder().decode(PhoneKeyStore.publicKeyForEnrollment(context, alias))

    private fun enrollmentPublicKeyBytes(alias: String): ByteArray =
        Base64.getDecoder().decode(PhoneKeyStore.publicKeyForEnrollment(context, alias))

    private fun assertSignatureVerifies(rawPublicKey: ByteArray, privateKey: PrivateKey, message: String) {
        val body = message.toByteArray(Charsets.US_ASCII)
        val signature = Ed25519Crypto.sign(privateKey, body)
        assertTrue(Ed25519Crypto.verifyRawPublicKey(rawPublicKey, body, signature))
    }

    private fun assertRawSignatureVerifies(rawPublicKey: ByteArray, encodedSignature: String, message: String) {
        assertTrue(
            Ed25519Crypto.verifyRawPublicKey(
                rawPublicKey,
                message.toByteArray(Charsets.US_ASCII),
                Base64.getDecoder().decode(encodedSignature)
            )
        )
    }

    private fun assertEcdsaSignatureVerifies(publicKey: java.security.PublicKey, privateKey: PrivateKey, message: String) {
        val body = message.toByteArray(Charsets.US_ASCII)
        val signature = EcdsaP256Crypto.sign(privateKey, body)
        assertTrue(EcdsaP256Crypto.verify(publicKey, body, signature))
    }

    private fun assertEcdsaSignatureVerifies(publicKey: java.security.PublicKey, encodedSignature: String, message: String) {
        assertTrue(
            EcdsaP256Crypto.verify(
                publicKey,
                message.toByteArray(Charsets.US_ASCII),
                Base64.getDecoder().decode(encodedSignature)
            )
        )
    }

    private fun generatePersistedSoftwareKey(alias: String): KeyPair {
        val method = PhoneKeyStore::class.java.getDeclaredMethod(
            "generateSoftwareKeyPair",
            Context::class.java,
            String::class.java
        )
        method.isAccessible = true
        return method.invoke(PhoneKeyStore, context, alias) as KeyPair
    }

    private fun enrollment(server: MockWebServer): Enrollment =
        Enrollment(
            serverUrl = server.url("/").toString().trimEnd('/'),
            deviceId = "phone-androidtest",
            enrollmentToken = "token-androidtest",
            enrollApi = "/custom/devices/{id}/enroll",
            decisionApi = "/custom/auth/{id}/decision"
        )

    private fun withServer(block: (MockWebServer) -> Unit) {
        val server = MockWebServer()
        try {
            block(server)
        } finally {
            runCatching { server.shutdown() }
        }
    }

    private fun await(start: ((Result<String>) -> Unit) -> Unit): Result<String> {
        val latch = CountDownLatch(1)
        var result: Result<String>? = null
        start {
            result = it
            latch.countDown()
        }
        assertTrue("callback timed out", latch.await(5, TimeUnit.SECONDS))
        return result ?: Result.failure(AssertionError("missing callback result"))
    }

    private fun assertRejectsEd25519Extraction(block: () -> Unit) {
        var rejected = false
        try {
            block()
        } catch (expected: IllegalStateException) {
            rejected = true
        }
        assertTrue("expected non-Ed25519 public key encoding to be rejected", rejected)
    }

    private fun uniqueAlias(name: String): String {
        val alias = "pushgate-phone-androidtest-$name-${System.nanoTime()}"
        aliases += alias
        deleteAliasData(alias)
        return alias
    }

    private fun deleteAliasData(alias: String) {
        runCatching {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        }
        softwarePrefs().edit()
            .remove("$alias.private.raw")
            .remove("$alias.public.raw")
            .remove("$alias.private.pkcs8")
            .remove("$alias.public.x509")
            .commit()
    }

    private fun softwarePrefs() =
        context.getSharedPreferences(SOFTWARE_PREFS, Context.MODE_PRIVATE)

    private companion object {
        const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val SOFTWARE_PREFS = "pushgate_phone_ed25519_keys"
    }
}
