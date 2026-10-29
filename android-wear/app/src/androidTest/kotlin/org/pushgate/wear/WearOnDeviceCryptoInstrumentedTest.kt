package org.pushgate.wear

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
class WearOnDeviceCryptoInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val aliases = mutableListOf<String>()

    @After
    fun tearDown() {
        aliases.forEach(::deleteAliasData)
        aliases.clear()
        WearEnrollmentStore.clearEnrollmentRecordsForCleanup(context)
    }

    @Test
    fun wearKeyStoreReturnsP256EnrollmentKeyAndPersists() {
        val alias = uniqueAlias("keystore")
        val firstSigningKey = WearKeyStore.getOrCreateDeviceSigningKey(context, alias, preferStrongBox = false)
        val firstSpkiPublicKey = enrollmentPublicKeyBytes(alias)

        assertEquals(DeviceKeyType.EcdsaP256, firstSigningKey.keyType)
        assertTrue(firstSpkiPublicKey.size > 32)
        assertArrayEquals(EcdsaP256Crypto.spkiPublicKey(firstSigningKey.keyPair.public), firstSpkiPublicKey)
        assertEcdsaSignatureVerifies(firstSigningKey.keyPair.public, firstSigningKey.privateKey, "androidtest-request-1.approve.true")

        val secondEnrollmentSpkiPublicKey = enrollmentPublicKeyBytes(alias)
        val secondSigningKey = WearKeyStore.getOrCreateDeviceSigningKey(context, alias, preferStrongBox = false)

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

        val reloadedKeyPair = WearKeyStore.getOrCreateSigningKey(context, alias, preferStrongBox = false)

        assertArrayEquals(rawPublicKey, Ed25519Crypto.rawPublicKey(reloadedKeyPair.public))
        assertArrayEquals(rawPublicKey, enrollmentRawPublicKey(alias))
        assertSignatureVerifies(rawPublicKey, reloadedKeyPair.private, "androidtest-software-reload.approve.true")
    }

    @Test
    fun persistedEnrollmentAndKeySurviveFreshStoreLoads() {
        val alias = uniqueAlias("persisted")
        val enrollment = WearEnrollment(
            serverUrl = "https://pushgate.example",
            deviceId = "wear-persisted-${System.nanoTime()}",
            enrollmentToken = "unused-after-enrollment",
            enrollApi = "/api/v1/devices/{id}/enroll",
            decisionApi = "/api/v1/auth/requests/{id}/decision",
            signingKeyAlias = alias
        )
        val signingKey = WearKeyStore.deviceSigningKeyForNewEnrollment(context, alias, preferStrongBox = false)
        val enrolledPublicKey = signingKey.enrollmentPublicKey
        val spkiPublicKey = Base64.getDecoder().decode(enrolledPublicKey)
        WearEnrollmentStore.save(context, enrollment)

        val loadedEnrollment = WearEnrollmentStore.load(context)
        val reloadedSigningKey = WearKeyStore.getOrCreateDeviceSigningKey(context, alias, preferStrongBox = false)
        val reloadedEnrollment = WearEnrollmentStore.load(context)
        val signature = WearDecisionSigner.sign(
            reloadedSigningKey.privateKey,
            "androidtest-persisted-request",
            WearDecision.Approve,
            biometricVerified = true
        )

        assertNotNull(loadedEnrollment)
        assertEquals(enrollment.serverUrl, loadedEnrollment!!.serverUrl)
        assertEquals(enrollment.deviceId, loadedEnrollment.deviceId)
        assertEquals(enrollment.decisionApi, loadedEnrollment.decisionApi)
        assertEquals(alias, loadedEnrollment.signingKeyAlias)
        assertEquals("", loadedEnrollment.enrollmentToken)
        assertEquals(DeviceKeyType.EcdsaP256, reloadedSigningKey.keyType)
        assertTrue(spkiPublicKey.size > 32)
        assertArrayEquals(spkiPublicKey, EcdsaP256Crypto.spkiPublicKey(reloadedSigningKey.keyPair.public))
        assertArrayEquals(spkiPublicKey, enrollmentPublicKeyBytes(alias))
        assertEcdsaSignatureVerifies(reloadedSigningKey.keyPair.public, signature, "androidtest-persisted-request.approve.true")
        assertEquals(loadedEnrollment, reloadedEnrollment)
    }

    @Test
    fun wearKeyStoreRegeneratesEnrollmentKeyAfterRotateOrClear() {
        val alias = uniqueAlias("rotate")
        val firstPublicKey = WearKeyStore.publicKeyForNewEnrollment(context, alias, preferStrongBox = false)
        val reusedPublicKey = WearKeyStore.publicKeyForEnrollment(context, alias)

        assertTrue(Base64.getDecoder().decode(firstPublicKey).size > 32)
        assertEquals(firstPublicKey, reusedPublicKey)

        val rotatedPublicKey = WearKeyStore.publicKeyForNewEnrollment(context, alias, preferStrongBox = false)

        assertTrue(Base64.getDecoder().decode(rotatedPublicKey).size > 32)
        assertNotEquals(firstPublicKey, rotatedPublicKey)

        assertTrue(WearKeyStore.clearSigningKey(context, alias))
        val afterClearPublicKey = WearKeyStore.publicKeyForEnrollment(context, alias)

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
    fun decisionSigningAndWearRequestBodiesVerifyWithEnrolledP256PublicKey() {
        val alias = uniqueAlias("requests")
        val signingKey = WearKeyStore.deviceSigningKeyForNewEnrollment(context, alias, preferStrongBox = false)
        val enrollmentPublicKey = signingKey.enrollmentPublicKey
        val spkiPublicKey = Base64.getDecoder().decode(enrollmentPublicKey)
        val directSignature = WearDecisionSigner.sign(
            signingKey.privateKey,
            "androidtest-request-3",
            WearDecision.Approve,
            biometricVerified = true
        )

        assertEquals(DeviceKeyType.EcdsaP256, signingKey.keyType)
        assertTrue(spkiPublicKey.size > 32)
        assertEcdsaSignatureVerifies(signingKey.keyPair.public, directSignature, "androidtest-request-3.approve.true")

        withServer { server ->
            val enrollment = enrollment(server)
            server.enqueue(MockResponse().setBody("""{"data":{"ok":true}}"""))

            val enrollResult = await { callback ->
                WearDeviceClient().enroll(enrollment, enrollmentPublicKey, signingKey.keyType, callback)
            }

            assertTrue(enrollResult.isSuccess)
            val enrollRequest = server.takeRequest(5, TimeUnit.SECONDS)!!
            val enrollBody = JSONObject(enrollRequest.body.readUtf8())
            assertEquals("/custom/devices/wear-androidtest/enroll", enrollRequest.path)
            assertEquals("token-androidtest", enrollBody.getString("enrollment_token"))
            assertEquals(enrollmentPublicKey, enrollBody.getString("public_key"))
            assertEquals("ecdsa_p256", enrollBody.getString("key_type"))

            val relayBody = JSONObject(
                WearRelayProtocol.decisionPayload(
                    enrollment,
                    challenge("androidtest-request-4"),
                    WearDecision.Approve,
                    signingKey.privateKey,
                    biometricVerified = true
                )
            )
            assertEquals("androidtest-request-4", relayBody.getString("request_id"))
            assertEquals("wear-androidtest", relayBody.getString("device_id"))
            assertEquals("approve", relayBody.getString("decision"))
            assertEquals(true, relayBody.getBoolean("biometric_verified"))
            assertEcdsaSignatureVerifies(
                signingKey.keyPair.public,
                relayBody.getString("signature"),
                "androidtest-request-4.approve.true"
            )

            server.enqueue(MockResponse().setBody("""{"data":{"status":"denied"}}"""))
            val decisionResult = await { callback ->
                DirectWearDecisionSender().send(
                    enrollment,
                    challenge("androidtest-request-5"),
                    WearDecision.Deny,
                    signingKey.privateKey,
                    callback,
                    biometricVerified = false
                )
            }

            assertTrue(decisionResult.isSuccess)
            assertEquals(WearDecisionOutcome.Denied, decisionResult.getOrThrow())
            val decisionRequest = server.takeRequest(5, TimeUnit.SECONDS)!!
            val decisionBody = JSONObject(decisionRequest.body.readUtf8())
            assertEquals("/custom/auth/androidtest-request-5/decision", decisionRequest.path)
            assertEquals("wear-androidtest", decisionBody.getString("device_id"))
            assertEquals("deny", decisionBody.getString("decision"))
            assertEquals(false, decisionBody.getBoolean("biometric_verified"))
            assertEcdsaSignatureVerifies(
                signingKey.keyPair.public,
                decisionBody.getString("signature"),
                "androidtest-request-5.deny.false"
            )
        }
    }

    private fun enrollmentRawPublicKey(alias: String): ByteArray =
        Base64.getDecoder().decode(WearKeyStore.publicKeyForEnrollment(context, alias))

    private fun enrollmentPublicKeyBytes(alias: String): ByteArray =
        Base64.getDecoder().decode(WearKeyStore.publicKeyForEnrollment(context, alias))

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
        val method = WearKeyStore::class.java.getDeclaredMethod(
            "generateSoftwareKeyPair",
            Context::class.java,
            String::class.java
        )
        method.isAccessible = true
        return method.invoke(WearKeyStore, context, alias) as KeyPair
    }

    private fun enrollment(server: MockWebServer): WearEnrollment =
        WearEnrollment(
            serverUrl = server.url("/").toString().trimEnd('/'),
            deviceId = "wear-androidtest",
            enrollmentToken = "token-androidtest",
            enrollApi = "/custom/devices/{id}/enroll",
            decisionApi = "/custom/auth/{id}/decision"
        )

    private fun challenge(id: String): WearChallenge =
        WearChallenge(
            id = id,
            username = "androidtest",
            system = "device-runtime",
            pamService = "login",
            sourceIp = "127.0.0.1",
            geolocation = "Android Emulator",
            requestedAt = "2026-07-06T12:00:00Z",
            expiresAt = "2026-07-06T12:01:00Z",
            requireBiometric = true
        )

    private fun withServer(block: (MockWebServer) -> Unit) {
        val server = MockWebServer()
        try {
            block(server)
        } finally {
            runCatching { server.shutdown() }
        }
    }

    private fun <T> await(start: ((Result<T>) -> Unit) -> Unit): Result<T> {
        val latch = CountDownLatch(1)
        var result: Result<T>? = null
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
        val alias = "pushgate-wear-androidtest-$name-${System.nanoTime()}"
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
        const val SOFTWARE_PREFS = "pushgate_wear_ed25519_keys"
    }
}
