package org.pushgate.wear

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object WearKeyStore {
    const val DEFAULT_ALIAS = "pushgate-wear-ed25519"
    internal const val STAGED_ALIAS_PREFIX = "$DEFAULT_ALIAS.pending."
    private const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val WRAPPING_KEY_ALIAS = "pushgate-wear-ed25519-wrap"
    private const val SOFTWARE_PREFS = "pushgate_wear_ed25519_keys"
    private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128

    fun getOrCreateSigningKey(
        context: Context,
        alias: String = DEFAULT_ALIAS,
        preferStrongBox: Boolean = true
    ): KeyPair {
        return signingKeyLifecycle(context, alias, preferStrongBox).getOrCreate()
    }

    fun getOrCreateDeviceSigningKey(
        context: Context,
        alias: String = DEFAULT_ALIAS,
        preferStrongBox: Boolean = true
    ): DeviceSigningKey =
        DeviceKeyCrypto.signingKey(getOrCreateSigningKey(context, alias, preferStrongBox))

    fun deviceSigningKey(context: Context, alias: String = DEFAULT_ALIAS): DeviceSigningKey? =
        loadKeyPair(context, alias)?.let(DeviceKeyCrypto::signingKey)

    fun privateKey(context: Context, alias: String = DEFAULT_ALIAS): PrivateKey? =
        loadKeyPair(context, alias)?.private

    fun publicKeyForEnrollment(context: Context, alias: String = DEFAULT_ALIAS): String {
        return getOrCreateDeviceSigningKey(context, alias).enrollmentPublicKey
    }

    fun deviceSigningKeyForNewEnrollment(
        context: Context,
        alias: String = DEFAULT_ALIAS,
        preferStrongBox: Boolean = true
    ): DeviceSigningKey =
        DeviceKeyCrypto.signingKey(regenerateSigningKey(context, alias, preferStrongBox))

    fun createStagedDeviceSigningKey(
        context: Context,
        preferStrongBox: Boolean = true
    ): StagedDeviceSigningKey {
        val alias = "$STAGED_ALIAS_PREFIX${UUID.randomUUID()}"
        return StagedDeviceSigningKey(
            alias = alias,
            signingKey = getOrCreateDeviceSigningKey(context, alias, preferStrongBox)
        )
    }

    /**
     * Enumerates every app-generated staged key, including incomplete software
     * key pairs. Enrollment recovery excludes aliases referenced by durable
     * active or pending records before journaling any deletion.
     */
    internal fun stagedSigningKeyAliases(context: Context): Set<String> {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
        val androidAliases = buildSet {
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) add(aliases.nextElement())
        }
        val softwarePreferenceKeys = prefs(context.applicationContext).all.keys
        return discoverGeneratedStagedSigningKeyAliases(
            androidAliases = androidAliases,
            softwarePreferenceKeys = softwarePreferenceKeys
        )
    }

    fun publicKeyForNewEnrollment(
        context: Context,
        alias: String = DEFAULT_ALIAS,
        preferStrongBox: Boolean = true
    ): String {
        return deviceSigningKeyForNewEnrollment(context, alias, preferStrongBox).enrollmentPublicKey
    }

    fun regenerateSigningKey(
        context: Context,
        alias: String = DEFAULT_ALIAS,
        preferStrongBox: Boolean = true
    ): KeyPair {
        return signingKeyLifecycle(context, alias, preferStrongBox).regenerate()
    }

    fun clearSigningKey(context: Context, alias: String = DEFAULT_ALIAS): Boolean {
        val appContext = context.applicationContext
        val androidKeyDeleted = deleteAndroidKeyStoreAlias(alias)
        val softwareKeyDeleted = deleteSoftwareKeyPair(appContext, alias)
        return androidKeyDeleted && softwareKeyDeleted
    }

    private fun signingKeyLifecycle(
        context: Context,
        alias: String,
        preferStrongBox: Boolean = true
    ): SigningKeyLifecycle {
        val appContext = context.applicationContext
        return SigningKeyLifecycle(
            load = { loadKeyPair(appContext, alias) },
            generate = {
                tryGenerateAndroidKeyStoreKeyPair(alias, preferStrongBox)
                    ?: generateSoftwareKeyPair(appContext, alias)
            },
            clearExisting = {
                check(clearSigningKey(appContext, alias)) {
                    "Could not clear existing signing key"
                }
            }
        )
    }

    private fun loadKeyPair(context: Context, alias: String): KeyPair? {
        loadSoftwareKeyPair(context.applicationContext, alias)?.let { return it }
        val keyPair = loadAndroidKeyStoreKeyPair(alias) ?: return null
        if (keyPair.isUsableEcdsaP256()) return keyPair

        deleteAndroidKeyStoreAlias(alias)
        return null
    }

    private fun tryGenerateAndroidKeyStoreKeyPair(alias: String, preferStrongBox: Boolean): KeyPair? {
        val attempts = if (preferStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            listOf(true, false)
        } else {
            listOf(false)
        }

        for (strongBox in attempts) {
            val keyPair = runCatching {
                generateAndroidKeyStoreKeyPair(alias, strongBox)
            }.getOrNull()
            if (keyPair != null && keyPair.isUsableEcdsaP256()) return keyPair
            deleteAndroidKeyStoreAlias(alias)
        }
        return null
    }

    private fun generateAndroidKeyStoreKeyPair(alias: String, strongBox: Boolean): KeyPair {
        val specBuilder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec(EcdsaP256Crypto.CURVE_NAME))
            .setDigests(KeyProperties.DIGEST_SHA256)
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            specBuilder.setIsStrongBoxBacked(true)
        }

        return KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE_PROVIDER).run {
            initialize(specBuilder.build())
            generateKeyPair()
        }
    }

    private fun loadAndroidKeyStoreKeyPair(alias: String): KeyPair? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: return null
        val publicKey = keyStore.getCertificate(alias)?.publicKey ?: return null
        return KeyPair(publicKey, privateKey)
    }

    private fun deleteAndroidKeyStoreAlias(alias: String): Boolean =
        runCatching {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
            !keyStore.containsAlias(alias)
        }.getOrDefault(false)

    private fun deleteSoftwareKeyPair(context: Context, alias: String): Boolean {
        val prefs = prefs(context)
        val committed = prefs.edit()
            .remove(privateKeyPref(alias))
            .remove(publicKeyPref(alias))
            .remove(legacyPrivateKeyPref(alias))
            .remove(legacyPublicKeyPref(alias))
            .commit()
        if (!committed) return false
        return listOf(
            privateKeyPref(alias),
            publicKeyPref(alias),
            legacyPrivateKeyPref(alias),
            legacyPublicKeyPref(alias)
        ).none(prefs::contains)
    }

    private fun generateSoftwareKeyPair(context: Context, alias: String): KeyPair {
        val keyPair = Ed25519Crypto.generateSoftwareKeyPair().requireUsableEd25519()
        saveSoftwareKeyPair(context, alias, keyPair)

        return loadSoftwareKeyPair(context, alias) ?: keyPair
    }

    private fun loadSoftwareKeyPair(context: Context, alias: String): KeyPair? {
        loadStoredSoftwareKeyPair(context, privateKeyPref(alias), publicKeyPref(alias))?.let { return it }

        return loadStoredSoftwareKeyPair(context, legacyPrivateKeyPref(alias), legacyPublicKeyPref(alias))
            ?.also { saveSoftwareKeyPair(context, alias, it) }
    }

    private fun loadStoredSoftwareKeyPair(context: Context, privatePref: String, publicPref: String): KeyPair? {
        val prefs = prefs(context)
        val privateValue = prefs.getString(privatePref, null)
        val publicValue = prefs.getString(publicPref, null)
        if (privateValue == null && publicValue == null) return null
        require(privateValue != null && publicValue != null) { "Stored Ed25519 key is incomplete" }

        return runCatching {
            val privateKey = Ed25519Crypto.privateKeyFromEncoded(decrypt(privateValue))
            val publicKey = Ed25519Crypto.publicKeyFromEncoded(decrypt(publicValue))
            KeyPair(publicKey, privateKey).requireUsableEd25519()
        }.getOrElse { throw IllegalStateException("Stored Ed25519 key cannot be loaded", it) }
    }

    private fun saveSoftwareKeyPair(context: Context, alias: String, keyPair: KeyPair) {
        val privateEncoded = Ed25519Crypto.rawPrivateKey(keyPair.private)
        val publicEncoded = Ed25519Crypto.rawPublicKey(keyPair.public)
        val saved = prefs(context).edit()
            .putString(privateKeyPref(alias), encrypt(privateEncoded))
            .putString(publicKeyPref(alias), encrypt(publicEncoded))
            .commit()
        if (!saved) throw IllegalStateException("Could not persist software Ed25519 key")
    }

    private fun KeyPair.isUsableEd25519(): Boolean =
        runCatching { requireUsableEd25519() }.isSuccess

    private fun KeyPair.isUsableEcdsaP256(): Boolean =
        runCatching { requireUsableEcdsaP256() }.isSuccess

    private fun KeyPair.requireUsableEd25519(): KeyPair {
        val rawPublicKey = Ed25519Crypto.rawPublicKey(public)

        val message = "pushgate-wear-ed25519-self-test".toByteArray(Charsets.UTF_8)
        val signature = Ed25519Crypto.sign(private, message)
        val verified = Ed25519Crypto.verifyRawPublicKey(rawPublicKey, message, signature)
        require(verified) { "Ed25519 key self-test failed" }
        return this
    }

    private fun KeyPair.requireUsableEcdsaP256(): KeyPair {
        EcdsaP256Crypto.requireP256PublicKey(public)

        val message = "pushgate-wear-ecdsa-p256-self-test".toByteArray(Charsets.UTF_8)
        val signature = EcdsaP256Crypto.sign(private, message)
        val verified = EcdsaP256Crypto.verify(public, message, signature)
        require(verified) { "ECDSA P-256 key self-test failed" }
        return this
    }

    private fun encryptionKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
        (keyStore.getKey(WRAPPING_KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val spec = KeyGenParameterSpec.Builder(
            WRAPPING_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUnlockedDeviceRequired(true)
            .build()

        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE_PROVIDER).run {
            init(spec)
            generateKey()
        }
    }

    private fun encrypt(plainText: ByteArray): String {
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, encryptionKey())
        }
        return "${plainTextBase64(cipher.iv)}:${plainTextBase64(cipher.doFinal(plainText))}"
    }

    private fun decrypt(value: String): ByteArray {
        val parts = value.split(":", limit = 2)
        require(parts.size == 2) { "Stored Ed25519 key has invalid encryption envelope" }
        val iv = Base64.decode(parts[0], Base64.NO_WRAP)
        val cipherText = Base64.decode(parts[1], Base64.NO_WRAP)
        return Cipher.getInstance(AES_GCM_TRANSFORMATION).run {
            init(Cipher.DECRYPT_MODE, encryptionKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
            doFinal(cipherText)
        }
    }

    private fun plainTextBase64(value: ByteArray): String =
        Base64.encodeToString(value, Base64.NO_WRAP)

    private fun prefs(context: Context) =
        context.getSharedPreferences(SOFTWARE_PREFS, Context.MODE_PRIVATE)

    private fun privateKeyPref(alias: String) = "$alias.private.raw"

    private fun publicKeyPref(alias: String) = "$alias.public.raw"

    private fun legacyPrivateKeyPref(alias: String) = "$alias.private.pkcs8"

    private fun legacyPublicKeyPref(alias: String) = "$alias.public.x509"
}

private val SOFTWARE_SIGNING_KEY_SUFFIXES = listOf(
    ".private.raw",
    ".public.raw",
    ".private.pkcs8",
    ".public.x509"
)

internal fun discoverGeneratedStagedSigningKeyAliases(
    androidAliases: Set<String>,
    softwarePreferenceKeys: Set<String>
): Set<String> = buildSet {
    androidAliases.filterTo(this) { it.isGeneratedStagedSigningKeyAlias() }
    softwarePreferenceKeys.forEach { preferenceKey ->
        SOFTWARE_SIGNING_KEY_SUFFIXES.firstOrNull(preferenceKey::endsWith)
            ?.let { suffix -> preferenceKey.removeSuffix(suffix) }
            ?.takeIf(String::isGeneratedStagedSigningKeyAlias)
            ?.let(::add)
    }
}

private fun String.isGeneratedStagedSigningKeyAlias(): Boolean {
    if (!startsWith(WearKeyStore.STAGED_ALIAS_PREFIX)) return false
    val uniqueId = removePrefix(WearKeyStore.STAGED_ALIAS_PREFIX)
    return runCatching { UUID.fromString(uniqueId).toString() == uniqueId.lowercase() }
        .getOrDefault(false)
}
