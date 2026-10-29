package org.pushgate.phone

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
import java.util.Collections
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object PhoneKeyStore {
    const val DEFAULT_ALIAS = "pushgate-phone-ed25519"
    private const val STAGED_ALIAS_PREFIX = "$DEFAULT_ALIAS.pending."
    private const val ACTIVE_ALIAS_PREF = "active_signing_alias"
    private const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val WRAPPING_KEY_ALIAS = "pushgate-phone-ed25519-wrap"
    private const val SOFTWARE_PREFS = "pushgate_phone_ed25519_keys"
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

    data class StagedDeviceSigningKey(
        val alias: String,
        val signingKey: DeviceSigningKey
    )

    fun deviceSigningKey(context: Context, alias: String? = null): DeviceSigningKey? =
        loadKeyPair(context, alias ?: preferredSigningAlias(context))?.let(DeviceKeyCrypto::signingKey)

    fun privateKey(context: Context, alias: String? = null): PrivateKey? =
        loadKeyPair(context, alias ?: preferredSigningAlias(context))?.private

    internal fun privateKeyOrNull(context: Context, alias: String? = null): PrivateKey? =
        runCatching { privateKey(context, alias) }.getOrNull()

    fun publicKeyForEnrollment(context: Context, alias: String = DEFAULT_ALIAS): String {
        return getOrCreateDeviceSigningKey(context, alias).enrollmentPublicKey
    }

    fun deviceSigningKeyForNewEnrollment(
        context: Context,
        alias: String = DEFAULT_ALIAS,
        preferStrongBox: Boolean = true
    ): DeviceSigningKey =
        DeviceKeyCrypto.signingKey(regenerateSigningKey(context, alias, preferStrongBox))

    fun publicKeyForNewEnrollment(
        context: Context,
        alias: String = DEFAULT_ALIAS,
        preferStrongBox: Boolean = true
    ): String {
        return deviceSigningKeyForNewEnrollment(context, alias, preferStrongBox).enrollmentPublicKey
    }

    fun stageDeviceSigningKeyForEnrollment(
        context: Context,
        preferStrongBox: Boolean = true
    ): StagedDeviceSigningKey {
        val alias = "$DEFAULT_ALIAS.pending.${UUID.randomUUID()}"
        return runCatching {
            StagedDeviceSigningKey(
                alias = alias,
                signingKey = getOrCreateDeviceSigningKey(context, alias, preferStrongBox)
            )
        }.getOrElse { error ->
            signingKeyLifecycle(context, alias).clear()
            throw error
        }
    }

    fun activateStagedSigningKey(context: Context, staged: StagedDeviceSigningKey) {
        aliasTransition(context).activate(staged.alias)
    }

    fun selectStagedSigningKey(context: Context, stagedAlias: String): String =
        aliasTransition(context).select(stagedAlias)

    fun finishStagedSigningKeySelection(context: Context, previousAlias: String) {
        aliasTransition(context).finishSelection(previousAlias)
    }

    fun activeSigningKeyAlias(context: Context): String = activeSigningAlias(context)

    internal fun currentSigningKeyAlias(context: Context): String = preferredSigningAlias(context)

    fun discardStagedSigningKey(context: Context, staged: StagedDeviceSigningKey) {
        aliasTransition(context).discard(staged.alias)
    }

    fun regenerateSigningKey(
        context: Context,
        alias: String = DEFAULT_ALIAS,
        preferStrongBox: Boolean = true
    ): KeyPair {
        return signingKeyLifecycle(context, alias, preferStrongBox).regenerate()
    }

    fun clearSigningKey(context: Context, alias: String? = null) {
        if (alias != null) {
            signingKeyLifecycle(context, alias).clear()
        } else {
            aliasTransition(context).clearActive()
        }
    }

    fun enrollmentSigningKeyAliases(context: Context, pendingAliases: Set<String>): Set<String> =
        persistedPhoneSigningKeyAliases(DEFAULT_ALIAS, activeSigningAlias(context), pendingAliases)

    fun orphanedStagedSigningKeyAliases(context: Context, referencedAliases: Set<String>): Set<String> {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
        val keyStoreAliases = Collections.list(keyStore.aliases()).toSet()
        val softwarePreferenceKeys = prefs(context.applicationContext).all.keys
        return orphanedStagedPhoneSigningKeyAliases(
            discoveredAliases = persistedStagedPhoneSigningKeyAliases(
                stagedAliasPrefix = STAGED_ALIAS_PREFIX,
                keyStoreAliases = keyStoreAliases,
                softwarePreferenceKeys = softwarePreferenceKeys
            ),
            referencedAliases = referencedAliases
        )
    }

    fun clearEnrollmentSigningKeys(context: Context, signingKeyAliases: Set<String>) {
        aliasTransition(context).clearAll(signingKeyAliases)
    }

    private fun activeSigningAlias(context: Context): String = aliasTransition(context).activeAlias()

    private fun preferredSigningAlias(context: Context): String =
        EnrollmentStore.pendingSigningKeyAlias(context) ?: activeSigningAlias(context)

    private fun aliasTransition(context: Context): SigningKeyAliasTransition {
        val appContext = context.applicationContext
        return SigningKeyAliasTransition(
            defaultAlias = DEFAULT_ALIAS,
            readActiveAlias = { prefs(appContext).getString(ACTIVE_ALIAS_PREF, null) },
            writeActiveAlias = { alias ->
                prefs(appContext).edit().run {
                    if (alias == null) remove(ACTIVE_ALIAS_PREF) else putString(ACTIVE_ALIAS_PREF, alias)
                    commit()
                }
            },
            clearAlias = { alias -> signingKeyLifecycle(appContext, alias).clear() }
        )
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
                deleteAndroidKeyStoreAlias(alias, ignoreErrors = false)
                deleteSoftwareKeyPair(appContext, alias)
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

    private fun deleteAndroidKeyStoreAlias(alias: String, ignoreErrors: Boolean = true) {
        val delete = {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        }
        if (ignoreErrors) runCatching(delete) else delete()
    }

    private fun deleteSoftwareKeyPair(context: Context, alias: String) {
        val cleared = prefs(context).edit()
            .remove(privateKeyPref(alias))
            .remove(publicKeyPref(alias))
            .remove(legacyPrivateKeyPref(alias))
            .remove(legacyPublicKeyPref(alias))
            .commit()
        check(cleared) { "Could not clear software signing key" }
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

        val message = "pushgate-phone-ed25519-self-test".toByteArray(Charsets.UTF_8)
        val signature = Ed25519Crypto.sign(private, message)
        val verified = Ed25519Crypto.verifyRawPublicKey(rawPublicKey, message, signature)
        require(verified) { "Ed25519 key self-test failed" }
        return this
    }

    private fun KeyPair.requireUsableEcdsaP256(): KeyPair {
        EcdsaP256Crypto.requireP256PublicKey(public)

        val message = "pushgate-phone-ecdsa-p256-self-test".toByteArray(Charsets.UTF_8)
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

internal fun persistedPhoneSigningKeyAliases(
    defaultAlias: String,
    activeAlias: String,
    pendingAliases: Set<String>
): Set<String> = buildSet {
    add(defaultAlias)
    add(activeAlias)
    addAll(pendingAliases.filter(String::isNotBlank))
}

internal fun persistedStagedPhoneSigningKeyAliases(
    stagedAliasPrefix: String,
    keyStoreAliases: Set<String>,
    softwarePreferenceKeys: Set<String>
): Set<String> {
    val softwareKeySuffixes = setOf(
        ".private.raw",
        ".public.raw",
        ".private.pkcs8",
        ".public.x509"
    )
    return buildSet {
        addAll(keyStoreAliases.filter { it.startsWith(stagedAliasPrefix) })
        softwarePreferenceKeys.forEach { preferenceKey ->
            softwareKeySuffixes.firstOrNull(preferenceKey::endsWith)?.let { suffix ->
                preferenceKey.removeSuffix(suffix)
                    .takeIf { it.startsWith(stagedAliasPrefix) }
                    ?.let(::add)
            }
        }
    }
}

internal fun orphanedStagedPhoneSigningKeyAliases(
    discoveredAliases: Set<String>,
    referencedAliases: Set<String>
): Set<String> = discoveredAliases - referencedAliases
