package org.pushgate.phone

import android.Manifest
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import java.io.Closeable
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.google.zxing.integration.android.IntentIntegrator
import okhttp3.Call
import java.security.PrivateKey

class MainActivity : ComponentActivity() {
    private val client = DeviceAuthClient()
    private val approvalFlow = ApprovalFlow(client)
    private var tokenSync: FirebaseTokenSync? = null
    private var pushChannel: PhonePushChannel? = null
    private var listenerGeneration = 0L
    private var wearRelay: PhoneWearRelay? = null
    private var enrollment: Enrollment? = null
    private var privateKey: PrivateKey? = null
    private var currentChallenge: AuthChallenge? = null
    private val expiryHandler = Handler(Looper.getMainLooper())
    private var expiryTimer: Runnable? = null
    private var resolutionSubscription: Closeable? = null
    private var decidingChallengeId: String? = null
    private var enrollmentAttemptAlias: String? = null
    private var enrollmentCall: Call? = null

    private var screen by mutableStateOf(PhoneScreen.Enrollment)
    private var enrollmentState by mutableStateOf<Enrollment?>(null)
    private var serverUrl by mutableStateOf("")
    private var enrollmentPayload by mutableStateOf("")
    private var statusMessage by mutableStateOf("")
    private var challengeState by mutableStateOf<AuthChallenge?>(null)
    private var isEnrolling by mutableStateOf(false)
    private var isListening by mutableStateOf(false)
    private var isDeciding by mutableStateOf(false)
    private var decisionFeedback by mutableStateOf<DecisionFeedback?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        requestNotificationPermission()
        PendingDenialScheduler.ensureScheduled(this)

        val keyCleanupFinished = resumeInterruptedEnrollmentClear()
        EnrollmentStore.loadPending(this)?.let(::finalizeAcceptedPendingEnrollment)
        val pendingEnrollment = EnrollmentStore.loadPending(this)
        val storedEnrollment = pendingEnrollment?.enrollment ?: EnrollmentStore.load(this)
        storedEnrollment?.let { stored ->
            enrollment = stored
            enrollmentState = stored
            serverUrl = stored.serverUrl
            screen = PhoneScreen.Home
            status(
                if (pendingEnrollment != null) {
                    "Enrollment recovery is active; do not reuse the enrollment payload"
                } else {
                    "Enrolled device ${stored.deviceId}"
                }
            )
            startListeners(stored, pendingEnrollment?.signingKeyAlias)
        } ?: run {
            screen = PhoneScreen.Enrollment
            status(
                if (keyCleanupFinished) {
                    "Scan, paste, or share enrollment payload to begin"
                } else {
                    "Enrollment is cleared; signing key cleanup will retry when PushGate restarts"
                }
            )
        }

        sharedText(intent)?.let { loadSharedEnrollmentPayload(it, "Loaded shared enrollment payload") }

        setContent {
            PushGatePhoneApp(
                state = PhoneUiState(
                    screen = screen,
                    enrollment = enrollmentState,
                    serverUrl = serverUrl,
                    enrollmentPayload = enrollmentPayload,
                    statusMessage = statusMessage,
                    challenge = challengeState,
                    isEnrolling = isEnrolling,
                    isListening = isListening,
                    isDeciding = isDeciding,
                    decisionFeedback = decisionFeedback
                ),
                onServerUrlChange = { serverUrl = it },
                onEnrollmentPayloadChange = { enrollmentPayload = it },
                onScanQr = ::scanEnrollmentQr,
                onPastePayload = ::pasteEnrollmentPayload,
                onEnroll = ::enrollDevice,
                onStartListening = {
                    enrollment?.let(::startListeners) ?: status("Enroll this phone first")
                },
                onClearEnrollment = ::clearEnrollment,
                onApprove = ::approveCurrentChallenge,
                onDeny = ::denyCurrentChallenge,
                onOpenHome = { screen = PhoneScreen.Home },
                onOpenSettings = { screen = PhoneScreen.Settings },
                onOpenEnrollment = { screen = PhoneScreen.Enrollment }
            )
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        sharedText(intent)?.let { loadSharedEnrollmentPayload(it, "Loaded shared enrollment payload") }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null) {
            result.contents?.let {
                enrollmentPayload = it
                screen = PhoneScreen.Enrollment
                status("Loaded scanned enrollment payload")
            } ?: status("QR scan canceled")
            return
        }
        super.onActivityResult(requestCode, resultCode, data)
    }

    override fun onDestroy() {
        listenerGeneration += 1
        enrollmentCall?.cancel()
        enrollmentCall = null
        pushChannel?.close()
        wearRelay?.close()
        tokenSync?.close()
        resolutionSubscription?.close()
        resolutionSubscription = null
        expiryHandler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    override fun onRestart() {
        super.onRestart()
        enrollment?.let { stored ->
            startListeners(stored, EnrollmentStore.loadPending(this)?.signingKeyAlias)
        }
    }

    private fun scanEnrollmentQr() {
        if (!packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)) {
            status("Camera unavailable; paste or share the enrollment payload")
            return
        }
        IntentIntegrator(this).apply {
            setDesiredBarcodeFormats(listOf(IntentIntegrator.QR_CODE))
            setPrompt("Point the camera at the PushGate enrollment QR")
            setBeepEnabled(false)
            setOrientationLocked(false)
            setCaptureActivity(QrCaptureActivity::class.java)
        }.initiateScan()
    }

    private fun pasteEnrollmentPayload() {
        val clipboard = getSystemService(ClipboardManager::class.java)
        val text = clipboard.primaryClip
            ?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)
            ?.coerceToText(this)
            ?.toString()
            ?.trim()
            .orEmpty()
        if (text.isBlank()) {
            status("Clipboard does not contain an enrollment payload")
            return
        }
        loadSharedEnrollmentPayload(text, "Pasted enrollment payload")
    }

    private fun enrollDevice() {
        if (isEnrolling) return
        if (!resumeInterruptedEnrollmentClear()) {
            status("Signing key cleanup is still pending. Restart PushGate before enrolling again.")
            return
        }
        if (EnrollmentStore.hasPending(this)) {
            status("An uncertain enrollment is already preserved. Do not reuse its payload; clear enrollment before starting another.")
            return
        }
        val activeServerUrl = serverUrl.trim()
        val payload = enrollmentPayload.trim()
        if (activeServerUrl.isBlank() || payload.isBlank()) {
            status("Server URL and enrollment payload are required")
            return
        }

        val nextEnrollment = runCatching { Enrollment.fromQr(activeServerUrl, payload) }
            .getOrElse { error ->
                statusError("That enrollment payload does not look valid.", error)
                return
            }
        val stagedSigningKey = runCatching { PhoneKeyStore.stageDeviceSigningKeyForEnrollment(this) }
            .getOrElse { error ->
                statusError("Could not prepare this phone for approval. Try clearing enrollment and enrolling again.", error)
                return
            }
        val enrolled = nextEnrollment.copy(enrollmentToken = "")
        val previousSigningKeyAlias = PhoneKeyStore.activeSigningKeyAlias(this)
        if (!EnrollmentStore.savePending(this, enrolled, stagedSigningKey.alias, previousSigningKeyAlias)) {
            val recovery = recoverStagedKeyAfterPendingSaveFailure(
                persistCleanupJournal = {
                    EnrollmentStore.beginPendingRollback(this, stagedSigningKey.alias)
                },
                retryCleanup = ::resumeInterruptedEnrollmentClear
            )
            status(
                when (recovery) {
                    StagedKeyRecoveryResult.Cleaned ->
                        "Could not save enrollment recovery state. The server was not contacted; fix phone storage and try again."
                    StagedKeyRecoveryResult.CleanupPending ->
                        "Could not save enrollment recovery state. The server was not contacted; signing key cleanup will retry when PushGate restarts."
                    StagedKeyRecoveryResult.JournalFailed ->
                        "Could not save enrollment recovery or signing key cleanup state. The server was not contacted; fix phone storage before retrying."
                }
            )
            return
        }
        PendingDenialScheduler.clear(this)

        enrollmentAttemptAlias = stagedSigningKey.alias
        isEnrolling = true
        status("Enrolling device ${nextEnrollment.deviceId}")
        runCatching {
            enrollmentCall = client.enroll(
                nextEnrollment,
                stagedSigningKey.signingKey.enrollmentPublicKey,
                keyType = stagedSigningKey.signingKey.keyType
            ) { result ->
                runOnUiThread {
                    if (isDestroyed || !shouldHandleEnrollmentResult(enrollmentAttemptAlias, stagedSigningKey.alias)) {
                        return@runOnUiThread
                    }
                    enrollmentCall = null
                    enrollmentAttemptAlias = null
                    isEnrolling = false
                    result
                        .onSuccess {
                            enrollmentPayload = ""
                            EnrollmentStore.markPendingServerAccepted(this, stagedSigningKey.alias)
                            val pending = EnrollmentStore.loadPending(this)
                            val enrollmentSaved = pending?.takeIf { it.signingKeyAlias == stagedSigningKey.alias }
                                ?.let { finalizeAcceptedPendingEnrollment(it, acceptedInCurrentSession = true) }
                                ?: false
                            enrollment = enrolled
                            enrollmentState = enrolled
                            serverUrl = enrolled.serverUrl
                            screen = PhoneScreen.Home
                            decisionFeedback = null
                            status(
                                if (enrollmentSaved) {
                                    "Enrollment complete"
                                } else {
                                    "Enrollment is active, but storage recovery is still pending. Keep this phone open."
                                }
                            )
                            startListeners(enrolled, stagedSigningKey.alias)
                        }
                        .onFailure { error ->
                            if (shouldPreserveEnrollmentRecovery(error)) {
                                preserveUncertainEnrollment(enrolled, stagedSigningKey, error)
                            } else if (EnrollmentStore.beginPendingRollback(this, stagedSigningKey.alias)) {
                                val cleanupFinished = resumeInterruptedEnrollmentClear()
                                statusError(
                                    if (cleanupFinished) {
                                        "Enrollment was rejected. Check the enrollment payload and try again."
                                    } else {
                                        "Enrollment was rejected. Signing key cleanup will retry when PushGate restarts."
                                    },
                                    error
                                )
                            } else {
                                statusError("Enrollment was rejected, but local recovery cleanup failed. Clear enrollment before retrying.", error)
                            }
                        }
                }
            }
        }.onFailure { error ->
            if (!shouldHandleEnrollmentResult(enrollmentAttemptAlias, stagedSigningKey.alias)) {
                return@onFailure
            }
            enrollmentAttemptAlias = null
            enrollmentCall = null
            isEnrolling = false
            if (EnrollmentStore.beginPendingRollback(this, stagedSigningKey.alias)) {
                val cleanupFinished = resumeInterruptedEnrollmentClear()
                statusError(
                    if (cleanupFinished) {
                        "Enrollment failed before the request was sent. Check the server URL and try again."
                    } else {
                        "Enrollment failed before the request was sent. Signing key cleanup will retry when PushGate restarts."
                    },
                    error
                )
            } else {
                statusError("Enrollment could not start, and local recovery cleanup failed. Clear enrollment before retrying.", error)
            }
        }
    }

    private fun preserveUncertainEnrollment(
        enrolled: Enrollment,
        stagedSigningKey: PhoneKeyStore.StagedDeviceSigningKey,
        error: Throwable
    ) {
        enrollmentPayload = ""
        enrollment = enrolled
        enrollmentState = enrolled
        serverUrl = enrolled.serverUrl
        screen = PhoneScreen.Home
        decisionFeedback = null
        statusError("Enrollment result is uncertain. Recovery state was preserved; do not reuse the enrollment payload.", error)
        startListeners(enrolled, stagedSigningKey.alias)
    }

    private fun startListeners(activeEnrollment: Enrollment, signingKeyAlias: String? = null) {
        listenerGeneration += 1
        val generation = listenerGeneration
        isListening = false
        val key = PhoneKeyStore.privateKeyOrNull(this, signingKeyAlias) ?: run {
            status("Missing signing key; clear enrollment and enroll again")
            return
        }
        privateKey = key
        wearRelay?.close()
        pushChannel?.close()
        tokenSync?.close()
        resolutionSubscription?.close()
        resolutionSubscription = ChallengeResolutions.register { resolution ->
            runOnUiThread {
                if (isDestroyed || generation != listenerGeneration) return@runOnUiThread
                applyResolution(resolution)
            }
        }

        wearRelay = runCatching {
            PhoneWearRelay(this).also { relay ->
                relay.start(
                    activeEnrollment,
                    onStatus = { message -> runOnUiThread { status(message) } },
                    onError = { error -> runOnUiThread { reportOptionalCompanionError(error) } }
                )
            }
        }.getOrElse { error ->
            reportOptionalCompanionError(error)
            null
        }

        pushChannel = runCatching {
            PhonePushChannel(activeEnrollment, key).also { channel ->
                channel.start(
                    onChallenge = { challenge ->
                        runOnUiThread {
                            if (isDestroyed || generation != listenerGeneration) return@runOnUiThread
                            wearRelay?.relayChallenge(challenge)
                            currentChallenge = challenge
                            renderChallenge(challenge)
                            AuthNotificationDispatcher(this).show(challenge)
                        }
                    },
                    onError = { error ->
                        runOnUiThread {
                            if (isDestroyed || generation != listenerGeneration) return@runOnUiThread
                            isListening = false
                            statusError(
                                if (error is PushReconnecting) "Connection lost. Reconnecting automatically."
                                else "Push connection rejected. Check enrollment and server access.", error
                            )
                        }
                    },
                    onReady = {
                        runOnUiThread {
                            if (isDestroyed || generation != listenerGeneration) return@runOnUiThread
                            isListening = true
                            status(
                                if (BuildConfig.FCM_CONFIGURED) "Connected. Listening for push requests"
                                else UnifiedPushRegistration.statusLine(this)
                                    ?: "Connected while app is open. Background push is not configured."
                            )
                        }
                    }
                )
            }
        }.getOrElse { error ->
            statusError("Push listening could not start. Check the server connection and try again.", error)
            null
        }

        tokenSync = runCatching {
            FirebaseTokenSync().also { sync ->
                sync.start(activeEnrollment, key) { result ->
                    result.onFailure { runOnUiThread { reportOptionalPushTokenError(it) } }
                }
            }
        }.getOrElse { error ->
            reportOptionalPushTokenError(error)
            null
        }
        if (!BuildConfig.FCM_CONFIGURED) {
            // Background delivery without Google: register with the UnifiedPush
            // distributor (ntfy app) and hand the endpoint to PushGate.
            runCatching {
                UnifiedPushRegistration.ensureRegistered(this)?.let { message -> status(message) }
                UnifiedPushRegistration.resyncIfNeeded(this)
            }.onFailure(::reportOptionalPushTokenError)
        }
        status("Connecting to PushGate")
    }

    private fun finalizeAcceptedPendingEnrollment(
        pending: EnrollmentStore.PendingEnrollment,
        acceptedInCurrentSession: Boolean = false
    ): Boolean {
        val activeAlias = PhoneKeyStore.activeSigningKeyAlias(this)
        if (!shouldFinalizePendingEnrollment(
                serverAccepted = pending.serverAccepted || acceptedInCurrentSession,
                activeSigningKeyAlias = activeAlias,
                stagedSigningKeyAlias = pending.signingKeyAlias
            )
        ) return false
        if (PhoneKeyStore.privateKeyOrNull(this, pending.signingKeyAlias) == null) return false
        if (activeAlias != pending.signingKeyAlias && activeAlias != pending.previousSigningKeyAlias) return false

        val aliasesToRetire = linkedSetOf(pending.previousSigningKeyAlias)
        if (activeAlias != pending.signingKeyAlias) {
            val selectedPreviousAlias = runCatching {
                PhoneKeyStore.selectStagedSigningKey(this, pending.signingKeyAlias)
            }.getOrNull() ?: return false
            aliasesToRetire += selectedPreviousAlias
        }

        val retired = runCatching {
            aliasesToRetire
                .filter { it != pending.signingKeyAlias }
                .forEach { PhoneKeyStore.finishStagedSigningKeySelection(this, it) }
        }.isSuccess
        if (!retired) return false

        // Retire old keys before removing the pending journal. A process death at any
        // earlier point leaves enough state to safely retry this idempotent sequence.
        return EnrollmentStore.promotePending(this, pending.enrollment)
    }

    private fun resumeInterruptedEnrollmentClear(): Boolean {
        var aliases = EnrollmentStore.pendingKeyCleanupAliases(this)
        if (aliases.isEmpty()) {
            val referencedAliases = EnrollmentStore.pendingSigningKeyAliases(this) +
                PhoneKeyStore.activeSigningKeyAlias(this)
            val orphanedAliases = runCatching {
                PhoneKeyStore.orphanedStagedSigningKeyAliases(this, referencedAliases)
            }.getOrElse { return false }
            if (orphanedAliases.isNotEmpty()) {
                if (!EnrollmentStore.beginOrphanedStagedKeyCleanup(this, orphanedAliases)) return false
                aliases = EnrollmentStore.pendingKeyCleanupAliases(this)
                if (!aliases.containsAll(orphanedAliases)) return false
            }
        }
        if (aliases.isEmpty()) return true
        val keysCleared = runCatching {
            if (EnrollmentStore.keyCleanupClearsActiveSigningKey(this)) {
                PhoneKeyStore.clearEnrollmentSigningKeys(this, aliases)
            } else {
                aliases.forEach { PhoneKeyStore.clearSigningKey(this, it) }
            }
        }.isSuccess
        return keysCleared && EnrollmentStore.finishClear(this)
    }

    private fun clearEnrollment() {
        listenerGeneration += 1
        AuthNotificationDispatcher(this).cancelAll()
        PendingDenialScheduler.clear(this)
        enrollmentCall?.cancel()
        enrollmentCall = null
        val signingKeyAliases = PhoneKeyStore.enrollmentSigningKeyAliases(
            this,
            EnrollmentStore.pendingSigningKeyAliases(this) + EnrollmentStore.pendingKeyCleanupAliases(this)
        )
        if (!EnrollmentStore.beginClear(this, signingKeyAliases)) {
            status("Could not clear enrollment storage; no signing keys were removed. Try again.")
            return
        }
        enrollmentAttemptAlias = null
        isEnrolling = false
        pushChannel?.close()
        wearRelay?.close()
        tokenSync?.close()
        pushChannel = null
        wearRelay = null
        tokenSync = null
        enrollment = null
        enrollmentState = null
        privateKey = null
        currentChallenge = null
        decidingChallengeId = null
        challengeState = null
        decisionFeedback = null
        isListening = false
        isDeciding = false
        val cleanupFinished = resumeInterruptedEnrollmentClear()
        screen = PhoneScreen.Enrollment
        status(
            if (cleanupFinished) {
                "Enrollment cleared"
            } else {
                "Enrollment cleared; signing key cleanup will retry when PushGate restarts"
            }
        )
    }

    private fun renderChallenge(challenge: AuthChallenge) {
        if (!challenge.isActionable()) {
            AuthNotificationDispatcher(this).cancel(challenge.id)
            status("Expired request ignored")
            return
        }
        currentChallenge = challenge
        challengeState = challenge
        decisionFeedback = null
        isDeciding = decidingChallengeId == challenge.id
        status("Push challenge received")
        scheduleLocalExpiry(challenge)
    }

    /** The card must clear by itself when the countdown ends, not wait for a tap on a disabled button. */
    private fun scheduleLocalExpiry(challenge: AuthChallenge) {
        expiryTimer?.let(expiryHandler::removeCallbacks)
        val remaining = challenge.remainingLifetimeMillis() ?: return
        val timer = Runnable {
            if (currentChallenge?.id == challenge.id && !challenge.isActionable()) expireCurrentChallenge(challenge)
        }
        expiryTimer = timer
        expiryHandler.postDelayed(timer, remaining + 250L)
    }

    /** Another surface (notification, watch, other device) or the server settled this request. */
    private fun applyResolution(resolution: ChallengeResolution) {
        AuthNotificationDispatcher(this).cancel(resolution.id)
        PendingDenialScheduler.discard(this, resolution.id)
        wearRelay?.relayResolution(resolution)
        val challenge = currentChallenge ?: return
        if (challenge.id != resolution.id) return
        if (decidingChallengeId == challenge.id) {
            // Our own decision is in flight; finishDecision reports its result.
            return
        }
        expiryTimer?.let(expiryHandler::removeCallbacks)
        currentChallenge = null
        challengeState = null
        isDeciding = false
        decidingChallengeId = null
        decisionFeedback = when (resolution.status) {
            "approved" -> DecisionFeedback(DecisionFeedbackKind.Approved, challenge.username, challenge.pamService, challenge.system)
            "denied" -> DecisionFeedback(DecisionFeedbackKind.Denied, challenge.username, challenge.pamService, challenge.system)
            else -> null
        }
        status(
            when (resolution.status) {
                "approved" -> "Request approved on another device"
                "denied" -> "Request denied on another device"
                "timeout" -> "Request expired"
                else -> "Request ${resolution.status}"
            }
        )
    }

    private fun approveCurrentChallenge() {
        val challenge = currentChallenge ?: return
        if (!challenge.isActionable()) {
            expireCurrentChallenge(challenge)
            return
        }
        val activeEnrollment = enrollment ?: return
        val key = privateKey ?: return
        val binding = AuthNotificationDispatcher.currentBinding(this) ?: return
        if (!DecisionClaimStore.tryClaim(this, challenge, binding, Decision.Approve)) {
            status("A decision for this request is already in progress")
            return
        }
        decidingChallengeId = challenge.id
        isDeciding = true
        status("Approving request")
        approvalFlow.approve(this, activeEnrollment, challenge, key) { result ->
            runOnUiThread { finishDecision(challenge, binding, Decision.Approve, result, "approved") }
        }
    }

    private fun denyCurrentChallenge() {
        val challenge = currentChallenge ?: return
        if (!challenge.isActionable()) {
            expireCurrentChallenge(challenge)
            return
        }
        val activeEnrollment = enrollment ?: return
        val key = privateKey ?: return
        val binding = AuthNotificationDispatcher.currentBinding(this) ?: return
        if (!DecisionClaimStore.tryClaim(this, challenge, binding, Decision.Deny)) {
            status("A decision for this request is already in progress")
            return
        }
        decidingChallengeId = challenge.id
        isDeciding = true
        status("Denying request")
        approvalFlow.deny(activeEnrollment, challenge, key) { result ->
            runOnUiThread { finishDecision(challenge, binding, Decision.Deny, result, "denied") }
        }
    }

    private fun finishDecision(
        challenge: AuthChallenge,
        binding: NotificationEnrollmentBinding,
        decision: Decision,
        result: Result<String>,
        action: String
    ) {
        val isCurrentChallenge = shouldApplyPhoneDecisionResult(currentChallenge?.id, challenge.id)
        if (decidingChallengeId == challenge.id) {
            decidingChallengeId = null
            isDeciding = false
        }
        result
            .onSuccess {
                AuthNotificationDispatcher(this).cancel(challenge.id)
                if (!isCurrentChallenge) return@onSuccess
                currentChallenge = null
                challengeState = null
                decisionFeedback = DecisionFeedback(
                    kind = if (action == "approved") DecisionFeedbackKind.Approved else DecisionFeedbackKind.Denied,
                    username = challenge.username,
                    service = challenge.pamService,
                    system = challenge.system
                )
                status("Request $action")
            }
            .onFailure {
                DecisionClaimStore.release(this, challenge.id, binding, decision)
                if (!isCurrentChallenge) return@onFailure
                if (it is DecisionResponseException && it.receivedStatus.isNotBlank()) {
                    applyResolution(ChallengeResolution(challenge.id, it.receivedStatus))
                } else if (it is SecurityException && !challenge.isActionable()) {
                    expireCurrentChallenge(challenge)
                } else {
                    statusError("Decision failed. Check your connection and try again.", it)
                }
            }
    }

    private fun expireCurrentChallenge(challenge: AuthChallenge) {
        AuthNotificationDispatcher(this).cancel(challenge.id)
        expiryTimer?.let(expiryHandler::removeCallbacks)
        if (currentChallenge?.id == challenge.id) {
            currentChallenge = null
            challengeState = null
            isDeciding = false
            decidingChallengeId = null
            status("Request expired")
        }
    }

    private fun status(message: String) {
        statusMessage = sanitizeStatus(message)
    }

    private fun statusError(message: String, _error: Throwable) {
        status(message)
    }

    private fun reportOptionalCompanionError(_error: Throwable) {
        // The watch relay is a convenience path. Phone approval and direct push still work without it.
    }

    private fun reportOptionalPushTokenError(_error: Throwable) {
        // FCM token sync is optional because websocket listening remains available.
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }

    private fun sharedText(intent: Intent?): String? {
        if (intent?.action != Intent.ACTION_SEND || intent.type != "text/plain") return null
        return intent.getStringExtra(Intent.EXTRA_TEXT)
    }

    private fun loadSharedEnrollmentPayload(payload: String, message: String) {
        enrollmentPayload = payload
        screen = PhoneScreen.Enrollment
        status(message)
    }
}

private fun sanitizeStatus(message: String): String {
    val cleaned = message.trim()
    if (cleaned.isBlank()) return ""
    return if (cleaned.looksTechnical()) "Something went wrong. Try again." else cleaned
}

internal fun shouldApplyPhoneDecisionResult(currentChallengeId: String?, completedChallengeId: String): Boolean =
    currentChallengeId == completedChallengeId

private fun String.looksTechnical(): Boolean {
    val technicalMarkers = listOf(
        "ConnectionResult",
        "API_UNAVAILABLE",
        "Wearable.API",
        "statusCode=",
        "clientMethodKey=",
        "Exception",
        "Throwable",
        "java.",
        "kotlin.",
        "com.google.",
        "\tat ",
        "\n    at "
    )
    return technicalMarkers.any { contains(it) }
}
