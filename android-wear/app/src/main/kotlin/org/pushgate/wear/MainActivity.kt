package org.pushgate.wear

import android.Manifest
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import java.io.Closeable
import android.view.HapticFeedbackConstants
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.google.zxing.integration.android.IntentIntegrator

class MainActivity : ComponentActivity() {
    private val client = WearDeviceClient()
    private val approvalFlow by lazy { WearApprovalFlow() }
    private var challengeInbox: WearChallengeInbox? = null
    private var enrollment: WearEnrollment? = null
    private var currentChallenge: WearChallenge? = null
    private val expiryHandler = Handler(Looper.getMainLooper())
    private var expiryTimer: Runnable? = null
    private var resolutionSubscription: Closeable? = null
    private var decidingBinding: WearDecisionBinding? = null
    private var enrollmentAttemptAlias: String? = null
    private var isForeground = false
    private var signingKeyCleanupRetryAliases: Set<String> = emptySet()
    private var cleanupJournalRecreationMode: SigningKeyCleanupMode? = null
    private var cleanupJournalRecreationExpectedAlias: String? = null

    private var screen by mutableStateOf(WearScreen.Enrollment)
    private var enrollmentState by mutableStateOf<WearEnrollment?>(null)
    private var serverUrl by mutableStateOf("")
    private var enrollmentPayload by mutableStateOf("")
    private var challengePayload by mutableStateOf("")
    private var statusMessage by mutableStateOf("")
    private var challengeState by mutableStateOf<WearChallenge?>(null)
    private var isEnrolling by mutableStateOf(false)
    private var isListening by mutableStateOf(false)
    private var isDeciding by mutableStateOf(false)
    private var decisionFeedback by mutableStateOf<WearDecisionFeedback?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        requestNotificationPermission()

        val startupCleanup = WearEnrollmentStore.recoverSigningKeyCleanup(this)
        startupCleanup?.let { cleanup ->
            rememberSigningKeyCleanup(
                cleanup,
                journalRecreationMode = failedCleanupJournalRecreationMode(
                    cleanup,
                    SigningKeyCleanupMode.DeleteOnly
                ).takeIf { cleanup.remainingAliases.isNotEmpty() }
            )
        }
        if (startupCleanup != null && !startupCleanup.complete) {
            val restored = if (startupCleanup.recordsCleared) WearEnrollmentStore.load(this) else null
            if (restored == null) {
                screen = WearScreen.Enrollment
                status("Signing-key cleanup is incomplete and will retry before enrollment.")
            } else {
                enrollment = restored
                enrollmentState = restored
                serverUrl = restored.serverUrl
                screen = WearScreen.Home
                status("Enrollment restored. Signing-key cleanup will retry.")
                startListening(restored)
            }
        } else {
            val isRecoveringEnrollment = WearEnrollmentStore.hasPending(this)
            WearEnrollmentStore.load(this)?.let { stored ->
                enrollment = stored
                enrollmentState = stored
                serverUrl = stored.serverUrl
                screen = WearScreen.Home
                status(
                    if (isRecoveringEnrollment) {
                        "Recovering interrupted enrollment for ${stored.deviceId}"
                    } else {
                        "Enrolled watch ${stored.deviceId}"
                    }
                )
                startListening(stored)
            } ?: run {
                screen = WearScreen.Enrollment
                status("Scan, paste, or share enrollment payload to begin")
            }
        }

        sharedText(intent)?.let { loadSharedPayload(it, fromExternalShare = true) }

        setContent {
            PushGateWearApp(
                state = WearUiState(
                    screen = screen,
                    enrollment = enrollmentState,
                    serverUrl = serverUrl,
                    enrollmentPayload = enrollmentPayload,
                    challengePayload = challengePayload,
                    statusMessage = statusMessage,
                    challenge = challengeState,
                    isEnrolling = isEnrolling,
                    isListening = isListening,
                    isDeciding = isDeciding,
                    decisionFeedback = decisionFeedback
                ),
                onServerUrlChange = { serverUrl = it },
                onEnrollmentPayloadChange = { enrollmentPayload = it },
                onChallengePayloadChange = { challengePayload = it },
                onScanQr = ::scanEnrollmentQr,
                onPastePayload = ::pasteEnrollmentPayload,
                onEnroll = ::enrollWatch,
                onLoadChallenge = ::loadChallenge,
                onStartListening = {
                    enrollment?.let(::startListening) ?: status("Enroll this watch first")
                },
                onClearEnrollment = ::clearEnrollment,
                onApprove = ::approveCurrentChallenge,
                onDeny = ::denyCurrentChallenge,
                onOpenHome = { screen = WearScreen.Home },
                onOpenSettings = { screen = WearScreen.Settings },
                onOpenEnrollment = { screen = WearScreen.Enrollment }
            )
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        sharedText(intent)?.let { loadSharedPayload(it, fromExternalShare = true) }
    }

    override fun onResume() {
        super.onResume()
        isForeground = true
        clearResolvedCurrentChallenge()
    }

    override fun onPause() {
        isForeground = false
        super.onPause()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null) {
            result.contents?.let {
                enrollmentPayload = it
                screen = WearScreen.Enrollment
                status("Loaded scanned enrollment payload")
            } ?: status("QR scan canceled")
            return
        }
        super.onActivityResult(requestCode, resultCode, data)
    }

    override fun onDestroy() {
        enrollmentAttemptAlias = null
        isEnrolling = false
        challengeInbox?.close()
        resolutionSubscription?.close()
        resolutionSubscription = null
        expiryHandler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private fun scanEnrollmentQr() {
        if (!packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)) {
            status("Camera unavailable; paste or share the enrollment payload")
            return
        }
        IntentIntegrator(this).apply {
            setDesiredBarcodeFormats(listOf(IntentIntegrator.QR_CODE))
            setPrompt("Scan PushGate enrollment QR")
            setBeepEnabled(false)
            setOrientationLocked(false)
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
            status("Clipboard is empty")
            return
        }
        loadSharedPayload(text, fromExternalShare = false)
    }

    private fun enrollWatch() {
        if (!retrySigningKeyCleanupBeforeEnrollment()) {
            status("Signing-key cleanup must finish before enrollment.")
            return
        }
        if (WearEnrollmentStore.hasPending(this)) {
            status("An interrupted enrollment is already preserved. Do not reuse its payload; clear enrollment before starting another.")
            return
        }
        val priorEnrollment = enrollmentBeforeNewAttempt(
            inMemoryEnrollment = enrollment,
            durableEnrollment = runCatching { WearEnrollmentStore.load(this) }.getOrNull()
        )
        if (enrollment == null && priorEnrollment != null) {
            // Deferred rollback may have restored an active record after this
            // Activity was created. Keep its alias in the next activation journal.
            enrollment = priorEnrollment
            enrollmentState = priorEnrollment
        }
        val activeServerUrl = serverUrl.trim()
        val payload = enrollmentPayload.trim()
        if (activeServerUrl.isBlank() || payload.isBlank()) {
            status("Server URL and enrollment payload are required")
            return
        }
        val nextEnrollment = runCatching { WearEnrollment.fromPayload(activeServerUrl, payload) }
            .getOrElse { error ->
                statusError("That enrollment payload does not look valid.", error)
                return
            }
        val stagedKey = runCatching { WearKeyStore.createStagedDeviceSigningKey(this) }
            .getOrElse { error ->
                statusError("Could not prepare this watch for approval. Try clearing enrollment and enrolling again.", error)
                return
            }
        val previousSigningKeyAlias = priorEnrollment?.signingKeyAlias
        val enrolled = nextEnrollment.copy(
            enrollmentToken = "",
            signingKeyAlias = stagedKey.alias
        )
        if (!WearEnrollmentStore.savePending(this, enrolled)) {
            val cleanup = startEnrollmentCleanup(
                signingKeyAliases = setOf(stagedKey.alias),
                persistCleanupJournal = {
                    // A failed SharedPreferences commit may still mutate the
                    // process-local pending fields. Roll those fields back
                    // durably before deleting their referenced key.
                    WearEnrollmentStore.beginPendingRollbackSigningKeyCleanup(
                        context = this,
                        stagedAlias = stagedKey.alias
                    )
                },
                retryCleanup = { WearEnrollmentStore.retrySigningKeyCleanup(this) }
            )
            rememberSigningKeyCleanup(
                cleanup = cleanup,
                journalRecreationMode = failedCleanupJournalRecreationMode(
                    cleanup,
                    SigningKeyCleanupMode.RollbackPending
                ),
                journalRecreationExpectedAlias = stagedKey.alias
            )
            status(
                if (cleanup.complete) {
                    "Could not save enrollment recovery state. The server was not contacted; fix watch storage and try again."
                } else {
                    "Could not save enrollment recovery state. Pending state and its signing key will be rolled back before retrying."
                }
            )
            return
        }

        enrollmentAttemptAlias = stagedKey.alias
        isEnrolling = true
        status("Enrolling watch ${nextEnrollment.deviceId}")
        client.enroll(
            nextEnrollment,
            stagedKey.signingKey.enrollmentPublicKey,
            keyType = stagedKey.signingKey.keyType
        ) { result ->
            runOnUiThread {
                if (!shouldHandleWearEnrollmentResult(enrollmentAttemptAlias, stagedKey.alias)) {
                    return@runOnUiThread
                }
                enrollmentAttemptAlias = null
                isEnrolling = false
                result
                    .onSuccess {
                        val activation = startEnrollmentCleanup(
                            signingKeyAliases = setOfNotNull(
                                previousSigningKeyAlias?.takeIf { it != stagedKey.alias }
                            ),
                            persistCleanupJournal = {
                                WearEnrollmentStore.beginActivationSigningKeyCleanup(
                                    context = this,
                                    previousAlias = previousSigningKeyAlias,
                                    replacementAlias = stagedKey.alias
                                )
                            },
                            retryCleanup = { WearEnrollmentStore.retrySigningKeyCleanup(this) }
                        )
                        rememberSigningKeyCleanup(
                            cleanup = activation,
                            journalRecreationMode = failedCleanupJournalRecreationMode(
                                activation,
                                SigningKeyCleanupMode.ActivatePending
                            ),
                            journalRecreationExpectedAlias = stagedKey.alias
                        )
                        val enrollmentSaved = activation.recordsCleared
                        enrollmentPayload = ""
                        enrollment = enrolled
                        enrollmentState = enrolled
                        serverUrl = enrolled.serverUrl
                        screen = WearScreen.Home
                        clearChallengeStateForEnrollmentChange()
                        WearAuthNotificationDispatcher(this).cancelAll()
                        decisionFeedback = null
                        status(
                            when {
                                !enrollmentSaved ->
                                    "Enrollment is active, but storage failed. Keep this watch open; do not reuse the enrollment payload."
                                activation.complete ->
                                    "Watch enrollment complete"
                                else ->
                                    "Watch enrollment complete. Previous signing-key cleanup will retry."
                            }
                        )
                        startListening(enrolled)
                    }
                    .onFailure { error ->
                        val settlement = settleEnrollmentFailure(
                            error = error,
                            stagedAlias = stagedKey.alias,
                            persistRollbackJournal = { alias ->
                                WearEnrollmentStore.beginPendingRollbackSigningKeyCleanup(this, alias)
                            },
                            retryRollback = { WearEnrollmentStore.retrySigningKeyCleanup(this) }
                        )
                        settlement.cleanup?.let(::rememberSigningKeyCleanup)
                        when (settlement.disposition) {
                            EnrollmentFailureDisposition.RejectedRolledBack -> {
                                // Leave the prior enrollment and its signing key active.
                                statusError("Enrollment was rejected. The previous enrollment was retained.", error)
                            }
                            EnrollmentFailureDisposition.RejectedRollbackFailed -> {
                                // Keep the staged key because the durable pending record still
                                // refers to it, but do not replace the active in-memory enrollment.
                                rememberSigningKeyCleanup(
                                    cleanup = EnrollmentCleanupResult(
                                        recordsCleared = false,
                                        remainingAliases = setOf(stagedKey.alias),
                                        journalPending = false
                                    ),
                                    journalRecreationMode = SigningKeyCleanupMode.RollbackPending,
                                    journalRecreationExpectedAlias = stagedKey.alias
                                )
                                statusError("Enrollment was rejected, but recovery storage could not be rolled back. Keep this watch open.", error)
                            }
                            EnrollmentFailureDisposition.RejectedCleanupPending -> {
                                statusError(
                                    "Enrollment was rejected. The previous enrollment was retained; staged signing-key cleanup will retry.",
                                    error
                                )
                            }
                            EnrollmentFailureDisposition.UncertainPreserved -> {
                                // A transport/server failure can arrive after the server accepted
                                // the key. Preserve the durable record and key for recovery.
                                enrollmentPayload = ""
                                enrollment = enrolled
                                enrollmentState = enrolled
                                serverUrl = enrolled.serverUrl
                                screen = WearScreen.Home
                                clearChallengeStateForEnrollmentChange()
                                WearAuthNotificationDispatcher(this).cancelAll()
                                decisionFeedback = null
                                statusError(
                                    "Enrollment result is uncertain. Recovery state was preserved; do not reuse the enrollment payload.",
                                    error
                                )
                                startListening(enrolled)
                            }
                        }
                    }
            }
        }
    }

    private fun clearEnrollment() {
        enrollmentAttemptAlias = null
        isEnrolling = false
        val signingKeyAliases = WearEnrollmentStore.signingKeyAliases(this)
            .plus(enrollment?.signingKeyAlias)
            .plus(signingKeyCleanupRetryAliases)
            .filterNotNull()
            .toSet()
        val cleanup = startEnrollmentCleanup(
            signingKeyAliases = signingKeyAliases,
            persistCleanupJournal = { aliases ->
                WearEnrollmentStore.beginSigningKeyCleanup(this, aliases)
            },
            retryCleanup = { WearEnrollmentStore.retrySigningKeyCleanup(this) }
        )
        rememberSigningKeyCleanup(
            cleanup,
            journalRecreationMode = SigningKeyCleanupMode.ClearEnrollment
        )
        if (!cleanup.recordsCleared) {
            status("Could not clear enrollment storage. No additional signing keys were removed.")
            return
        }
        WearAuthNotificationDispatcher(this).cancelAll()
        resetClearedEnrollmentState()
        status(
            if (cleanup.complete) {
                "Enrollment cleared"
            } else {
                "Enrollment records cleared, but signing-key cleanup is incomplete and will retry."
            }
        )
    }

    private fun retrySigningKeyCleanupBeforeEnrollment(): Boolean {
        val preservedRecreationMode = cleanupJournalRecreationMode
        val preservedExpectedAlias = cleanupJournalRecreationExpectedAlias
        var cleanup = if (preservedRecreationMode != null) {
            // A failed SharedPreferences commit can update process memory without
            // making the journal durable. Rewrite self-contained modes even when
            // the process-local SharedPreferences view contains a phantom journal.
            startEnrollmentCleanup(
                signingKeyAliases = signingKeyCleanupRetryAliases,
                persistCleanupJournal = { aliases ->
                    when (preservedRecreationMode) {
                        SigningKeyCleanupMode.ClearEnrollment ->
                            WearEnrollmentStore.beginSigningKeyCleanup(this, aliases)
                        SigningKeyCleanupMode.DeleteOnly ->
                            WearEnrollmentStore.replaceDeleteOnlySigningKeyCleanup(this, aliases)
                        SigningKeyCleanupMode.ActivatePending ->
                            preservedExpectedAlias?.let { replacementAlias ->
                                WearEnrollmentStore.replaceActivationSigningKeyCleanup(
                                    context = this,
                                    previousAlias = aliases.singleOrNull(),
                                    replacementAlias = replacementAlias
                                )
                            } ?: false
                        SigningKeyCleanupMode.RollbackPending ->
                            preservedExpectedAlias?.let { stagedAlias ->
                                WearEnrollmentStore.replacePendingRollbackSigningKeyCleanup(
                                    context = this,
                                    stagedAlias = stagedAlias
                                )
                            } ?: false
                    }
                },
                retryCleanup = { WearEnrollmentStore.retrySigningKeyCleanup(this) }
            )
        } else {
            // Always enumerate staged aliases before creating another one. This
            // also retries a prior enumeration failure held in process state.
            WearEnrollmentStore.recoverSigningKeyCleanup(this)
        }
        if (cleanup == null) {
            signingKeyCleanupRetryAliases = emptySet()
            cleanupJournalRecreationMode = null
            cleanupJournalRecreationExpectedAlias = null
            return true
        }
        if (cleanup.complete) {
            // A recreated journal can finish without having run orphan discovery.
            // Discover again before allowing a new staged key to be generated.
            cleanup = WearEnrollmentStore.recoverSigningKeyCleanup(this) ?: cleanup
        }
        rememberSigningKeyCleanup(
            cleanup,
            journalRecreationMode = preservedRecreationMode?.takeIf {
                !cleanup.recordsCleared && !cleanup.journalPending
            } ?: failedCleanupJournalRecreationMode(
                cleanup,
                SigningKeyCleanupMode.DeleteOnly
            ).takeIf { cleanup.remainingAliases.isNotEmpty() },
            journalRecreationExpectedAlias = preservedExpectedAlias
        )
        return cleanup.complete
    }

    private fun rememberSigningKeyCleanup(
        cleanup: EnrollmentCleanupResult,
        journalRecreationMode: SigningKeyCleanupMode? = null,
        journalRecreationExpectedAlias: String? = null
    ) {
        signingKeyCleanupRetryAliases = if (cleanup.complete) {
            emptySet()
        } else {
            cleanup.remainingAliases
        }
        cleanupJournalRecreationMode = if (cleanup.complete) null else journalRecreationMode
        cleanupJournalRecreationExpectedAlias = if (cleanup.complete || journalRecreationMode == null) {
            null
        } else {
            journalRecreationExpectedAlias
        }
    }

    private fun resetClearedEnrollmentState() {
        challengeInbox?.close()
        challengeInbox = null
        enrollment = null
        enrollmentState = null
        clearChallengeStateForEnrollmentChange()
        isListening = false
        screen = WearScreen.Enrollment
    }

    private fun clearChallengeStateForEnrollmentChange() {
        currentChallenge = null
        challengeState = null
        decisionFeedback = null
        isDeciding = false
        decidingBinding = null
    }

    private fun startListening(activeEnrollment: WearEnrollment) {
        challengeInbox?.close()
        challengeInbox = null
        isListening = false
        val key = runCatching {
            WearKeyStore.privateKey(this, activeEnrollment.signingKeyAlias)
        }.getOrNull() ?: run {
            status("Missing watch signing key; clear enrollment and enroll again")
            return
        }
        val inbox = StandaloneWebSocketChallengeInbox(activeEnrollment, key)
        challengeInbox = inbox
        isListening = true
        resolutionSubscription?.close()
        resolutionSubscription = WearResolutions.register { resolution ->
            runOnUiThread {
                if (!shouldHandleWearInboxEvent(challengeInbox, inbox)) return@runOnUiThread
                applyResolution(activeEnrollment, resolution)
            }
        }
        status("Listening for push requests")
        inbox.start(
            onChallenge = { challenge ->
                runOnUiThread {
                    if (!shouldHandleWearInboxEvent(challengeInbox, inbox)) return@runOnUiThread
                    if (!isWearChallengeActionable(challenge)) {
                        WearAuthNotificationDispatcher(this).cancel(challenge.id)
                        status("Expired or invalid push request ignored")
                        return@runOnUiThread
                    }
                    if (WearResolvedChallenges.consume(activeEnrollment.decisionBinding(challenge.id))) {
                        WearAuthNotificationDispatcher(this).cancel(challenge.id)
                        return@runOnUiThread
                    }
                    currentChallenge = challenge
                    renderChallenge(challenge)
                    if (isForeground) {
                        performWatchHaptic(HapticFeedbackConstants.LONG_PRESS)
                    } else {
                        WearAuthNotificationDispatcher(this).show(activeEnrollment, challenge)
                    }
                    status("Push challenge received")
                }
            },
            onError = { error ->
                runOnUiThread {
                    if (!shouldHandleWearInboxEvent(challengeInbox, inbox)) return@runOnUiThread
                    if (error is RecoverableWearChallengeMessageException) {
                        status("Invalid push message ignored; still listening")
                    } else {
                        isListening = false
                        reportListenerError(error)
                    }
                }
            }
        )
    }

    private fun loadChallenge() {
        val payload = challengePayload.trim()
        if (payload.isBlank()) {
            status("Challenge JSON is required")
            return
        }
        runCatching { WearChallenge.fromPayload(payload) }
            .onSuccess { challenge ->
                if (!isWearChallengeActionable(challenge)) {
                    status("That challenge is expired or has an invalid expiration.")
                    return@onSuccess
                }
                currentChallenge = challenge
                renderChallenge(challenge)
                performWatchHaptic(HapticFeedbackConstants.LONG_PRESS)
                status("Challenge loaded")
            }
            .onFailure { statusError("That challenge payload does not look valid.", it) }
    }

    private fun renderChallenge(challenge: WearChallenge) {
        if (decidingBinding?.matches(enrollment, challenge.id) != true) {
            decidingBinding = null
            isDeciding = false
        }
        currentChallenge = challenge
        challengeState = challenge
        decisionFeedback = null
        scheduleLocalExpiry(challenge)
    }

    /** The prompt clears itself when the countdown ends instead of lingering with disabled buttons. */
    private fun scheduleLocalExpiry(challenge: WearChallenge) {
        expiryTimer?.let(expiryHandler::removeCallbacks)
        val remaining = wearChallengeRemainingMillis(challenge) ?: return
        val timer = Runnable {
            if (currentChallenge?.id == challenge.id && !isWearChallengeActionable(challenge)) {
                WearAuthNotificationDispatcher(this).cancel(challenge.id)
                if (decidingBinding?.matches(enrollment, challenge.id) == true) return@Runnable
                currentChallenge = null
                challengeState = null
                status("Request expired")
            }
        }
        expiryTimer = timer
        expiryHandler.postDelayed(timer, remaining + 250L)
    }

    /** Settled on the phone, another device, or the server: drop the prompt and remember the outcome. */
    private fun applyResolution(activeEnrollment: WearEnrollment, resolution: WearResolution) {
        WearAuthNotificationDispatcher(this).cancel(resolution.id)
        WearResolvedChallenges.mark(activeEnrollment.decisionBinding(resolution.id))
        val challenge = currentChallenge ?: return
        if (challenge.id != resolution.id) return
        if (decidingBinding?.matches(enrollment, challenge.id) == true) return
        expiryTimer?.let(expiryHandler::removeCallbacks)
        currentChallenge = null
        challengeState = null
        decisionFeedback = when (resolution.status) {
            "approved" -> WearDecisionFeedback(WearDecisionFeedbackKind.Approved, challenge.username, challenge.pamService, challenge.system)
            "denied" -> WearDecisionFeedback(WearDecisionFeedbackKind.Denied, challenge.username, challenge.pamService, challenge.system)
            else -> null
        }
        status(
            when (resolution.status) {
                "approved" -> "Request approved elsewhere"
                "denied" -> "Request denied elsewhere"
                "timeout" -> "Request expired"
                else -> "Request ${resolution.status}"
            }
        )
    }

    private fun approveCurrentChallenge() {
        if (isDeciding) return
        val activeEnrollment = enrollment ?: run {
            status("Enroll this watch first")
            return
        }
        val challenge = currentChallenge ?: return
        if (!requireActionableCurrentChallenge(challenge)) return
        val binding = activeEnrollment.decisionBinding(challenge.id)
        if (!WearInFlightDecisions.tryAcquire(binding)) {
            status("A decision for this request is already in progress")
            return
        }
        isDeciding = true
        decidingBinding = binding
        performWatchHaptic(HapticFeedbackConstants.VIRTUAL_KEY)
        status("Approving request")
        approvalFlow.approve(this, activeEnrollment, challenge) { result ->
            runOnUiThread { finishDecision(binding, challenge, result) }
        }
    }

    private fun denyCurrentChallenge() {
        if (isDeciding) return
        val activeEnrollment = enrollment ?: run {
            status("Enroll this watch first")
            return
        }
        val challenge = currentChallenge ?: return
        if (!requireActionableCurrentChallenge(challenge)) return
        val binding = activeEnrollment.decisionBinding(challenge.id)
        if (!WearInFlightDecisions.tryAcquire(binding)) {
            status("A decision for this request is already in progress")
            return
        }
        isDeciding = true
        decidingBinding = binding
        performWatchHaptic(HapticFeedbackConstants.VIRTUAL_KEY)
        status("Denying request")
        approvalFlow.denyWithDeviceKey(this, activeEnrollment, challenge) { result ->
            runOnUiThread { finishDecision(binding, challenge, result) }
        }
    }

    private fun finishDecision(
        binding: WearDecisionBinding,
        challenge: WearChallenge,
        result: Result<WearDecisionOutcome>
    ) {
        WearInFlightDecisions.release(binding)
        val isCurrentChallenge = binding.matches(enrollment, currentChallenge?.id)
        if (decidingBinding == binding) {
            decidingBinding = null
            isDeciding = false
        }
        result
            .onSuccess { outcome ->
                if (!outcome.isTerminal) {
                    if (isCurrentChallenge) status("Decision sent; awaiting server confirmation")
                    return@onSuccess
                }
                WearResolvedChallenges.mark(binding)
                if (binding.matches(enrollment, binding.requestId)) {
                    WearAuthNotificationDispatcher(this).cancel(challenge.id)
                }
                if (!isCurrentChallenge) return@onSuccess
                currentChallenge = null
                challengeState = null
                decisionFeedback = when (outcome) {
                    WearDecisionOutcome.Approved -> WearDecisionFeedback(
                        kind = WearDecisionFeedbackKind.Approved,
                        username = challenge.username,
                        service = challenge.pamService,
                        system = challenge.system
                    )
                    WearDecisionOutcome.Denied -> WearDecisionFeedback(
                        kind = WearDecisionFeedbackKind.Denied,
                        username = challenge.username,
                        service = challenge.pamService,
                        system = challenge.system
                    )
                    WearDecisionOutcome.Timeout,
                    WearDecisionOutcome.Pending -> null
                }
                status(
                    when (outcome) {
                        WearDecisionOutcome.Approved -> "Request approved"
                        WearDecisionOutcome.Denied -> "Request denied"
                        WearDecisionOutcome.Timeout -> "Request timed out"
                        WearDecisionOutcome.Pending -> "Decision sent; awaiting server confirmation"
                    }
                )
            }
            .onFailure {
                if (isCurrentChallenge) {
                    statusError("Decision failed. Check your connection and try again.", it)
                }
            }
    }

    private fun status(message: String) {
        statusMessage = sanitizeStatus(message)
    }

    private fun statusError(message: String, _error: Throwable) {
        status(message)
    }

    private fun reportListenerError(error: Throwable) {
        statusError("Push listening was interrupted. Check the server connection and try again.", error)
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

    private fun loadSharedPayload(payload: String, fromExternalShare: Boolean) {
        val allowChallenge = !fromExternalShare || isDebuggable()
        when (classifyWearSharedPayload(payload, allowChallenge)) {
            WearSharedPayloadDisposition.Enrollment -> {
                enrollmentPayload = payload
                screen = WearScreen.Enrollment
                status("Loaded shared enrollment payload")
            }
            WearSharedPayloadDisposition.Challenge -> {
                challengePayload = payload
                status("Loaded shared challenge payload")
            }
            WearSharedPayloadDisposition.Rejected ->
                status("Shared challenge payloads are disabled in release builds")
        }
    }

    private fun isDebuggable(): Boolean =
        applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    private fun clearResolvedCurrentChallenge() {
        val activeEnrollment = enrollment ?: return
        val challenge = currentChallenge ?: return
        val binding = activeEnrollment.decisionBinding(challenge.id)
        if (!WearResolvedChallenges.consume(binding)) return
        WearAuthNotificationDispatcher(this).cancel(challenge.id)
        currentChallenge = null
        challengeState = null
        decisionFeedback = null
        if (decidingBinding == binding) {
            WearInFlightDecisions.release(binding)
            decidingBinding = null
            isDeciding = false
        }
        status("Request resolved")
    }

    private fun requireActionableCurrentChallenge(challenge: WearChallenge): Boolean {
        if (isWearChallengeActionable(challenge)) return true
        WearAuthNotificationDispatcher(this).cancel(challenge.id)
        currentChallenge = null
        challengeState = null
        isDeciding = false
        decidingBinding = null
        status("Request expired")
        return false
    }

    private fun performWatchHaptic(feedback: Int) {
        window.decorView.performHapticFeedback(feedback)
    }
}

internal enum class WearSharedPayloadDisposition {
    Enrollment,
    Challenge,
    Rejected
}

internal fun classifyWearSharedPayload(
    payload: String,
    allowChallenge: Boolean
): WearSharedPayloadDisposition {
    val isEnrollment = runCatching {
        val json = org.json.JSONObject(payload)
        json.optString("device_id").isNotBlank() &&
            json.optString("enrollment_token").isNotBlank()
    }.getOrDefault(false)
    if (isEnrollment) return WearSharedPayloadDisposition.Enrollment
    return if (allowChallenge) {
        WearSharedPayloadDisposition.Challenge
    } else {
        WearSharedPayloadDisposition.Rejected
    }
}

private fun sanitizeStatus(message: String): String {
    val cleaned = message.trim()
    if (cleaned.isBlank()) return ""
    return if (cleaned.looksTechnical()) "Something went wrong. Try again." else cleaned
}

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
