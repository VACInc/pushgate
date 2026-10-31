package org.pushgate.phone

import android.Manifest
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
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
import androidx.core.content.FileProvider
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
    private var panels by mutableStateOf(PhonePanels())
    /** When the app screen was last left; a blocking stop after this is reported once on return. */
    private var lastLeftAtMillis = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DebugLog.log(this, "screen", "App screen created" + if (savedInstanceState != null) " (restored)" else "")
        lastLeftAtMillis = uiPrefs().getLong(LAST_LEFT_AT, 0L)
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
                    "This phone is enrolled"
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
        openNotificationRequest(intent)

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
                    decisionFeedback = decisionFeedback,
                    panels = panels
                ),
                actions = PhoneUiActions(
                    onServerUrlChange = { serverUrl = it },
                    onEnrollmentPayloadChange = { enrollmentPayload = it },
                    onScanQr = ::scanEnrollmentQr,
                    onPastePayload = ::pasteEnrollmentPayload,
                    onEnroll = ::enrollDevice,
                    onRestartConnection = ::restartConnection,
                    onReenroll = { navigate(PhoneScreen.Enrollment) },
                    onClearEnrollment = ::clearEnrollment,
                    onApprove = ::approveCurrentChallenge,
                    onDeny = ::denyCurrentChallenge,
                    onNavigate = ::navigate,
                    onDebugLoggingChange = ::setDebugLogging,
                    onRetentionChange = ::setLogRetention,
                    onShareLogs = ::shareDebugLog,
                    onOpenNotificationSettings = ::openNotificationSettings,
                    onAllowBackground = ::requestBackgroundUse
                )
            )
        }
        refreshPanels()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        sharedText(intent)?.let { loadSharedEnrollmentPayload(it, "Loaded shared enrollment payload") }
        openNotificationRequest(intent)
    }

    /** Notification body tap: show that request's card for the enrollment that received it. */
    private fun openNotificationRequest(intent: Intent?) {
        if (intent?.action != AuthNotificationDispatcher.ACTION_OPEN) return
        val binding = AuthNotificationDispatcher.bindingFromIntent(intent) ?: return
        if (binding != AuthNotificationDispatcher.currentBinding(this)) return
        val challenge = AuthNotificationDispatcher.challengeFromIntent(intent) ?: return
        screen = PhoneScreen.Home
        if (!phoneCardShouldShow(SettledRequestStore.contains(this, challenge.id), challenge.isActionable())) {
            AuthNotificationDispatcher(this).cancel(challenge.id, binding)
            return
        }
        if (currentChallenge?.id != challenge.id) renderChallenge(challenge)
    }

    override fun onStart() {
        super.onStart()
        DebugLog.log(this, "screen", "App opened")
    }

    override fun onResume() {
        super.onResume()
        dropSettledCard()
        refreshPanels()
    }

    override fun onStop() {
        lastLeftAtMillis = System.currentTimeMillis()
        uiPrefs().edit().putLong(LAST_LEFT_AT, lastLeftAtMillis).apply()
        DebugLog.log(this, "screen", "App moved to the background")
        super.onStop()
    }

    private fun navigate(target: PhoneScreen) {
        screen = target
        refreshPanels()
    }

    /** Re-reads history, logging and background-delivery state for Home, Settings and History. */
    private fun refreshPanels() {
        runCatching {
            val health = DeliveryHealthProbe.read(this)
            panels = PhonePanels(
                history = RequestHistoryStore.list(this),
                debugLoggingEnabled = DebugLog.isEnabled(this),
                retentionDays = DebugLog.retentionDays(this),
                debugLogBytes = DebugLog.storedBytes(this),
                deliveryWarnings = if (enrollment != null) DeliveryWarnings.of(health) else emptyList(),
                batteryUnrestricted = health.batteryUnrestricted,
                lastStopNotice = DeliveryWarnings.lastStopNotice(health.lastStop, lastLeftAtMillis)?.let { notice ->
                    val at = health.lastStop?.timestampMillis ?: 0L
                    "${historyTime(at, System.currentTimeMillis())}: $notice"
                },
                appVersion = "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"
            )
        }.onFailure { DebugLog.error(this, "screen", "Could not refresh settings and history", it) }
    }

    private fun restartConnection() {
        val active = enrollment ?: run {
            status("Enroll this phone first")
            return
        }
        DebugLog.log(this, "connection", "Restart connection tapped")
        startListeners(active, EnrollmentStore.loadPending(this)?.signingKeyAlias)
        refreshPanels()
    }

    private fun setDebugLogging(enabled: Boolean) {
        DebugLog.setEnabled(this, enabled)
        status(if (enabled) "Debug logging is on" else "Debug logging is off and the log was deleted")
        refreshPanels()
    }

    private fun setLogRetention(days: Int) {
        DebugLog.setRetentionDays(this, days)
        status("Debug logs are kept for ${if (days == 1) "1 day" else "$days days"}")
        refreshPanels()
    }

    private fun shareDebugLog() {
        if (!DebugLog.isEnabled(this)) {
            status("Turn on debug logging first")
            return
        }
        runCatching {
            val file = DebugLog.export(this)
            val uri = FileProvider.getUriForFile(this, "$packageName.debuglog", file)
            val send = Intent(Intent.ACTION_SEND)
                .setType("text/plain")
                .putExtra(Intent.EXTRA_SUBJECT, "PushGate debug log")
                .putExtra(Intent.EXTRA_STREAM, uri)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            startActivity(Intent.createChooser(send, "Share PushGate debug log"))
        }.onFailure {
            DebugLog.error(this, "log", "Could not share the debug log", it)
            status("Could not share the debug log")
        }
    }

    private fun openNotificationSettings() {
        runCatching {
            startActivity(
                Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
            )
        }.onFailure { status("Open Android Settings > Apps > PushGate > Notifications") }
    }

    /** Asks Android to exempt PushGate from battery optimization so it is not put to sleep. */
    private fun requestBackgroundUse() {
        DebugLog.log(this, "settings", "Allow background use tapped")
        val direct = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).setData(Uri.parse("package:$packageName"))
        runCatching { startActivity(direct) }
            .recoverCatching { startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }
            .onFailure { status("Open Android Settings > Apps > PushGate > Battery and choose Unrestricted") }
    }

    private fun uiPrefs() = getSharedPreferences(UI_PREFS, MODE_PRIVATE)

    /**
     * The card can outlive its request while the app is in the background: a notification or
     * watch tap settles it elsewhere and the `auth_decided` event may never reach this screen.
     */
    private fun dropSettledCard(): Boolean {
        val challenge = currentChallenge ?: return false
        if (decidingChallengeId == challenge.id) return false
        if (!SettledRequestStore.contains(this, challenge.id)) return false
        expiryTimer?.let(expiryHandler::removeCallbacks)
        currentChallenge = null
        challengeState = null
        isDeciding = false
        decidingChallengeId = null
        status("Request already decided")
        return true
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
        DebugLog.log(this, "screen", "App screen closed")
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
        status("Enrolling this phone")
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
        DebugLog.log(this, "connection", "Starting request connection")
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
                            // A late copy (pending replay, reconnect) of a request already settled here.
                            if (SettledRequestStore.contains(this, challenge.id)) return@runOnUiThread
                            DebugLog.log(this, "connection", "Request received over the live connection: ${safeDisplayText(challenge.system)} (request ${challenge.id.take(8)}…)")
                            wearRelay?.relayChallenge(challenge)
                            currentChallenge = challenge
                            renderChallenge(challenge)
                            AuthNotificationDispatcher(this).showDelivered(challenge)
                            refreshPanels()
                        }
                    },
                    onError = { error ->
                        runOnUiThread {
                            if (isDestroyed || generation != listenerGeneration) return@runOnUiThread
                            isListening = false
                            DebugLog.error(this, "connection", "Live connection problem", error)
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
                            DebugLog.log(this, "connection", "Live connection ready")
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
        DebugLog.log(this, "settings", "Clear enrollment confirmed")
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
        refreshPanels()
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
        RequestHistoryStore.resolve(this, resolution.id, resolution.status, decidedHere = resolution.decidedHere)
        DebugLog.log(this, "decision", "Request ${resolution.id.take(8)}… settled: ${resolution.status}" + if (resolution.decidedHere) " (on this phone)" else "")
        refreshPanels()
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
                "approved" -> if (resolution.decidedHere) "Request approved" else "Request approved on another device"
                "denied" -> if (resolution.decidedHere) "Request denied" else "Request denied on another device"
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
        if (dropSettledCard()) return
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
        if (dropSettledCard()) return
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
                SettledRequestStore.mark(this, challenge.id)
                RequestHistoryStore.resolve(this, challenge.id, action, decidedHere = true)
                DebugLog.log(this, "decision", "${decision.wireValue} sent from the app for request ${challenge.id.take(8)}… and accepted")
                refreshPanels()
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
                DebugLog.error(this, "decision", "${decision.wireValue} from the app failed", it)
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

private const val UI_PREFS = "pushgate.ui"
private const val LAST_LEFT_AT = "last_left_at"

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
