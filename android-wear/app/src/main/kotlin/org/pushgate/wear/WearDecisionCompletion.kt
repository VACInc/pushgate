package org.pushgate.wear

internal fun handleWearNotificationDecisionResult(
    result: Result<WearDecisionOutcome>,
    onTerminal: (WearDecisionOutcome) -> Unit,
    onRetained: () -> Unit
) {
    val outcome = result.getOrNull()
    if (outcome?.isTerminal == true) onTerminal(outcome) else onRetained()
}

internal data class WearDecisionBinding(
    val serverUrl: String,
    val deviceId: String,
    val signingKeyAlias: String,
    val requestId: String
)

internal fun WearEnrollment.decisionBinding(requestId: String): WearDecisionBinding =
    WearDecisionBinding(serverUrl, deviceId, signingKeyAlias, requestId)

internal fun WearDecisionBinding.matches(
    enrollment: WearEnrollment?,
    requestId: String?
): Boolean = enrollment != null &&
    serverUrl == enrollment.serverUrl &&
    deviceId == enrollment.deviceId &&
    signingKeyAlias == enrollment.signingKeyAlias &&
    this.requestId == requestId

internal fun shouldHandleWearInboxEvent(
    activeInbox: WearChallengeInbox?,
    eventInbox: WearChallengeInbox
): Boolean = activeInbox === eventInbox

internal object WearInFlightDecisions {
    private val bindings = mutableSetOf<WearDecisionBinding>()

    @Synchronized
    fun tryAcquire(binding: WearDecisionBinding): Boolean = bindings.add(binding)

    @Synchronized
    fun release(binding: WearDecisionBinding) {
        bindings.remove(binding)
    }
}

internal object WearResolvedChallenges {
    private const val MAX_REMEMBERED = 64
    private val bindings = LinkedHashSet<WearDecisionBinding>()

    @Synchronized
    fun mark(binding: WearDecisionBinding) {
        bindings.remove(binding)
        bindings.add(binding)
        while (bindings.size > MAX_REMEMBERED) {
            bindings.remove(bindings.first())
        }
    }

    @Synchronized
    fun consume(binding: WearDecisionBinding): Boolean = bindings.remove(binding)
}
