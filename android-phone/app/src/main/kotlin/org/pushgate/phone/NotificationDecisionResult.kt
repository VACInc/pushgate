package org.pushgate.phone

internal fun handleNotificationDecisionResult(
    result: Result<String>,
    onSuccess: () -> Unit,
    onFailure: () -> Unit
) {
    if (result.isSuccess) onSuccess() else onFailure()
}

internal data class ApproveFailure(val message: String, val retryable: Boolean)

/** What to tell the approver after a background approve fails; only a still-live request is retryable. */
internal fun approveFailure(error: Throwable?, stillActionable: Boolean): ApproveFailure {
    val settledStatus = (error as? DecisionResponseException)?.receivedStatus.orEmpty()
    return when {
        settledStatus.isNotBlank() -> ApproveFailure("Not approved: request was already $settledStatus.", retryable = false)
        !stillActionable -> ApproveFailure("Not approved: request expired.", retryable = false)
        else -> ApproveFailure("Approve did not reach the server. Tap Approve to retry.", retryable = true)
    }
}
