package org.pushgate.phone

internal fun handleNotificationDecisionResult(
    result: Result<String>,
    onSuccess: () -> Unit,
    onFailure: () -> Unit
) {
    if (result.isSuccess) onSuccess() else onFailure()
}
