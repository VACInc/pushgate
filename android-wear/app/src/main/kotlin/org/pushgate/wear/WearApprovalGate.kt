package org.pushgate.wear

import android.app.Activity
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import java.util.concurrent.CancellationException

class WearApprovalGate {
    fun requestApproval(activity: Activity, challenge: WearChallenge, callback: (Result<Unit>) -> Unit) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            callback(Result.failure(UnsupportedOperationException("Watch approval requires Wear OS with BiometricPrompt support")))
            return
        }

        var finished = false
        fun finish(result: Result<Unit>) {
            if (!finished) {
                finished = true
                callback(result)
            }
        }

        val prompt = BiometricPrompt.Builder(activity)
            .setTitle("Approve sign-in")
            .setSubtitle("${challenge.username} on ${challenge.system}")
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    setDeviceCredentialAllowed(true)
                } else {
                    setNegativeButton("Cancel", activity.mainExecutor) { _, _ ->
                        finish(Result.failure(CancellationException("Approval canceled")))
                    }
                }
            }
            .build()

        prompt.authenticate(
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    finish(Result.success(Unit))
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    finish(Result.failure(SecurityException(errString.toString())))
                }
            }
        )
    }
}
