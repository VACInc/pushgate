package org.pushgate.phone

import java.security.PrivateKey
import java.util.Base64

object DecisionSigner {
    fun sign(privateKey: PrivateKey, requestId: String, decision: Decision, biometricVerified: Boolean = decision == Decision.Approve): String {
        return signMessage(privateKey, "$requestId.${decision.wireValue}.$biometricVerified")
    }

    fun signMessage(privateKey: PrivateKey, message: String): String {
        val body = message.toByteArray(Charsets.UTF_8)
        return Base64.getEncoder().encodeToString(DeviceKeyCrypto.sign(privateKey, body))
    }
}
