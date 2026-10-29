package org.pushgate.wear

import java.security.PrivateKey
import java.util.Base64

object WearDecisionSigner {
    fun sign(privateKey: PrivateKey, requestId: String, decision: WearDecision, biometricVerified: Boolean): String {
        return signMessage(privateKey, "$requestId.${decision.wireValue}.$biometricVerified")
    }

    fun signMessage(privateKey: PrivateKey, message: String): String {
        return Base64.getEncoder().encodeToString(DeviceKeyCrypto.sign(privateKey, message.toByteArray(Charsets.UTF_8)))
    }
}
