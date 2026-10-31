package org.pushgate.phone

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

class NotificationDecisionActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) {
            // A recreated approval surface must never launch a second prompt or decision request.
            finish()
            return
        }
        setContent {
            PushGateNotificationDecisionScreen()
        }

        val challenge = AuthNotificationDispatcher.challengeFromIntent(intent)
        val binding = AuthNotificationDispatcher.bindingFromIntent(intent)
        val enrollment = EnrollmentStore.load(this)
        val currentBinding = AuthNotificationDispatcher.currentBinding(this)
        val privateKey = binding?.takeIf { it == currentBinding }?.let {
            PhoneKeyStore.privateKeyOrNull(this, it.signingKeyAlias)
        }
        if (
            intent.action != AuthNotificationDispatcher.ACTION_APPROVE ||
            challenge == null ||
            !challenge.isActionable() ||
            binding == null ||
            enrollment == null ||
            privateKey == null
        ) {
            challenge?.id?.let { AuthNotificationDispatcher(this).cancel(it, binding) }
            finish()
            return
        }

        if (!DecisionClaimStore.tryClaim(this, challenge, binding, Decision.Approve)) {
            finish()
            return
        }

        ApprovalFlow().approve(this, enrollment, challenge, privateKey) {
            runOnUiThread {
                val notifications = AuthNotificationDispatcher(this)
                handleNotificationDecisionResult(
                    result = it,
                    onSuccess = {
                        ChallengeResolutions.settledHere(this, challenge.id, Decision.Approve)
                        notifications.cancel(challenge.id, binding)
                    },
                    onFailure = {
                        DecisionClaimStore.release(this, challenge.id, binding, Decision.Approve)
                        notifications.show(challenge, binding)
                    }
                )
                finish()
            }
        }
    }
}

@Composable
private fun PushGateNotificationDecisionScreen() {
    PushGateTheme {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(28.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = androidx.compose.foundation.layout.Arrangement.Center
            ) {
                Box(
                    modifier = Modifier
                        .size(72.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.18f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Security,
                        contentDescription = "PushGate approval",
                        tint = MaterialTheme.colorScheme.primary
                    )
                }
                Spacer(Modifier.height(20.dp))
                Text(
                    text = "Approving PushGate request",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(18.dp))
                CircularProgressIndicator()
            }
        }
    }
}
