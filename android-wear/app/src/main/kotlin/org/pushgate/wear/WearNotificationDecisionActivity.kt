package org.pushgate.wear

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.wear.compose.material.CircularProgressIndicator
import androidx.wear.compose.material.Icon
import androidx.wear.compose.material.MaterialTheme
import androidx.wear.compose.material.Scaffold
import androidx.wear.compose.material.Text
import androidx.wear.compose.material.TimeText
import androidx.wear.compose.material.Vignette
import androidx.wear.compose.material.VignettePosition

class WearNotificationDecisionActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            PushGateWearNotificationDecisionScreen()
        }

        val challenge = WearAuthNotificationDispatcher.challengeFromIntent(intent)
        val enrollment = WearEnrollmentStore.load(this)
        if (challenge != null && !isWearChallengeActionable(challenge)) {
            WearAuthNotificationDispatcher(this).cancel(challenge.id)
            finish()
            return
        }
        if (
            intent.action != WearAuthNotificationDispatcher.ACTION_APPROVE ||
            challenge == null ||
            enrollment == null ||
            !WearAuthNotificationDispatcher.matchesEnrollment(intent, enrollment)
        ) {
            finish()
            return
        }
        val binding = enrollment.decisionBinding(challenge.id)
        if (!WearInFlightDecisions.tryAcquire(binding)) {
            finish()
            return
        }

        WearApprovalFlow().approve(this, enrollment, challenge) { result ->
            runOnUiThread {
                try {
                    handleWearNotificationDecisionResult(
                        result,
                        onTerminal = {
                            val currentEnrollment = runCatching {
                                WearEnrollmentStore.load(this)
                            }.getOrNull()
                            if (binding.matches(currentEnrollment, challenge.id)) {
                                WearResolvedChallenges.mark(binding)
                                WearAuthNotificationDispatcher(this).cancel(challenge.id)
                            }
                        },
                        onRetained = {}
                    )
                } finally {
                    WearInFlightDecisions.release(binding)
                    finish()
                }
            }
        }
    }
}

@androidx.compose.runtime.Composable
private fun PushGateWearNotificationDecisionScreen() {
    PushGateWearTheme {
        Scaffold(
            timeText = { TimeText() },
            vignette = { Vignette(vignettePosition = VignettePosition.TopAndBottom) }
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colors.background)
                    .padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Box(
                    modifier = Modifier
                        .size(58.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colors.primary.copy(alpha = 0.18f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Security,
                        contentDescription = "PushGate approval",
                        tint = MaterialTheme.colors.primary
                    )
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    text = "Approving PushGate request",
                    style = MaterialTheme.typography.title3,
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center
                )
                Spacer(Modifier.height(12.dp))
                CircularProgressIndicator()
            }
        }
    }
}
