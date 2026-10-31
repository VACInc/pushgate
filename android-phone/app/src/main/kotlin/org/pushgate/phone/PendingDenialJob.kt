package org.pushgate.phone

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import okhttp3.Call
import org.json.JSONObject
import java.time.Instant

internal data class PendingDenial(
    val challenge: AuthChallenge,
    val binding: NotificationEnrollmentBinding
) {
    val stableId: String = "${binding.signingKeyAlias}:${challenge.id}"

    fun isDeliverable(currentBinding: NotificationEnrollmentBinding?, now: Instant = Instant.now()): Boolean =
        binding == currentBinding && challenge.isActionable(now)

    fun toJson(): String = JSONObject()
        .put("id", challenge.id)
        .put("username", challenge.username)
        .put("system", challenge.system)
        .put("pam_service", challenge.pamService)
        .put("source_ip", challenge.sourceIp)
        .put("geolocation", challenge.geolocation)
        .put("requested_at", challenge.requestedAt)
        .put("expires_at", challenge.expiresAt)
        .put("require_biometric", challenge.requireBiometric)
        .put("device_id", binding.deviceId)
        .put("signing_key_alias", binding.signingKeyAlias)
        .toString()

    companion object {
        fun fromJson(value: String): PendingDenial {
            val json = JSONObject(value)
            return PendingDenial(
                challenge = AuthChallenge.fromJson(json),
                binding = NotificationEnrollmentBinding(
                    deviceId = json.getString("device_id"),
                    signingKeyAlias = json.getString("signing_key_alias")
                )
            )
        }
    }
}

internal fun deduplicatePendingDenials(
    existing: Collection<PendingDenial>,
    replacement: PendingDenial
): List<PendingDenial> = existing.filterNot { it.stableId == replacement.stableId } + replacement

internal data class DecisionClaim(
    val challengeId: String,
    val expiresAt: String,
    val binding: NotificationEnrollmentBinding,
    val decision: Decision
) {
    fun conflictsWith(other: DecisionClaim): Boolean =
        binding == other.binding && challengeId == other.challengeId

    fun isActive(currentBinding: NotificationEnrollmentBinding?, now: Instant = Instant.now()): Boolean =
        binding == currentBinding && AuthChallenge(
            id = challengeId,
            username = "",
            system = "",
            pamService = "",
            sourceIp = null,
            geolocation = null,
            requestedAt = null,
            expiresAt = expiresAt,
            requireBiometric = false
        ).isActionable(now)

    fun toJson(): String = JSONObject()
        .put("challenge_id", challengeId)
        .put("expires_at", expiresAt)
        .put("device_id", binding.deviceId)
        .put("signing_key_alias", binding.signingKeyAlias)
        .put("decision", decision.wireValue)
        .toString()

    companion object {
        fun fromJson(value: String): DecisionClaim {
            val json = JSONObject(value)
            val decision = when (json.getString("decision")) {
                Decision.Approve.wireValue -> Decision.Approve
                Decision.Deny.wireValue -> Decision.Deny
                else -> throw IllegalArgumentException("Invalid decision claim")
            }
            return DecisionClaim(
                challengeId = json.getString("challenge_id"),
                expiresAt = json.getString("expires_at"),
                binding = NotificationEnrollmentBinding(
                    deviceId = json.getString("device_id"),
                    signingKeyAlias = json.getString("signing_key_alias")
                ),
                decision = decision
            )
        }
    }
}

internal object DecisionClaimStore {
    private const val PREFS = "pushgate.decision_claims"
    private const val RECORDS = "records"

    @Synchronized
    fun tryClaim(
        context: Context,
        challenge: AuthChallenge,
        binding: NotificationEnrollmentBinding,
        decision: Decision
    ): Boolean {
        if (!challenge.isActionable()) return false
        val currentBinding = AuthNotificationDispatcher.currentBinding(context)
        if (binding != currentBinding) return false
        val claims = read(context).filter { it.isActive(currentBinding) }
        val replacement = DecisionClaim(challenge.id, challenge.expiresAt, binding, decision)
        if (
            !decisionMayStart(
                settled = SettledRequestStore.contains(context, challenge.id),
                conflictingClaim = claims.any(replacement::conflictsWith)
            )
        ) {
            write(context, claims)
            return false
        }
        return write(context, claims + replacement)
    }

    @Synchronized
    fun release(
        context: Context,
        challengeId: String,
        binding: NotificationEnrollmentBinding,
        decision: Decision
    ): Boolean = write(
        context,
        read(context).filterNot {
            it.challengeId == challengeId && it.binding == binding && it.decision == decision
        }
    )

    @Synchronized
    fun hasActiveClaim(context: Context, challengeId: String, binding: NotificationEnrollmentBinding): Boolean =
        read(context).any { it.challengeId == challengeId && it.isActive(binding) }

    @Synchronized
    fun clear(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().commit()

    /** The request is settled server-side; no claim on it can still matter. */
    @Synchronized
    fun releaseAll(context: Context, challengeId: String): Boolean =
        write(context, read(context).filterNot { it.challengeId == challengeId })

    private fun read(context: Context): List<DecisionClaim> =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getStringSet(RECORDS, emptySet())
            .orEmpty()
            .mapNotNull { runCatching { DecisionClaim.fromJson(it) }.getOrNull() }

    private fun write(context: Context, claims: Collection<DecisionClaim>): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(RECORDS, claims.mapTo(linkedSetOf(), DecisionClaim::toJson))
            .commit()
}

internal object PendingDenialStore {
    private const val PREFS = "pushgate.pending_denials"
    private const val RECORDS = "records"

    @Synchronized
    fun enqueue(context: Context, denial: PendingDenial): Boolean {
        val existing = read(context)
        return write(context, deduplicatePendingDenials(existing, denial))
    }

    @Synchronized
    fun loadDeliverable(context: Context): List<PendingDenial> {
        val notifications = AuthNotificationDispatcher(context)
        val currentBinding = AuthNotificationDispatcher.currentBinding(context)
        val all = read(context)
        val deliverable = all.filter { it.isDeliverable(currentBinding) }
        all.filterNot { it in deliverable }.forEach { notifications.cancel(it.challenge.id, it.binding) }
        if (deliverable.size != all.size) write(context, deliverable)
        return deliverable
    }

    @Synchronized
    fun removeByChallengeId(context: Context, challengeId: String): Boolean =
        write(context, read(context).filterNot { it.challenge.id == challengeId })

    @Synchronized
    fun remove(context: Context, stableId: String): Boolean =
        write(context, read(context).filterNot { it.stableId == stableId })

    @Synchronized
    fun clear(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().commit()

    private fun read(context: Context): List<PendingDenial> =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getStringSet(RECORDS, emptySet())
            .orEmpty()
            .mapNotNull { runCatching { PendingDenial.fromJson(it) }.getOrNull() }

    private fun write(context: Context, denials: Collection<PendingDenial>): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(RECORDS, denials.mapTo(linkedSetOf(), PendingDenial::toJson))
            .commit()
}

internal object PendingDenialScheduler {
    private const val JOB_ID = 0x50554744

    fun enqueue(
        context: Context,
        challenge: AuthChallenge,
        binding: NotificationEnrollmentBinding
    ): Boolean {
        val currentBinding = AuthNotificationDispatcher.currentBinding(context)
        val denial = PendingDenial(challenge, binding)
        if (!denial.isDeliverable(currentBinding)) return false
        if (!DecisionClaimStore.tryClaim(context, challenge, binding, Decision.Deny)) return false
        if (!PendingDenialStore.enqueue(context, denial)) {
            DecisionClaimStore.release(context, challenge.id, binding, Decision.Deny)
            return false
        }
        return finishPendingDenialScheduling(
            schedule = { schedule(context) },
            removePendingDenial = { PendingDenialStore.remove(context, denial.stableId) },
            releaseDecisionClaim = {
                DecisionClaimStore.release(context, challenge.id, binding, Decision.Deny)
            }
        )
    }

    fun ensureScheduled(context: Context) {
        if (PendingDenialStore.loadDeliverable(context).isNotEmpty()) schedule(context)
    }

    fun clear(context: Context) {
        PendingDenialStore.clear(context)
        DecisionClaimStore.clear(context)
        SettledRequestStore.clear(context)
        context.getSystemService(JobScheduler::class.java).cancel(JOB_ID)
    }

    /**
     * A settled request needs no queued denial and holds no decision claim. It is marked settled
     * first so a late delivery cannot land between the claim release and the mark and repost it.
     */
    fun discard(context: Context, challengeId: String) {
        SettledRequestStore.mark(context, challengeId)
        PendingDenialStore.removeByChallengeId(context, challengeId)
        DecisionClaimStore.releaseAll(context, challengeId)
    }

    private fun schedule(context: Context): Boolean {
        val job = JobInfo.Builder(JOB_ID, ComponentName(context, PendingDenialJobService::class.java))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setPersisted(true)
            .setBackoffCriteria(30_000L, JobInfo.BACKOFF_POLICY_EXPONENTIAL)
            .build()
        return context.getSystemService(JobScheduler::class.java).schedule(job) == JobScheduler.RESULT_SUCCESS
    }
}

internal fun finishPendingDenialScheduling(
    schedule: () -> Boolean,
    removePendingDenial: () -> Unit,
    releaseDecisionClaim: () -> Unit
): Boolean {
    val scheduled = try {
        schedule()
    } catch (_: RuntimeException) {
        false
    }
    if (scheduled) return true
    removePendingDenial()
    releaseDecisionClaim()
    return false
}

class PendingDenialJobService : JobService() {
    private var activeCall: Call? = null
    private var jobGeneration = 0

    override fun onStartJob(params: JobParameters): Boolean {
        DebugLog.log(this, "deny-job", "Queued deny job started")
        if (PendingDenialStore.loadDeliverable(this).isEmpty()) return false
        jobGeneration += 1
        deliverNext(params, jobGeneration)
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        DebugLog.log(this, "deny-job", "Android stopped the queued deny job early")
        jobGeneration += 1
        activeCall?.cancel()
        activeCall = null
        return PendingDenialStore.loadDeliverable(this).isNotEmpty()
    }

    private fun deliverNext(params: JobParameters, generation: Int) {
        if (generation != jobGeneration) return
        val denial = PendingDenialStore.loadDeliverable(this).firstOrNull()
        if (denial == null) {
            activeCall = null
            jobFinished(params, false)
            return
        }
        val enrollment = EnrollmentStore.load(this)
        val currentBinding = AuthNotificationDispatcher.currentBinding(this)
        val privateKey = if (denial.binding == currentBinding) {
            PhoneKeyStore.privateKeyOrNull(this, denial.binding.signingKeyAlias)
        } else {
            null
        }
        if (enrollment == null || privateKey == null || !denial.isDeliverable(currentBinding)) {
            PendingDenialStore.remove(this, denial.stableId)
            AuthNotificationDispatcher(this).cancel(denial.challenge.id, denial.binding)
            deliverNext(params, generation)
            return
        }

        activeCall = runCatching {
            DeviceAuthClient().decide(
                enrollment = enrollment,
                requestId = denial.challenge.id,
                decision = Decision.Deny,
                privateKey = privateKey,
                biometricVerified = false,
                callback = { result ->
                    if (generation != jobGeneration) return@decide
                    activeCall = null
                    if (result.isSuccess) {
                        ChallengeResolutions.settledHere(this, denial.challenge.id, Decision.Deny)
                        PendingDenialStore.remove(this, denial.stableId)
                        AuthNotificationDispatcher(this).cancel(denial.challenge.id, denial.binding)
                        deliverNext(params, generation)
                    } else {
                        DebugLog.error(this, "deny-job", "Deny did not reach the server; will retry", result.exceptionOrNull())
                        AuthNotificationDispatcher(this).show(denial.challenge, denial.binding)
                        jobFinished(params, true)
                    }
                }
            )
        }.getOrElse {
            AuthNotificationDispatcher(this).show(denial.challenge, denial.binding)
            jobFinished(params, true)
            null
        }
    }
}
