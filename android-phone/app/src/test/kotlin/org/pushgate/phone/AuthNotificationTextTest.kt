package org.pushgate.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class AuthNotificationTextTest {
    @Test
    fun showsTheServerLineAsItIs() {
        val challenge = challenge(pushText = "Agent requests SSH from workstation to server01")

        assertEquals("Agent requests SSH from workstation to server01", notificationText(challenge))
    }

    @Test
    fun buildsTheSameLineWhenTheServerSendsNone() {
        assertEquals("alice requests SSH from 192.0.2.10 to gateway-1", notificationText(challenge(username = "alice", system = "gateway-1", pamService = "SSH access")))
        assertEquals("alice requests SSH from 192.0.2.10 to gateway-1", notificationText(challenge(username = "alice", system = "gateway-1", pamService = "sshd")))
        assertEquals("alice requests SSH from 192.0.2.10 to gateway-1", notificationText(challenge(username = "alice", system = "gateway-1", pamService = "ssh")))
    }

    @Test
    fun unknownServiceKeepsItsName() {
        assertEquals("alice requests sudo from 192.0.2.10 to server01", notificationText(challenge(username = "alice", pamService = "sudo")))
        assertEquals("alice requests access from 192.0.2.10 to server01", notificationText(challenge(username = "alice", pamService = "")))
    }

    @Test
    fun consentServiceNamesOnlyAnotherLoginUser() {
        assertEquals("svc requests SSH from 192.0.2.10 to server01", notificationText(challenge(username = "svc", pamService = "SSH as svc")))
        assertEquals("svc requests SSH as root from 192.0.2.10 to server01", notificationText(challenge(username = "svc", pamService = "SSH as root")))
    }

    @Test
    fun namesTheHostOnceWhenTheServiceIsTheHostName() {
        assertEquals("serviceuser requests SSH from 192.0.2.10 to server01", notificationText(challenge(system = "server01", pamService = "server01")))
    }

    @Test
    fun placeholdersForMissingFields() {
        assertEquals(
            "Unknown user requests SSH from unknown source to unknown host",
            notificationText(challenge(username = "", system = "", pamService = "SSH access", sourceIp = null))
        )
    }

    @Test
    fun stripsPromptSpoofingControlsAndBidiFormatting() {
        val challenge = challenge(
            username = "alice\nadmin",
            system = "gateway‮txt.exe",
            pamService = "ss⁦h",
            sourceIp = "192.0.2.10\rTrusted"
        )

        assertEquals("alice admin requests ss h from 192.0.2.10 Trusted to gateway txt.exe", notificationText(challenge))
        val spoofed = notificationText(challenge(pushText = "Agent requests SSH\nApproved‮ from x to y"))
        assertFalse(spoofed.contains('\n'))
        assertEquals("Agent requests SSH Approved from x to y", spoofed)
    }

    @Test
    fun neverAddsAReasonLine() {
        val json = org.json.JSONObject()
            .put("id", "request-1")
            .put("username", "serviceuser")
            .put("system", "server01")
            .put("pam_service", "SSH access")
            .put("source_ip", "192.0.2.10")
            .put("expires_at", "2099-01-01T00:00:00Z")
            .put("reason", "Check backups")
            .put("detail", org.json.JSONObject().put("reason", "Check backups"))

        assertEquals("serviceuser requests SSH from 192.0.2.10 to server01", notificationText(AuthChallenge.fromJson(json)))
    }

    @Test
    fun serverLineRidesToTheWatch() {
        val json = org.json.JSONObject()
            .put("id", "request-1")
            .put("username", "serviceuser")
            .put("system", "server01")
            .put("pam_service", "SSH access")
            .put("source_ip", "192.0.2.10")
            .put("expires_at", "2099-01-01T00:00:00Z")
            .put("push_text", "Agent requests SSH from workstation to server01")
        val challenge = AuthChallenge.fromJson(json)

        assertEquals("Agent requests SSH from workstation to server01", challenge.pushText)
        assertEquals(
            "Agent requests SSH from workstation to server01",
            org.json.JSONObject(PhoneWearRelayProtocol.challengePayload(challenge))
                .getJSONObject("data").getString("push_text")
        )
        assertFalse(org.json.JSONObject(PhoneWearRelayProtocol.challengePayload(challenge)).getJSONObject("data").has("reason"))
    }

    private fun challenge(
        username: String = "serviceuser",
        system: String = "server01",
        pamService: String = "SSH access",
        sourceIp: String? = "192.0.2.10",
        pushText: String? = null
    ) = AuthChallenge(
        id = "request-1",
        username = username,
        system = system,
        pamService = pamService,
        sourceIp = sourceIp,
        geolocation = null,
        requestedAt = null,
        expiresAt = "2099-01-01T00:00:00Z",
        requireBiometric = true,
        pushText = pushText
    )
}
