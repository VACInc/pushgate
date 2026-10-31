"""The request text the server owns: title `PushGate`, line `<USER> requests <SERVICE> from <source machine> to <host>`."""
from __future__ import annotations

import json

import pytest

from server.app.config import Settings
from server.app.push import unifiedpush_body
from server.app.push_text import display_service, display_user, parse_display_users, push_text, push_title

# A deployment that shows its automation login under a display name.
NAMES = parse_display_users("agent:AGENT")


def push_text_(username, service, source, system):
    return push_text(username, service, source, system, NAMES)


def test_configured_login_reads_as_its_display_name() -> None:
    assert push_text_("agent", "SSH access", "server01", "server02") == "AGENT requests SSH from server01 to server02"
    assert display_user("AGENT", NAMES) == "AGENT"
    assert display_user("Agent", NAMES) == "AGENT"
    # Without the setting every login is shown as it is.
    assert push_text("agent", "SSH access", "server01", "server02") == "agent requests SSH from server01 to server02"


def test_other_users_keep_their_name() -> None:
    assert push_text_("alice", "SSH access", "server01", "server06") == "alice requests SSH from server01 to server06"
    assert push_text_("Operator", "sshd", "server06", "server07") == "Operator requests SSH from server06 to server07"
    assert display_user("agents", NAMES) == "agents"
    assert display_user("", NAMES) == "Unknown user"
    assert display_user(None, NAMES) == "Unknown user"


def test_display_users_setting() -> None:
    assert parse_display_users("") == {}
    assert parse_display_users(" agent:AGENT , Svc:Service Bot ,") == {"agent": "AGENT", "svc": "Service Bot"}
    for bad in ("agent", "agent:", ":AGENT", "a:b,c"):
        with pytest.raises(ValueError):
            parse_display_users(bad)
    assert Settings(display_users="agent:AGENT").display_users == "agent:AGENT"
    with pytest.raises(ValueError):
        Settings(display_users="agent")


@pytest.mark.parametrize("service", ["SSH access", "ssh access", "sshd", "ssh", "SSH", "  SSH   access "])
def test_ssh_service_labels_read_as_SSH(service: str) -> None:
    assert display_service(service) == "SSH"


def test_unknown_service_keeps_its_name() -> None:
    assert push_text_("agent", "sudo", "server01", "server02") == "AGENT requests sudo from server01 to server02"
    assert push_text_("agent", "backup restore", "server01", "server04") == "AGENT requests backup restore from server01 to server04"
    assert display_service("x") == "x"
    assert display_service("") == "access"
    assert display_service(None) == "access"


def test_broker_consent_service() -> None:
    # Same user as the requester: nothing to add.
    assert push_text_("agent", "SSH as agent", "server01", "server03") == "AGENT requests SSH from server01 to server03"
    # A different login user is worth naming.
    assert push_text_("agent", "SSH as root", "server01", "server05") == "AGENT requests SSH as root from server01 to server05"
    assert display_service("SSH as ") == "SSH"


def test_old_helpers_that_sent_the_host_as_the_service() -> None:
    # 2026-10-29 regression: "agent requests server03 on server03".
    assert push_text_("agent", "server03", "server01", "server03") == "AGENT requests SSH from server01 to server03"
    assert push_text_("agent", "SERVER03", "server01", "server03") == "AGENT requests SSH from server01 to server03"


def test_source_falls_back_to_the_address_and_placeholders() -> None:
    assert push_text_("agent", "SSH access", "192.0.2.250", "server02") == "AGENT requests SSH from 192.0.2.250 to server02"
    assert push_text_("agent", "SSH access", "2001:db8::5", "server02") == "AGENT requests SSH from 2001:db8::5 to server02"
    assert push_text_("agent", "SSH access", None, "server02") == "AGENT requests SSH from unknown source to server02"
    assert push_text_("agent", "SSH access", "server01", "") == "AGENT requests SSH from server01 to unknown host"


def test_one_line_only() -> None:
    text = push_text_("agent\n", "SSH\taccess", "server01\r\nreason: x", "server02\x00")
    assert "\n" not in text and "\r" not in text and "\x00" not in text and "\t" not in text
    assert text == "AGENT requests SSH from server01 reason: x to server02"


def test_trimmed_unifiedpush_body_keeps_the_line() -> None:
    data = {
        "id": "req-1",
        "username": "agent",
        "system": "server02",
        "pam_service": "SSH access",
        "source_ip": "server01",
        "push_title": "PushGate",
        "push_text": "AGENT requests SSH from server01 to server02",
        "geolocation": "x" * 5000,  # forces the trimmed form
        "expires_at": "2026-10-31T00:00:00Z",
    }
    wire = json.loads(unifiedpush_body("dev-1", {"type": "auth_request", "data": data}))
    inner = json.loads(wire["payload"])["data"]
    assert "geolocation" not in inner
    assert inner["push_text"] == "AGENT requests SSH from server01 to server02"
    assert inner["push_title"] == "PushGate"


def test_the_title_is_server_owned() -> None:
    # The apps show this as it is; changing it is a server release, never an app update.
    assert push_title() == "PushGate"
