"""The one-line approval text every PushGate notification shows.

    <USER> requests <SERVICE> from <source machine> to <host>
    e.g. "Agent requests SSH from workstation to server01"

Who asks, for what, from which machine, to which host. Nothing else: no reason, no
approver, no second line. The phone and watch apps show the server's `push_text`
as it is, so the wording changes here without an app update.
"""

from __future__ import annotations

from collections.abc import Mapping

# Service labels that all mean an SSH login. Helpers send "SSH access", older
# helpers "sshd"; a consent push may send "SSH as <login user>".
_SSH_SERVICES = {"ssh access", "sshd", "ssh"}


def _clean(value: object) -> str:
    """One line of plain text: control characters become spaces, runs collapse."""
    if value is None:
        return ""
    text = "".join(" " if not ch.isprintable() else ch for ch in str(value))
    return " ".join(text.split())


def parse_display_users(value: str | None) -> dict[str, str]:
    """`login:Shown,login2:Shown2` -> {login: Shown}. Logins match case-insensitively."""
    names: dict[str, str] = {}
    for item in (value or "").split(","):
        item = item.strip()
        if not item:
            continue
        login, sep, shown = item.partition(":")
        login, shown = _clean(login), _clean(shown)
        if not sep or not login or not shown:
            raise ValueError(f"display user entry must be login:Shown, got {item!r}")
        names[login.lower()] = shown
    return names


def display_user(username: object, display_users: Mapping[str, str] | None = None) -> str:
    """The configured display name for this login, else the login as it is."""
    user = _clean(username)
    if not user:
        return "Unknown user"
    return (display_users or {}).get(user.lower(), user)


def display_service(pam_service: object, username: object = "", system: object = "") -> str:
    service = _clean(pam_service)
    lowered = service.lower()
    if not service:
        return "access"
    if lowered in _SSH_SERVICES:
        return "SSH"
    # Helpers from before 2026-10-30 sent the host name as the service.
    if lowered == _clean(system).lower():
        return "SSH"
    # Consent push: "SSH as <login user>". The requester's own login adds nothing.
    if lowered == "ssh as" or lowered.startswith("ssh as "):
        target = service[len("ssh as"):].strip()
        if not target or target.lower() == _clean(username).lower():
            return "SSH"
        return f"SSH as {target}"
    return service


def push_text(
    username: object,
    pam_service: object,
    source: object,
    system: object,
    display_users: Mapping[str, str] | None = None,
) -> str:
    """`<USER> requests <SERVICE> from <source machine> to <host>`."""
    user = display_user(username, display_users)
    service = display_service(pam_service, username, system)
    src = _clean(source) or "unknown source"
    dest = _clean(system) or "unknown host"
    return f"{user} requests {service} from {src} to {dest}"
