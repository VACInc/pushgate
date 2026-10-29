from __future__ import annotations

import argparse
import json

from pushgate import PushGateAdminClient


def run(base_url: str, token: str) -> dict:
    client = PushGateAdminClient(base_url, token)
    try:
        users = [
            client.create_user("alice", "Alice Operator", fail_mode="open"),
            client.create_user("bob", "Bob Breakglass", fail_mode="open"),
            client.create_user("carol", "Carol Console", fail_mode="open"),
        ]
        alice, bob, carol = users
        operators = client.create_group("operators", "Bulk-enrolled lab operators")
        for user in users:
            client.add_group_user(operators["id"], user["id"])

        phone = client.create_device(alice["id"], "Alice phone", "phone", require_biometric=True)
        wear = client.create_device(alice["id"], "Alice watch", "wear")
        client.create_device(bob["id"], "Bob phone", "phone")
        linux = client.create_integration("lab-linux", client_id="lab-linux", fail_mode="open")
        proxy = client.create_integration("proxy", client_id="proxy", fail_mode="closed", system_type="proxy")
        client.enroll_totp(carol["id"])
        backup_codes = client.create_backup_codes(carol["id"], count=3)
        client.set_user_fail_mode(alice["id"], "closed")
        rotated_wear = client.rotate_device_key(wear["id"])
        client.revoke_device(phone["id"])
        api_key = client.create_api_key("automation-reader", "read-only")
        reader = PushGateAdminClient(base_url, api_key["token"])
        try:
            read_only_denials = reader.denials_last_24h()
        finally:
            reader.close()
        client.delete_api_key(api_key["id"])
        audit = client.audit_logs(resource_type="device", resource_id=phone["id"], limit=20)
        denials = client.denials_last_24h()
        return {
            "users": [user["username"] for user in users],
            "group": operators["name"],
            "group_members": [user["username"] for user in client.group_users(operators["id"])],
            "integration": {"name": linux["name"], "client_id": linux["client_id"], "fail_mode": linux["fail_mode"]},
            "proxy_integration": {"name": proxy["name"], "client_id": proxy["client_id"], "system_type": proxy["system_type"], "fail_mode": proxy["fail_mode"]},
            "fail_closed_user": client.get_user(alice["id"])["username"],
            "revoked_device": phone["id"],
            "revoked_device_state": client.get_device(phone["id"])["revoked"],
            "rotated_wear_has_payload": bool(rotated_wear.get("enrollment_qr_payload")),
            "bob_device_count": len(client.devices(bob["id"])),
            "backup_code_count": len(backup_codes["codes"]),
            "denials_last_24h": len(denials),
            "read_only_denials_last_24h": len(read_only_denials),
            "device_audit_actions": [row["action"] for row in audit],
        }
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Drive PushGate Admin API end to end.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--token",
        required=True,
        help="configured PushGate bootstrap token or scoped Admin API key",
    )
    args = parser.parse_args()
    print(json.dumps(run(args.base_url, args.token), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
