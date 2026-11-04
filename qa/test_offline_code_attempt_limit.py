"""Online offline-code guessing is bounded per principal.

Any holder of an integration secret can submit offline_code with a start
request. Without a limit the 6-digit TOTP space (three valid codes per 30 s
window) could be searched online at the request rate.
"""
from datetime import timedelta
from uuid import uuid4

import pyotp
from fastapi.testclient import TestClient

from qa.test_audit_2026_10_28 import make_app
from qa.test_server_hardening import admin_request, create_device, create_integration, create_user, start_auth
from server.app.models import AuthRequest
from server.app.security import utcnow


def wrong_code(secret: str) -> str:
    valid = {pyotp.TOTP(secret).at(utcnow() + timedelta(seconds=offset)) for offset in (-30, 0, 30)}
    return next(code for code in (f"{n:06d}" for n in range(1_000_000)) if code not in valid)


def test_wrong_offline_codes_lock_out_offline_factors_but_not_push(tmp_path) -> None:
    app = make_app(tmp_path, "offline-limit.db", offline_code_max_failures=5, offline_code_failure_window_seconds=900)
    suffix = uuid4().hex[:10]
    with TestClient(app) as client:
        user = create_user(client, "guess-" + suffix)
        bystander = create_user(client, "bystander-" + suffix)
        create_device(client, user["id"])
        integration = create_integration(client, "guess-" + suffix)
        secret = admin_request(client, "POST", f"/api/admin/users/{user['id']}/totp").json()["data"]["secret"]
        other_secret = admin_request(client, "POST", f"/api/admin/users/{bystander['id']}/totp").json()["data"]["secret"]
        backup = admin_request(client, "POST", f"/api/admin/users/{user['id']}/backup-codes",
                               params={"count": 1}).json()["data"]["codes"][0]
        bad = wrong_code(secret)

        for attempt in range(5):
            guessed = start_auth(client, integration, user["username"], f"guess-{attempt}-{suffix}", offline_code=bad)
            assert guessed.json()["data"]["status"] == "denied"

        # The limit is reached: even the right TOTP or an unused backup code is refused unchecked.
        for label, code in (("totp", pyotp.TOTP(secret).now()), ("backup", backup)):
            refused = start_auth(client, integration, user["username"], f"refused-{label}-{suffix}", offline_code=code)
            assert refused.json()["data"]["status"] == "denied"
            with app.state.db.SessionLocal() as db:
                assert db.get(AuthRequest, refused.json()["data"]["id"]).factor == "offline_code_throttled"
        # Refusing unchecked did not spend the backup code.
        codes = admin_request(client, "GET", f"/api/admin/users/{user['id']}/backup-codes").json()["data"]
        assert [row["used_at"] for row in codes] == [None]

        # Push approval is unaffected, and so is every other principal.
        push = start_auth(client, integration, user["username"], "push-" + suffix)
        assert push.json()["data"]["status"] == "pending"
        other = start_auth(client, integration, bystander["username"], "other-" + suffix,
                           offline_code=pyotp.TOTP(other_secret).now())
        assert other.json()["data"]["status"] == "approved"

        # Once the failures age out of the window the right code works again.
        with app.state.db.SessionLocal() as db:
            for row in db.query(AuthRequest).filter(AuthRequest.user_id == user["id"]).all():
                row.created_at = utcnow() - timedelta(seconds=901)
            db.commit()
        recovered = start_auth(client, integration, user["username"], "recovered-" + suffix, offline_code=backup)
        assert recovered.json()["data"]["status"] == "approved"


def test_defaults_allow_ten_failures_per_fifteen_minutes(tmp_path) -> None:
    app = make_app(tmp_path, "offline-defaults.db")
    assert app.state.settings.offline_code_max_failures == 10
    assert app.state.settings.offline_code_failure_window_seconds == 900
