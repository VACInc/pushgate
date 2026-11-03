"""An admin PATCH that sets a required field to null is a 422, and nothing changes.

Leaving a field out of a PATCH keeps it. Sending null for a column the database
stores as NOT NULL used to reach the database and come back as a 500, or as a
misleading 409 duplicate for unique names.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from server.app.config import Settings
from server.app.main import create_app

from test_server_hardening import ADMIN_TOKEN, admin_request, create_device, create_integration, create_user


def make_resources(client: TestClient) -> dict[str, str]:
    user = create_user(client, "null-user")
    device, _key = create_device(client, user["id"])
    integration = create_integration(client, "null-integration")
    group = admin_request(client, "POST", "/api/admin/groups", json={"name": "null-group"}).json()["data"]
    policy = admin_request(
        client, "POST", "/api/admin/policies", json={"name": "null-policy", "subject_type": "user", "subject_id": user["id"]}
    ).json()["data"]
    role = admin_request(client, "POST", "/api/admin/rbac/roles", json={"name": "null-role"}).json()["data"]
    key = admin_request(client, "POST", "/api/admin/rbac/api-keys", json={"name": "null-key"}).json()["data"]
    return {
        "users": user["id"],
        "devices": device["id"],
        "integrations": integration["id"],
        "groups": group["id"],
        "policies": policy["id"],
        "rbac/roles": role["id"],
        "rbac/api-keys": key["id"],
    }


NULLED_FIELDS = [
    ("users", "locked"),
    ("groups", "name"),
    ("devices", "name"),
    ("devices", "revoked"),
    ("devices", "require_biometric"),
    ("integrations", "name"),
    ("integrations", "enabled"),
    ("policies", "name"),
    ("policies", "enabled"),
    ("rbac/roles", "permissions"),
    ("rbac/roles", "enabled"),
    ("rbac/api-keys", "name"),
    ("rbac/api-keys", "role"),
    ("rbac/api-keys", "enabled"),
]


@pytest.mark.parametrize(("resource", "field"), NULLED_FIELDS)
def test_null_on_a_required_field_is_422_and_changes_nothing(tmp_path, resource, field) -> None:
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'null.db'}", bootstrap_token=ADMIN_TOKEN))
    with TestClient(app, raise_server_exceptions=False) as client:
        ids = make_resources(client)
        path = f"/api/admin/{resource}/{ids[resource]}"
        before = admin_request(client, "GET", path).json()["data"]

        response = admin_request(client, "PATCH", path, json={field: None})

        assert response.status_code == 422, response.text
        assert f"{field} cannot be null" in response.text
        assert admin_request(client, "GET", path).json()["data"] == before


def test_omitted_and_nullable_fields_still_patch(tmp_path) -> None:
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'null.db'}", bootstrap_token=ADMIN_TOKEN))
    with TestClient(app, raise_server_exceptions=False) as client:
        ids = make_resources(client)
        # Nullable columns accept null; the required ones are untouched when left out.
        response = admin_request(client, "PATCH", f"/api/admin/users/{ids['users']}", json={"display_name": None, "fail_mode": None})
        assert response.status_code == 200, response.text
        assert response.json()["data"]["locked"] is False
        response = admin_request(client, "PATCH", f"/api/admin/groups/{ids['groups']}", json={"description": None})
        assert response.status_code == 200, response.text
        assert response.json()["data"]["name"] == "null-group"
        response = admin_request(client, "PATCH", f"/api/admin/devices/{ids['devices']}", json={"push_token": None})
        assert response.status_code == 200, response.text
        response = admin_request(client, "PATCH", f"/api/admin/integrations/{ids['integrations']}", json={"fail_mode": None})
        assert response.status_code == 200, response.text
        response = admin_request(client, "PATCH", f"/api/admin/policies/{ids['policies']}", json={"auth_ttl_seconds": None})
        assert response.status_code == 200, response.text
        response = admin_request(client, "PATCH", f"/api/admin/rbac/roles/{ids['rbac/roles']}", json={"description": None})
        assert response.status_code == 200, response.text
        response = admin_request(client, "PATCH", f"/api/admin/rbac/api-keys/{ids['rbac/api-keys']}", json={"name": "renamed"})
        assert response.status_code == 200, response.text
        assert response.json()["data"]["name"] == "renamed"
