"""Creating an integration with a client_id already in use is a 409, not a 500."""
from __future__ import annotations

from fastapi.testclient import TestClient

from server.app.config import Settings
from server.app.main import create_app

from test_server_hardening import ADMIN_TOKEN, admin_request, create_integration, create_user, start_auth


def test_duplicate_client_id_is_409_and_keeps_the_first(tmp_path) -> None:
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'dup.db'}", bootstrap_token=ADMIN_TOKEN))
    with TestClient(app, raise_server_exceptions=False) as client:
        create_user(client, "dup-user")
        first = create_integration(client, "dup-client")

        response = admin_request(
            client, "POST", "/api/admin/integrations", json={"name": "second", "client_id": "dup-client", "fail_mode": "closed"}
        )

        assert response.status_code == 409, response.text
        assert response.json()["detail"]["code"] == "duplicate_client_id"
        assert "secret" not in response.text
        listed = admin_request(client, "GET", "/api/admin/integrations").json()["data"]
        assert [(row["id"], row["name"]) for row in listed] == [(first["id"], "dup-client")]
        # The first integration's secret still signs requests.
        assert start_auth(client, first, "dup-user", "dup-nonce").status_code == 201
        # A disabled integration still owns its client_id.
        assert admin_request(client, "DELETE", f"/api/admin/integrations/{first['id']}").status_code == 204
        response = admin_request(client, "POST", "/api/admin/integrations", json={"name": "third", "client_id": "dup-client"})
        assert response.status_code == 409, response.text
        # A new client_id, or none, still creates.
        assert admin_request(client, "POST", "/api/admin/integrations", json={"name": "other", "client_id": "other-client"}).status_code == 201
        assert admin_request(client, "POST", "/api/admin/integrations", json={"name": "generated"}).status_code == 201
