from fastapi.testclient import TestClient
from server.app.config import Settings
from server.app.main import create_app
from server.app.push import unifiedpush_endpoint_allowed


def test_public_defaults_deny_cross_origin_and_unconfigured_push():
    settings = Settings(_env_file=None)
    assert settings.global_fail_mode == "closed"
    assert settings.bootstrap_token is None
    assert not settings.trusted_proxy_auth_enabled
    assert not settings.cors_allow_origins
    assert settings.cors_allow_origin_regex is None
    assert unifiedpush_endpoint_allowed("https://untrusted.example/push", None) is False
    assert not unifiedpush_endpoint_allowed("https://untrusted.example/push", "notify.example")
    assert unifiedpush_endpoint_allowed("https://notify.example/push", "notify.example")


def test_anonymous_admin_and_debug_routes_are_closed(tmp_path):
    app = create_app(Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'defaults.db'}"))
    with TestClient(app) as client:
        for path in ("/api/admin/users", "/api/admin/settings/global", "/api/admin/integrations"):
            assert client.get(path).status_code in (401, 403)
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404
        assert client.get("/healthz").status_code == 200


def test_api_schema_requires_explicit_opt_in(tmp_path):
    app = create_app(Settings(_env_file=None, database_url=f"sqlite:///{tmp_path / 'docs.db'}", api_docs_enabled=True))
    with TestClient(app) as client:
        assert client.get("/openapi.json").json()["info"]["version"] == "1.0.2"


def test_malformed_push_endpoint_is_rejected():
    assert unifiedpush_endpoint_allowed("https://notify.example:bad/push", "notify.example") is False
