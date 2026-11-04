"""Every HTTP response carries baseline browser hardening, proxy or not."""
from pathlib import Path

from fastapi.testclient import TestClient

from qa.test_server_hardening import ADMIN_TOKEN
from server.app.config import Settings
from server.app.main import BASELINE_SECURITY_HEADERS, create_app


def make_client(tmp_path: Path, **overrides) -> TestClient:
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("<!doctype html><title>console</title>")
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'headers.db'}",
        bootstrap_token=ADMIN_TOKEN,
        static_dir=str(static),
        **overrides,
    )
    return TestClient(create_app(settings))


def assert_hardened(response) -> None:
    for name, value in BASELINE_SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, (response.request.url, name)


def test_console_api_errors_and_rate_limits_are_hardened(tmp_path: Path) -> None:
    with make_client(tmp_path, rate_limit_per_minute=3) as client:
        console = client.get("/")
        assert console.status_code == 200 and "console" in console.text
        assert_hardened(console)
        assert "frame-ancestors 'none'" in console.headers["content-security-policy"]
        assert console.headers["x-frame-options"] == "DENY"

        health = client.get("/healthz")
        assert health.status_code == 200
        assert_hardened(health)

        unauthorized = client.get("/api/admin/users")
        assert unauthorized.status_code == 401
        assert_hardened(unauthorized)
        assert unauthorized.headers["cache-control"] == "no-store"

        for _ in range(3):
            client.get("/api/admin/users")
        limited = client.get("/api/admin/users")
        assert limited.status_code == 429
        assert_hardened(limited)


def test_opt_in_api_docs_keep_their_page_working(tmp_path: Path) -> None:
    with make_client(tmp_path, api_docs_enabled=True) as client:
        docs = client.get("/docs")
        assert docs.status_code == 200
        assert "content-security-policy" not in docs.headers
        assert docs.headers["x-frame-options"] == "DENY"
        schema = client.get("/openapi.json")
        assert_hardened(schema)
