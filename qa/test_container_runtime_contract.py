import os
import subprocess
import sys
from pathlib import Path

from server.app.config import Settings


ROOT = Path(__file__).resolve().parents[1]


def test_container_sqlite_default_uses_private_service_owned_directory():
    dockerfile = (ROOT / "server" / "Dockerfile").read_text(encoding="utf-8")
    directory_setup = (
        "install -d --owner=pushgate --group=pushgate --mode=0700 "
        "/var/lib/pushgate"
    )
    sqlite_default = "PUSHGATE_DATABASE_URL=sqlite:////var/lib/pushgate/pushgate.db"

    assert directory_setup in dockerfile
    assert sqlite_default in dockerfile
    assert dockerfile.index(directory_setup) < dockerfile.index("USER pushgate")
    assert '"server.app.main:create_app", "--factory"' in dockerfile
    assert "server.app.main:app" not in dockerfile


def test_server_module_import_does_not_open_default_database(tmp_path):
    shared_checkout = tmp_path / "group-writable-checkout"
    shared_checkout.mkdir(mode=0o770)
    shared_checkout.chmod(0o770)
    env = os.environ.copy()
    env.pop("PUSHGATE_DATABASE_URL", None)
    env["PYTHONPATH"] = str(ROOT)

    result = subprocess.run(
        [sys.executable, "-c", "import server.app.main"],
        cwd=shared_checkout,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert not (shared_checkout / "pushgate.db").exists()


def test_container_database_environment_supports_sqlite_and_postgres(monkeypatch):
    compose = (ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "PUSHGATE_DATABASE_URL:" in compose
    assert "postgresql+psycopg://" in compose

    monkeypatch.setenv(
        "PUSHGATE_DATABASE_URL", "sqlite:////var/lib/pushgate/pushgate.db"
    )
    assert Settings().database_url == "sqlite:////var/lib/pushgate/pushgate.db"
    monkeypatch.setenv(
        "PUSHGATE_DATABASE_URL",
        "postgresql+psycopg://pushgate:password@postgres:5432/pushgate",
    )

    assert Settings().database_url.startswith("postgresql+psycopg://")
