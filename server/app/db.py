from collections.abc import Generator
import os
from pathlib import Path
import stat

from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


APPEND_ONLY_TABLES = {"audit_logs", "auth_log_entries"}


class AppendOnlyLogViolation(RuntimeError):
    pass


class Base(DeclarativeBase):
    pass


@event.listens_for(Session, "before_flush")
def protect_append_only_logs(session: Session, _flush_context, _instances) -> None:
    for row in session.deleted:
        if getattr(row, "__tablename__", None) in APPEND_ONLY_TABLES:
            raise AppendOnlyLogViolation(f"{row.__tablename__} rows are append-only")
    for row in session.dirty:
        if getattr(row, "__tablename__", None) in APPEND_ONLY_TABLES and session.is_modified(row, include_collections=False):
            raise AppendOnlyLogViolation(f"{row.__tablename__} rows are append-only")


DEFAULT_STATEMENT_TIMEOUT_MS = 15000
DEFAULT_LOCK_TIMEOUT_MS = 5000


class Database:
    def __init__(
        self,
        url: str,
        statement_timeout_ms: int = DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = DEFAULT_LOCK_TIMEOUT_MS,
    ):
        self.sqlite_path = self._sqlite_path(url)
        self._secure_sqlite_file(create=True)
        timeouts = (statement_timeout_ms, lock_timeout_ms)
        self.engine = create_engine(url, future=True, hide_parameters=True, **self.engine_options(url, *timeouts))
        self.SessionLocal = sessionmaker(self.engine, expire_on_commit=False, class_=Session)

    @staticmethod
    def engine_options(
        url: str,
        statement_timeout_ms: int = DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = DEFAULT_LOCK_TIMEOUT_MS,
    ) -> dict:
        backend = make_url(url).get_backend_name()
        if backend == "sqlite":
            return {"connect_args": {"check_same_thread": False}}
        if backend == "postgresql":
            # A Patroni failover leaves pooled sockets pointing at the old leader.
            # Ping on checkout, recycle idle connections, and bound connect and
            # dead-peer detection so a worker fails fast instead of hanging.
            # Parameters given in the URL query win over these defaults.
            query = make_url(url).query
            defaults = {
                "connect_timeout": 5,
                "keepalives": 1,
                "keepalives_idle": 10,
                "keepalives_interval": 3,
                "keepalives_count": 3,
                "tcp_user_timeout": 15000,
            }
            connect_args = {key: value for key, value in defaults.items() if key not in query}
            # A live connection blocked on a lock or a slow statement is not a
            # dead peer, so keepalives never end it. Bound both per session.
            # An explicit libpq "options" URL parameter is an operator override.
            if "options" not in query:
                server_options = [
                    f"-c {name}={int(value)}"
                    for name, value in (
                        ("statement_timeout", statement_timeout_ms),
                        ("lock_timeout", lock_timeout_ms),
                    )
                    if value
                ]
                if server_options:
                    connect_args["options"] = " ".join(server_options)
            return {
                "pool_pre_ping": True,
                "pool_recycle": 300,
                "pool_timeout": 10,
                "connect_args": connect_args,
            }
        return {}

    def init(self) -> None:
        from . import models  # noqa: F401

        Base.metadata.create_all(bind=self.engine)
        self.install_schema_compatibility()
        self.install_append_only_guards()
        self._secure_sqlite_file()

    @staticmethod
    def _sqlite_path(url: str) -> Path | None:
        parsed = make_url(url)
        if parsed.get_backend_name() != "sqlite" or not parsed.database or parsed.database == ":memory:":
            return None
        if parsed.database.startswith("file:"):
            query = dict(parsed.query)
            uri = query.get("uri")
            mode = query.get("mode")
            cache = query.get("cache")
            allowed_keys = {"uri", "mode", "cache"}
            if (
                uri != "true"
                or set(query) - allowed_keys
                or cache not in (None, "private", "shared")
            ):
                raise RuntimeError("SQLite file: URLs are restricted to explicit in-memory URIs")

            if parsed.database == "file::memory:":
                if mode not in (None, "memory"):
                    raise RuntimeError("SQLite file: URLs are restricted to explicit in-memory URIs")
                return None

            memory_name = parsed.database.removeprefix("file:")
            if mode == "memory" and memory_name and all(
                character.isalnum() or character in "_.-" for character in memory_name
            ):
                return None
            raise RuntimeError("Disk-backed SQLite file URIs are not supported")
        return Path(parsed.database).absolute()

    def _secure_sqlite_file(self, create: bool = False) -> None:
        path = self.sqlite_path
        if not path:
            return
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            directory_fd = os.open(path.parent, directory_flags)
        except OSError as exc:
            raise RuntimeError("SQLite parent directory must be a real, accessible directory") from exc
        try:
            parent_stat = os.fstat(directory_fd)
            if parent_stat.st_uid != os.geteuid():
                raise RuntimeError("SQLite parent directory must be owned by the service user")
            if not parent_stat.st_mode & stat.S_IWUSR:
                raise RuntimeError("SQLite parent directory must be owner-writable")
            if parent_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise RuntimeError("SQLite parent directory must not be writable by non-owners")

            names = (path.name, f"{path.name}-journal", f"{path.name}-wal", f"{path.name}-shm")
            for index, name in enumerate(names):
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                if create and index == 0:
                    flags |= os.O_CREAT
                try:
                    fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise RuntimeError("SQLite database files must be regular, non-symlink files") from exc
                try:
                    file_stat = os.fstat(fd)
                    if not stat.S_ISREG(file_stat.st_mode):
                        raise RuntimeError("SQLite database files must be regular files")
                    if file_stat.st_uid != os.geteuid():
                        raise RuntimeError("SQLite database files must be owned by the service user")
                    os.fchmod(fd, 0o600)
                finally:
                    os.close(fd)
        finally:
            os.close(directory_fd)

    def install_schema_compatibility(self) -> None:
        with self.engine.begin() as conn:
            dialect = conn.dialect.name
            if dialect == "postgresql":
                # One-time upgrade backfills may legitimately run longer than a
                # request; lock_timeout still bounds waiting on a live peer.
                conn.exec_driver_sql("SET LOCAL statement_timeout = 0")

            def columns_for(table: str) -> set[str]:
                if dialect == "sqlite":
                    return {
                        row["name"]
                        for row in conn.exec_driver_sql(f"PRAGMA table_info({table})").mappings()
                    }
                if dialect == "postgresql":
                    return {
                        row["column_name"]
                        for row in conn.exec_driver_sql(
                            f"""
                            SELECT column_name
                            FROM information_schema.columns
                            WHERE table_name = '{table}'
                            """
                        ).mappings()
                    }
                return set()

            device_columns = columns_for("devices")
            if device_columns and "key_type" not in device_columns:
                conn.exec_driver_sql("ALTER TABLE devices ADD COLUMN key_type VARCHAR(32) NOT NULL DEFAULT 'ed25519'")
            if device_columns and "enrollment_expires_at" not in device_columns:
                column_type = "TIMESTAMP WITH TIME ZONE" if dialect == "postgresql" else "DATETIME"
                conn.exec_driver_sql(f"ALTER TABLE devices ADD COLUMN enrollment_expires_at {column_type}")
                device_columns.add("enrollment_expires_at")
            if {"enrollment_token_hash", "enrollment_expires_at"}.issubset(device_columns):
                # Legacy tokens had no expiry. Invalidate them instead of
                # silently reviving an unbounded enrollment credential.
                conn.exec_driver_sql(
                    """
                    UPDATE devices
                    SET enrollment_token_hash = NULL
                    WHERE enrollment_token_hash IS NOT NULL
                      AND enrollment_expires_at IS NULL
                    """
                )

            user_columns = columns_for("users")
            if user_columns and "totp_last_used_step" not in user_columns:
                conn.exec_driver_sql("ALTER TABLE users ADD COLUMN totp_last_used_step INTEGER")

            integration_columns = columns_for("integrations")
            for column in ("principal_username", "approver_username", "system_name"):
                if integration_columns and column not in integration_columns:
                    conn.exec_driver_sql(f"ALTER TABLE integrations ADD COLUMN {column} VARCHAR(128)")

            for table in ("auth_requests", "auth_log_entries"):
                columns = columns_for(table)
                if columns and "approver_user_id" not in columns:
                    conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN approver_user_id VARCHAR(36)")
                if table == "auth_requests" and columns and "consumed_at" not in columns:
                    column_type = "TIMESTAMP WITH TIME ZONE" if dialect == "postgresql" else "DATETIME"
                    conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN consumed_at {column_type}")
                    if {"status", "created_at", "decided_at"}.issubset(columns):
                        # Approvals created before the consume/ack contract were
                        # already effective. Preserve that historical decision
                        # while preventing it from refreshing a trust window.
                        conn.exec_driver_sql(
                            """
                            UPDATE auth_requests
                            SET consumed_at = COALESCE(decided_at, created_at)
                            WHERE status = 'approved'
                              AND consumed_at IS NULL
                            """
                        )
                if columns:
                    conn.exec_driver_sql(
                        f"CREATE INDEX IF NOT EXISTS ix_{table}_approver_user_id ON {table} (approver_user_id)"
                    )

    def install_append_only_guards(self) -> None:
        with self.engine.begin() as conn:
            dialect = conn.dialect.name
            if dialect == "sqlite":
                for table in APPEND_ONLY_TABLES:
                    for action in ("UPDATE", "DELETE"):
                        conn.exec_driver_sql(
                            f"""
                            CREATE TRIGGER IF NOT EXISTS trg_{table}_append_only_{action.lower()}
                            BEFORE {action} ON {table}
                            BEGIN
                                SELECT RAISE(ABORT, '{table} rows are append-only');
                            END
                            """
                        )
            elif dialect == "postgresql":
                conn.exec_driver_sql(
                    """
                    CREATE OR REPLACE FUNCTION pushgate_append_only_guard()
                    RETURNS trigger
                    LANGUAGE plpgsql
                    AS $$
                    BEGIN
                        RAISE EXCEPTION '%% rows are append-only', TG_TABLE_NAME;
                    END;
                    $$;
                    """
                )
                for table in APPEND_ONLY_TABLES:
                    for action in ("UPDATE", "DELETE"):
                        trigger = f"trg_{table}_append_only_{action.lower()}"
                        conn.exec_driver_sql(
                            f"""
                            DO $$
                            BEGIN
                                IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = '{trigger}') THEN
                                    CREATE TRIGGER {trigger}
                                    BEFORE {action} ON {table}
                                    FOR EACH ROW EXECUTE FUNCTION pushgate_append_only_guard();
                                END IF;
                            END $$;
                            """
                        )

    def session(self) -> Generator[Session, None, None]:
        db = self.SessionLocal()
        try:
            yield db
        finally:
            db.close()
