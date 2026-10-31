from typing import Any, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


MIN_BOOTSTRAP_TOKEN_LENGTH = 32
INSECURE_BOOTSTRAP_TOKENS = frozenset({"dev-admin", "change-me", "replace-me"})


def _setting(name: str, default: Any, **constraints: Any) -> Any:
    """Use the PushGate environment setting name."""
    return Field(
        default,
        validation_alias=f"PUSHGATE_{name}",
        **constraints,
    )


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PUSHGATE_",
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )

    database_url: str = _setting("DATABASE_URL", "sqlite:///./pushgate.db")
    redis_url: str | None = _setting("REDIS_URL", None)
    bootstrap_token: str | None = _setting("BOOTSTRAP_TOKEN", None)
    auth_ttl_seconds: int = _setting("AUTH_TTL_SECONDS", 60, ge=1, le=600)
    hmac_window_seconds: int = _setting("HMAC_WINDOW_SECONDS", 300, ge=1, le=3600)
    global_fail_mode: Literal["open", "closed"] = _setting("GLOBAL_FAIL_MODE", "closed")
    push_retry_count: int = _setting("PUSH_RETRY_COUNT", 1, ge=0, le=10)
    require_biometric: bool = _setting("REQUIRE_BIOMETRIC", False)
    trusted_session_window_seconds: int = _setting("TRUSTED_SESSION_WINDOW_SECONDS", 0, ge=0, le=2592000)
    enrollment_token_ttl_seconds: int = _setting("ENROLLMENT_TOKEN_TTL_SECONDS", 600, ge=1, le=86400)
    server_name: str = _setting("SERVER_NAME", "pushgate")
    syslog_enabled: bool = _setting("SYSLOG_ENABLED", False)
    syslog_host: str = _setting("SYSLOG_HOST", "127.0.0.1")
    syslog_port: int = _setting("SYSLOG_PORT", 514, ge=1, le=65535)
    fcm_project_id: str | None = _setting("FCM_PROJECT_ID", None)
    fcm_access_token: str | None = _setting("FCM_ACCESS_TOKEN", None)
    fcm_endpoint: str = _setting(
        "FCM_ENDPOINT", "https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
    )
    # Optional private ntfy wake-up (works without FCM): a topic URL such as
    # https://ntfy.example/pushgate, an Authorization header value ("Basic ..."
    # or "Bearer tk_..."), and an ntfy priority name. One notification per
    # push attempt tells the approver to open the app; it carries no request
    # id, secret, or approval capability.
    ntfy_url: str | None = _setting("NTFY_URL", None)
    ntfy_auth: str | None = _setting("NTFY_AUTH", None)
    ntfy_priority: str = _setting("NTFY_PRIORITY", "high")
    # UnifiedPush (self-hosted ntfy as distributor): optional Authorization
    # header value sent only to endpoints on this host.
    unifiedpush_auth: str | None = _setting("UNIFIEDPUSH_AUTH", None)
    unifiedpush_auth_host: str | None = _setting("UNIFIEDPUSH_AUTH_HOST", None)
    # Comma-separated hosts a device may register as its UnifiedPush endpoint.
    # Empty disables endpoint registration and delivery. Configure only trusted
    # distributor hosts; their DNS and network routes must also be trusted.
    unifiedpush_allowed_hosts: str | None = _setting("UNIFIEDPUSH_ALLOWED_HOSTS", None)
    # Bound every application SQL statement and row/table lock wait (PostgreSQL
    # only). Keep both below the PAM helper's 70 s deadline; 0 disables one.
    # An explicit libpq "options" parameter in the database URL wins.
    db_statement_timeout_ms: int = _setting("DB_STATEMENT_TIMEOUT_MS", 15000, ge=0, le=600000)
    db_lock_timeout_ms: int = _setting("DB_LOCK_TIMEOUT_MS", 5000, ge=0, le=600000)
    # Connected phone streams re-read pending/settled requests from the shared
    # database this often, so events published on another edge still arrive.
    ws_reconcile_seconds: float = _setting("WS_RECONCILE_SECONDS", 5.0, ge=0.1, le=300)
    # Requester names: when a login helper sends a raw client address as source_ip, show the
    # shortest machine name under SOURCE_NAME_SUFFIX instead (PTR, confirmed forward). An empty
    # suffix leaves every source as sent. RESOLVERS is a comma list of DNS servers (host[:port]);
    # empty uses the system resolver. A login waits at most TIMEOUT_MS for a name, then shows the
    # address while the lookup finishes in the background. Display only: dedupe and trusted
    # sessions keep the value the helper sent.
    source_name_lookup: bool = _setting("SOURCE_NAME_LOOKUP", True)
    source_name_suffix: str = _setting("SOURCE_NAME_SUFFIX", "")
    source_name_resolvers: str = _setting("SOURCE_NAME_RESOLVERS", "")
    source_name_timeout_ms: int = _setting("SOURCE_NAME_TIMEOUT_MS", 300, ge=0, le=5000)
    source_name_query_timeout_ms: int = _setting("SOURCE_NAME_QUERY_TIMEOUT_MS", 1000, ge=50, le=10000)
    source_name_ttl_seconds: int = _setting("SOURCE_NAME_TTL_SECONDS", 3600, ge=1, le=604800)
    source_name_negative_ttl_seconds: int = _setting("SOURCE_NAME_NEGATIVE_TTL_SECONDS", 60, ge=1, le=86400)
    rate_limit_per_minute: int = _setting("RATE_LIMIT_PER_MINUTE", 600, ge=1, le=100000)
    rate_limit_window_seconds: int = _setting("RATE_LIMIT_WINDOW_SECONDS", 60, ge=1, le=3600)
    static_dir: str | None = _setting("STATIC_DIR", None)
    trusted_proxy_auth_enabled: bool = _setting("TRUSTED_PROXY_AUTH_ENABLED", False)
    trusted_proxy_auth_secret: str | None = _setting("TRUSTED_PROXY_AUTH_SECRET", None, min_length=16)
    trusted_proxy_auth_username_header: str = _setting(
        "TRUSTED_PROXY_AUTH_USERNAME_HEADER", "x-proxy-username"
    )
    trusted_proxy_auth_groups_header: str = _setting(
        "TRUSTED_PROXY_AUTH_GROUPS_HEADER", "x-proxy-groups"
    )
    trusted_proxy_auth_admin_groups: str = _setting(
        "TRUSTED_PROXY_AUTH_ADMIN_GROUPS", "pushgate-admins"
    )
    trusted_proxy_auth_role: str = _setting("TRUSTED_PROXY_AUTH_ROLE", "admin")
    api_docs_enabled: bool = _setting("API_DOCS_ENABLED", False)
    cors_allow_origins: str = _setting(
        "CORS_ALLOW_ORIGINS",
        "",
    )
    cors_allow_origin_regex: str | None = _setting(
        "CORS_ALLOW_ORIGIN_REGEX",
        None,
    )

    @field_validator("source_name_resolvers")
    @classmethod
    def validate_source_name_resolvers(cls, value: str) -> str:
        from .source_names import parse_resolvers

        parse_resolvers(value)
        return value

    @field_validator("bootstrap_token")
    @classmethod
    def validate_bootstrap_token(cls, value: str | None) -> str | None:
        # An omitted or explicitly empty token disables bootstrap access for
        # direct, non-Compose deployments. Any enabled token must be strong.
        if value is None or value == "":
            return value
        if value != value.strip():
            raise ValueError("bootstrap token must not have surrounding whitespace")
        if value.casefold() in INSECURE_BOOTSTRAP_TOKENS:
            raise ValueError("bootstrap token must not be a placeholder")
        if len(value) < MIN_BOOTSTRAP_TOKEN_LENGTH:
            raise ValueError(
                f"bootstrap token must be at least {MIN_BOOTSTRAP_TOKEN_LENGTH} characters"
            )
        return value
