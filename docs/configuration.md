# Server configuration

Environment variables take precedence over `.env`. Use `PUSHGATE_` setting names. `None` means unset. Secret values are never example credentials.

| Variable | Default | Bounds |
| --- | --- | --- |
| `PUSHGATE_DATABASE_URL` | `sqlite:///./pushgate.db` |  |
| `PUSHGATE_REDIS_URL` | `None` |  |
| `PUSHGATE_BOOTSTRAP_TOKEN` | `None` |  |
| `PUSHGATE_AUTH_TTL_SECONDS` | `60` | ge=1, le=600 |
| `PUSHGATE_HMAC_WINDOW_SECONDS` | `300` | ge=1, le=3600 |
| `PUSHGATE_GLOBAL_FAIL_MODE` | `closed` |  |
| `PUSHGATE_PUSH_RETRY_COUNT` | `1` | ge=0, le=10 |
| `PUSHGATE_REQUIRE_BIOMETRIC` | `False` |  |
| `PUSHGATE_TRUSTED_SESSION_WINDOW_SECONDS` | `0` | ge=0, le=2592000 |
| `PUSHGATE_ENROLLMENT_TOKEN_TTL_SECONDS` | `600` | ge=1, le=86400 |
| `PUSHGATE_SERVER_NAME` | `pushgate` |  |
| `PUSHGATE_SYSLOG_ENABLED` | `False` |  |
| `PUSHGATE_SYSLOG_HOST` | `127.0.0.1` |  |
| `PUSHGATE_SYSLOG_PORT` | `514` | ge=1, le=65535 |
| `PUSHGATE_FCM_PROJECT_ID` | `None` |  |
| `PUSHGATE_FCM_ACCESS_TOKEN` | `None` |  |
| `PUSHGATE_FCM_ENDPOINT` | `https://fcm.googleapis.com/v1/projects/{project_id}/messages:send` |  |
| `PUSHGATE_NTFY_URL` | `None` |  |
| `PUSHGATE_NTFY_AUTH` | `None` |  |
| `PUSHGATE_NTFY_PRIORITY` | `high` |  |
| `PUSHGATE_UNIFIEDPUSH_AUTH` | `None` |  |
| `PUSHGATE_UNIFIEDPUSH_AUTH_HOST` | `None` |  |
| `PUSHGATE_UNIFIEDPUSH_ALLOWED_HOSTS` | `None` |  |
| `PUSHGATE_DB_STATEMENT_TIMEOUT_MS` | `15000` | ge=0, le=600000 |
| `PUSHGATE_DB_LOCK_TIMEOUT_MS` | `5000` | ge=0, le=600000 |
| `PUSHGATE_WS_RECONCILE_SECONDS` | `5.0` | ge=0.1, le=300 |
| `PUSHGATE_RATE_LIMIT_PER_MINUTE` | `600` | ge=1, le=100000 |
| `PUSHGATE_RATE_LIMIT_WINDOW_SECONDS` | `60` | ge=1, le=3600 |
| `PUSHGATE_STATIC_DIR` | `None` |  |
| `PUSHGATE_TRUSTED_PROXY_AUTH_ENABLED` | `False` |  |
| `PUSHGATE_TRUSTED_PROXY_AUTH_SECRET` | `None` | min_length=16 |
| `PUSHGATE_TRUSTED_PROXY_AUTH_USERNAME_HEADER` | `x-proxy-username` |  |
| `PUSHGATE_TRUSTED_PROXY_AUTH_GROUPS_HEADER` | `x-proxy-groups` |  |
| `PUSHGATE_TRUSTED_PROXY_AUTH_ADMIN_GROUPS` | `pushgate-admins` |  |
| `PUSHGATE_TRUSTED_PROXY_AUTH_ROLE` | `admin` |  |
| `PUSHGATE_API_DOCS_ENABLED` | `False` |  |
| `PUSHGATE_CORS_ALLOW_ORIGINS` | `` |  |
| `PUSHGATE_CORS_ALLOW_ORIGIN_REGEX` | `None` |  |

Use a private owner-only directory for SQLite. Database URLs and notification credentials are secrets. Protect `.env` with mode 0600; do not commit it. For PostgreSQL, zero disables a timeout and explicit URL `options` overrides the defaults.
