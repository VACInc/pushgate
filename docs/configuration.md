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

## Proxy authentication and CSRF

Proxy-authenticated `POST`, `PUT`, `PATCH` and `DELETE` requests must include
`X-PushGate-CSRF: 1`. The admin web client sends it automatically, including
bodyless writes. Other proxy-authenticated clients must set it themselves.
Missing or incorrect values return 403 before the operation. Reads and direct
bearer/API-key automation do not require this header; proxy identity still takes
precedence when both authentication mechanisms are present.

Keep CORS origins explicit and limited to trusted admin UI origins. Never allow
wildcard origins or a broad origin regex: the custom header forces a browser
preflight, which must reject hostile origins. The identity proxy must forward
this client header, never inject it automatically. Keep stripping untrusted
identity assertions and validating the proxy secret and administrator groups.

## Requester names

Login helpers send the connecting client as `source_ip`, and the phone shows it as
`... from <source>`. When `PUSHGATE_SOURCE_NAME_SUFFIX` is set, the server turns a
raw address into the shortest machine name under that DNS suffix, so every helper
shows the same short name without a per-host change. A helper that already sent a
name is left alone.

| Setting | Default | Meaning |
| --- | --- | --- |
| `PUSHGATE_SOURCE_NAME_LOOKUP` | `true` | Master switch. `false` shows every source as sent. |
| `PUSHGATE_SOURCE_NAME_SUFFIX` | empty | DNS suffix of machine names, for example `lan.example.test`. Empty turns the lookup off. |
| `PUSHGATE_SOURCE_NAME_RESOLVERS` | empty | Comma list of DNS servers, `host[:port]` or `[v6]:port`, asked in order. Empty uses the system resolver. |
| `PUSHGATE_SOURCE_NAME_TIMEOUT_MS` | `300` | Longest a login waits for a name. A slower lookup finishes in the background and that login shows the address. |
| `PUSHGATE_SOURCE_NAME_QUERY_TIMEOUT_MS` | `1000` | Per-resolver query timeout for the background lookup. |
| `PUSHGATE_SOURCE_NAME_TTL_SECONDS` | `3600` | How long a name is cached. An expired name is still shown while it is refreshed. |
| `PUSHGATE_SOURCE_NAME_NEGATIVE_TTL_SECONDS` | `60` | How long a failed lookup is cached. |

A reverse (PTR) name is used only when it is under the suffix and resolves forward
to the same address; among several, the shortest wins. The name is display only:
request dedupe and trusted sessions keep the value the helper sent, the auth log
keeps the raw `source_ip` and records the shown name as `detail.source_name`.
Addresses seen in the last week are looked up at startup. Each new pending request
logs one `pushgate.source` line, `push_text request=<id> text=<user> requests
<service> on <system> from <source>`, so the shown text can be checked in the
server log.
