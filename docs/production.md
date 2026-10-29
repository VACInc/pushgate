# Production operation

Use HTTPS for phone enrollment and PAM traffic. Keep the backend bound to loopback or a private container network and expose it only through a TLS reverse proxy. Do not publish the database or Redis ports.
Back up the SQL database and secret configuration together before any upgrade. Startup performs additive schema migrations; rehearse upgrades against a copy and never overwrite live state with an older database.
Use one server process for SQLite. PostgreSQL is the supported shared database for multiple processes; Redis supplies low-latency fanout, while SQL reconciliation repairs missed stream events.
`/healthz` measures application liveness only, not database readiness. Monitor both and alert on failed delivery, rate limits and database errors. SQL statement and lock limits default to 15 and 5 seconds.
The built-in limiter is bounded in-memory per process. Configure reverse-proxy rate and connection limits as well, especially for multiple instances and WebSockets. Trust forwarded client IP headers only from your known proxy.
Keep enrollment QR codes, integration HMAC credentials, API keys, phone signing keys and database backups private. Revoke lost devices and lock users promptly. SQL bind parameters are hidden in errors, but request metadata remains sensitive.
Default fail mode is closed. Trusted sessions are disabled. Avoid fail-open, offline factors and trusted sessions on SSH integrations; `online_only` provisioning enforces this. Keep a separately tested local recovery console before changing PAM.
Use your own signing identity for Android releases. A release signed by a different key is a separate application trust decision.
See [proxy configuration](proxy.md) and [configuration reference](configuration.md).
