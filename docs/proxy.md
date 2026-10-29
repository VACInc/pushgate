# Optional identity proxy

The default admin login uses a bearer API key. Proxy authentication is disabled.
To opt in, set `PUSHGATE_TRUSTED_PROXY_AUTH_ENABLED=true`, a unique random `PUSHGATE_TRUSTED_PROXY_AUTH_SECRET`, username/group header names, and allowed admin groups.
The proxy must strip all incoming identity headers and `X-PushGate-Proxy-Secret`, authenticate the user, then inject its own values. Only the proxy may reach the backend.
A group assertion plus matching shared secret grants the configured role. A compromised proxy can therefore administer this service.
The generic signed verification adapter is `POST /api/v1/proxy/verify`. It uses integration HMAC authentication and the normal approval/consumption rules.
The optional Traefik example needs an operator-provided ForwardAuth URL and external network. It is not required by the quick start.
