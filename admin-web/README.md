# PushGate Admin Web

Small React console for the Admin API.

## Run

```sh
npm install
npm run dev
```

Set the API URL and bearer token in the top bar. Configure a strong `PUSHGATE_BOOTSTRAP_TOKEN` on the server first; there is no usable default, and common placeholder values are rejected.

In the production Docker image, the admin web is served by the API container and defaults to same-origin requests. When Traefik/Identity proxy proxy auth is enabled, the token can be left blank because Identity proxy headers authorize `/api/admin/*`.

## API coverage

- Reads and manages global settings, users, groups, devices, integrations, policies, RBAC roles, API keys, backup codes, auth logs, and audit logs.
- Shows one-time device enrollment payloads, integration secrets, API tokens, TOTP secrets, and generated backup codes returned by the API.
