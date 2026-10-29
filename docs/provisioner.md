# Creation-only integration provisioner

An operator with admin permission issues a service key using
`POST /api/admin/rbac/provisioners`:

```json
{"name":"Automation PushGate Provisioner","principal_username":"serviceuser","approver_username":"operator","systems":["server01"]}
```

Both usernames must already exist. `systems` is an exact, lowercase hostname
allowlist, not a pattern. No user/device/factor is created. Store the response's
`data.token` once in a protected secret consumer. Never log the response.
The general API-key endpoint cannot supply scope. A key assigned the new role
without an issued scope fails closed. Scope is immutable; normal operator API-key
PATCH can disable the key. Changing its role does not remove its restriction.

With the issued bearer, `GET /api/admin/whoami` returns safe effective permissions,
key ID, canonical scope and capability summary. No token, hash or user factor is
returned. All global read/write/admin bits are false. The only permitted routes:

* GET `/api/admin/integrations`: metadata for allowlisted systems, including
  conflicting legacy bindings so clients can stop rather than duplicate them.
* GET `/api/admin/integrations/{id}`: same metadata boundary.
* POST `/api/admin/integrations`: exact principal/approver; allowed system;
  `name: "SSH <system>"`, `system_type: "linux-pam"`, `fail_mode: "closed"`,
  `enabled: true`. No supplied client ID or extra fields. Returns the generated
  integration secret once, as with the existing creation API.
* PATCH `/api/admin/integrations/{id}`: exactly `{"enabled":false}` for an
  integration created by that same key. Not adoption, rebinding, rotation,
  re-enabling, or deletion. Rollback does not release the system reservation.

Reusing metadata does NOT validate a stored client secret. A signed preflight is
still required. Existing integrations retain their existing authentication
behavior; adoption does not automatically make a legacy integration online-only.

New provisioned integrations permanently require online push approval. The server
never returns principal TOTP seeds or backup hashes in their auth cache, rejects
submitted offline factors, disables trusted-session reuse, and forces effective
fail-closed even if user/global policies say open. Normal device-signature
validation remains necessary to approve. Provisioner bearer alone is not a device
credential. Compromising a PAM host can bypass its local client; this API boundary
is not a claim of endpoint integrity or end-to-end approval isolation.

## Persistence and deployment

Two additive tables (`provisioner_scopes`, `provisioned_integrations`) are created
by the existing `Database.init()` / `Base.metadata.create_all()` startup path.
There are no new columns, rewrites or backfills. Existing records remain unchanged.
Only SQLite and PostgreSQL support reservation locking. Scoped creations reserve
system names with a unique primary key; every native create and rebind participates
in a database transaction lock. Existing unreserved legacy duplicates are preserved
but prevent scoped creation. Provisioned bindings cannot be edited through general
write routes either. Do not run old and new application versions concurrently after
issuance: an older version does not know these enforcement rules.

After independently reviewing the exact commit, on the operator-selected checkout
and preserved Compose environment, build and replace only the application service:

```sh
docker compose -f deploy/docker-compose.yml build server
docker compose -f deploy/docker-compose.yml up -d --no-deps server
```

Startup performs the additive migration. Verify health and revision before issuing
a key, then verify its whoami scope using the same stored token. Do not downgrade
to old server code while provisioner-created integration credentials remain usable.
No destructive down migration is supplied. Backups, source deployment, credentials,
SSH identity restrictions and final live proof are operator responsibilities.

## Attestation and contention

Integration list/get/create/patch metadata now includes `online_only`, derived
exclusively from the durable server reservation. Signed `/api/v1/auth/preflight`
returns the same boolean at `data.online_only`. A dedicated no-factor workflow
must require literal `true` in metadata AND signed preflight before distributing
or using a pair. False/missing is a hard stop, not authorization to migrate a
legacy integration. Client-supplied flags cannot establish this property.

Creation and PATCH run their complete SQL transaction in synchronous worker
endpoints; an async dependency only reads raw JSON before endpoint execution.
No database lock is held across a route await. PostgreSQL provisioning locks
have a transaction-local five-second timeout. SQLite uses its driver's default
five-second busy timeout. Recognized lock contention returns 503 `database_busy`,
not an unhandled server error; no automatic replay is performed. Reconcile
metadata/ownership after any failed or ambiguous creation before retrying.
