from __future__ import annotations

import json
import re
import secrets
import asyncio
import ipaddress
import math
import time
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from .config import Settings
from .db import Database
from .delivery_watch import UnansweredWatch
from .ephemeral import build_auth_state
from .models import ApiKey, AuditLog, AuthLogEntry, AuthRequest, BackupCode, Device, DeviceNonce, Group, Integration, Nonce, Policy, ProvisionerScope, ProvisionedIntegration, Role, Setting, User, UserGroup, now
from .source_names import LOG as SOURCE_LOG, ensure_log_handler, resolver_from_settings
from .push import FanoutDisconnected, build_push_fanout, build_push_provider, unifiedpush_endpoint_allowed
from .security import (
    DEVICE_KEY_TYPE_ED25519,
    DEVICE_KEY_TYPE_ECDSA_P256,
    constant_eq,
    generate_backup_codes,
    hash_value,
    integration_signature,
    is_valid_device_public_key,
    matching_totp_counter,
    new_totp_secret,
    normalize_device_key_type,
    random_secret,
    totp_uri,
    utcnow,
    verify_device_signature,
    verify_device_message_signature,
)
from .syslog_export import SyslogExporter


class UserIn(BaseModel):
    username: str
    display_name: str | None = None
    fail_mode: str | None = Field(default=None, pattern="^(open|closed)$")
    locked: bool = False


class UserPatch(BaseModel):
    display_name: str | None = None
    fail_mode: str | None = Field(default=None, pattern="^(open|closed)$")
    locked: bool | None = None


class GroupIn(BaseModel):
    name: str
    description: str | None = None


class GroupPatch(BaseModel):
    name: str | None = None
    description: str | None = None


class DeviceIn(BaseModel):
    user_id: str
    name: str
    kind: str = Field(default="phone", pattern="^(phone|wear)$")
    key_type: str = Field(default=DEVICE_KEY_TYPE_ED25519, pattern="^(ed25519|ecdsa_p256)$")
    public_key: str | None = Field(default=None, min_length=1)
    push_token: str | None = None
    require_biometric: bool = False


class DevicePatch(BaseModel):
    name: str | None = None
    key_type: str | None = Field(default=None, pattern="^(ed25519|ecdsa_p256)$")
    public_key: str | None = Field(default=None, min_length=1)
    push_token: str | None = None
    revoked: bool | None = None
    require_biometric: bool | None = None


class IntegrationIn(BaseModel):
    name: str
    client_id: str | None = None
    system_type: str = Field(default="linux-pam", min_length=1, max_length=64)
    principal_username: str | None = Field(default=None, min_length=1, max_length=128)
    approver_username: str | None = Field(default=None, min_length=1, max_length=128)
    system_name: str | None = Field(default=None, min_length=1, max_length=128)
    fail_mode: str | None = Field(default=None, pattern="^(open|closed)$")
    enabled: bool = True


class IntegrationPatch(BaseModel):
    name: str | None = None
    principal_username: str | None = Field(default=None, min_length=1, max_length=128)
    approver_username: str | None = Field(default=None, min_length=1, max_length=128)
    system_name: str | None = Field(default=None, min_length=1, max_length=128)
    fail_mode: str | None = Field(default=None, pattern="^(open|closed)$")
    enabled: bool | None = None


class PolicyIn(BaseModel):
    name: str
    description: str | None = None
    subject_type: str = Field(pattern="^(global|user|integration)$")
    subject_id: str | None = None
    fail_mode: str | None = Field(default=None, pattern="^(open|closed)$")
    auth_ttl_seconds: int | None = Field(default=None, ge=5, le=600)
    push_retry_count: int | None = Field(default=None, ge=0, le=10)
    require_biometric: bool | None = None
    trusted_session_window_seconds: int | None = Field(default=None, ge=0, le=2592000)
    enabled: bool = True


class PolicyPatch(BaseModel):
    name: str | None = None
    description: str | None = None
    fail_mode: str | None = Field(default=None, pattern="^(open|closed)$")
    auth_ttl_seconds: int | None = Field(default=None, ge=5, le=600)
    push_retry_count: int | None = Field(default=None, ge=0, le=10)
    require_biometric: bool | None = None
    trusted_session_window_seconds: int | None = Field(default=None, ge=0, le=2592000)
    enabled: bool | None = None


class RoleIn(BaseModel):
    name: str
    description: str | None = None
    permissions: dict[str, bool] = Field(default_factory=dict)
    enabled: bool = True


class RolePatch(BaseModel):
    description: str | None = None
    permissions: dict[str, bool] | None = None
    enabled: bool | None = None


class ApiKeyIn(BaseModel):
    name: str
    role: str = "read-only"


class ProvisionerIn(BaseModel):
    model_config = {"extra": "forbid", "strict": True}
    name: str = Field(min_length=1, max_length=128)
    principal_username: str = Field(min_length=1, max_length=128)
    approver_username: str = Field(min_length=1, max_length=128)
    systems: list[str] = Field(min_length=1, max_length=512)


class ApiKeyPatch(BaseModel):
    name: str | None = None
    role: str | None = None
    enabled: bool | None = None


class GlobalSettingsPatch(BaseModel):
    global_fail_mode: str | None = Field(default=None, pattern="^(open|closed)$")
    auth_ttl_seconds: int | None = Field(default=None, ge=5, le=600)
    push_retry_count: int | None = Field(default=None, ge=0, le=10)
    require_biometric: bool | None = None
    trusted_session_window_seconds: int | None = Field(default=None, ge=0, le=2592000)


class DecisionIn(BaseModel):
    device_id: str
    decision: str = Field(pattern="^(approve|deny)$")
    signature: str
    biometric_verified: bool = False


class DeviceEnrollIn(BaseModel):
    enrollment_token: str
    public_key: str = Field(min_length=1)
    key_type: str = Field(default=DEVICE_KEY_TYPE_ED25519, pattern="^(ed25519|ecdsa_p256)$")
    push_token: str | None = None


class DevicePushTokenIn(BaseModel):
    push_token: str
    timestamp: str
    nonce: str
    signature: str


BUILT_IN_ROLES: dict[str, dict[str, Any]] = {
    "integration-provisioner": {"read": False, "write": False, "admin": False},
    "read-only": {"read": True, "write": False, "admin": False},
    "read-write": {"read": True, "write": True, "admin": False},
    "admin": {"read": True, "write": True, "admin": True},
}


def envelope(data: Any, **meta: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"data": data}
    if meta:
        out["meta"] = meta
    return out


def aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def utc_iso(dt: datetime) -> str:
    return aware(dt).astimezone(timezone.utc).isoformat()


def query_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=422, detail={"code": "bad_datetime", "message": "datetime must be ISO-8601"}) from None
    if dt.tzinfo:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def csv_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def group_list(value: str | None) -> set[str]:
    if not value:
        return set()
    normalized = value.replace("|", ",").replace(";", ",")
    return {item.strip() for item in normalized.split(",") if item.strip()}


def obj(model: Any, include_secret: bool = False) -> dict[str, Any]:
    data = {c.name: getattr(model, c.name) for c in model.__table__.columns}
    if isinstance(model, Device):
        data["push_token_configured"] = bool(data.get("push_token"))
    for key, value in list(data.items()):
        if isinstance(value, datetime):
            data[key] = utc_iso(value)
    if not include_secret:
        data.pop("secret", None)
        data.pop("token_hash", None)
        data.pop("totp_secret", None)
        data.pop("enrollment_token_hash", None)
        data.pop("code_hash", None)
        data.pop("push_token", None)
    return data


def auth_log_obj(row: AuthLogEntry) -> dict[str, Any]:
    data = obj(row)
    data["log_id"] = data.pop("id")
    data["id"] = data.pop("auth_request_id")
    return data


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    if settings.trusted_proxy_auth_enabled and not settings.trusted_proxy_auth_secret:
        raise RuntimeError("trusted proxy authentication requires PUSHGATE_TRUSTED_PROXY_AUTH_SECRET")
    db_handle = Database(settings.database_url, settings.db_statement_timeout_ms, settings.db_lock_timeout_ms)
    db_handle.init()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.loop = asyncio.get_running_loop()
        app.state.expirer_task = asyncio.create_task(expire_pending_loop())
        app.state.source_prewarm_task = asyncio.create_task(prewarm_source_names())
        try:
            yield
        finally:
            for task in (app.state.expirer_task, getattr(app.state, "source_prewarm_task", None)):
                if task:
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task
            app.state.source_names.close()

    app = FastAPI(
        title="PushGate API",
        version="1.0.2",
        description="Self-hosted push MFA Admin and authentication API.",
        lifespan=lifespan,
        docs_url="/docs" if settings.api_docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.api_docs_enabled else None,
    )
    app.state.db = db_handle
    app.state.settings = settings
    app.state.auth_state = build_auth_state(settings.redis_url)
    app.state.unanswered_watch = UnansweredWatch()
    app.state.source_names = resolver_from_settings(settings)
    if app.state.source_names.enabled:
        ensure_log_handler()
    app.state.push_fanout = build_push_fanout(settings.redis_url)
    app.state.push_provider = build_push_provider(
        settings.fcm_access_token,
        settings.fcm_project_id,
        settings.fcm_endpoint,
        settings.ntfy_url,
        settings.ntfy_auth,
        settings.ntfy_priority,
        settings.unifiedpush_auth,
        settings.unifiedpush_auth_host,
        settings.unifiedpush_allowed_hosts,
    )
    app.state.syslog = SyslogExporter(settings.syslog_enabled, settings.syslog_host, settings.syslog_port, settings.server_name)
    app.state.expirer_task = None
    app.state.rate_limits = {}

    app.add_middleware(
        CORSMiddleware,
        allow_origins=csv_list(settings.cors_allow_origins),
        allow_origin_regex=settings.cors_allow_origin_regex or None,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def rate_limit_key(request: Request) -> str:
        host = request.client.host if request.client else "unknown"
        proxy_secret = request.headers.get("x-pushgate-proxy-secret")
        forwarded_for = request.headers.get("x-forwarded-for")
        if (
            settings.trusted_proxy_auth_secret
            and proxy_secret
            and constant_eq(proxy_secret, settings.trusted_proxy_auth_secret)
            and forwarded_for
        ):
            # Traefik appends its direct peer to any client-supplied chain. Trust
            # only the rightmost address, and only after authenticating Traefik.
            candidate = forwarded_for.rsplit(",", 1)[-1].strip()
            try:
                host = ipaddress.ip_address(candidate).compressed
            except ValueError:
                pass
        return "ip:" + host

    def rate_limit_headers(remaining: int, reset_at: float) -> dict[str, str]:
        return {
            "X-RateLimit-Limit": str(settings.rate_limit_per_minute),
            "X-RateLimit-Remaining": str(max(0, remaining)),
            "X-RateLimit-Reset": str(int(reset_at)),
        }

    def response_contains_sensitive_data(path: str) -> bool:
        return path.startswith(("/api/admin/", "/api/v1/auth/", "/api/v1/proxy/"))

    @app.middleware("http")
    async def enforce_rate_limit(request: Request, call_next):
        if request.url.path == "/healthz":
            return await call_next(request)
        now_ts = time.time()
        window = max(1, settings.rate_limit_window_seconds)
        limit = max(1, settings.rate_limit_per_minute)
        if len(app.state.rate_limits) > 1024:
            app.state.rate_limits = {
                item_key: item
                for item_key, item in app.state.rate_limits.items()
                if item[0] > now_ts
            }
        key = rate_limit_key(request)
        if key not in app.state.rate_limits and len(app.state.rate_limits) >= 1024:
            oldest_key = min(app.state.rate_limits, key=lambda item_key: app.state.rate_limits[item_key][0])
            app.state.rate_limits.pop(oldest_key, None)
        reset_at, count = app.state.rate_limits.get(key, (now_ts + window, 0))
        if now_ts >= reset_at:
            reset_at, count = now_ts + window, 0
        count += 1
        app.state.rate_limits[key] = (reset_at, count)
        remaining = limit - count
        headers = rate_limit_headers(remaining, reset_at)
        if count > limit:
            headers["Retry-After"] = str(max(1, int(reset_at - now_ts)))
            response = JSONResponse(status_code=429, content={"detail": {"code": "rate_limited", "message": "rate limit exceeded"}}, headers=headers)
            if response_contains_sensitive_data(request.url.path):
                response.headers["Cache-Control"] = "no-store"
            return response

        response = await call_next(request)
        if response_contains_sensitive_data(request.url.path):
            response.headers["Cache-Control"] = "no-store"
        for name, value in headers.items():
            response.headers.setdefault(name, value)
        return response

    def get_db():
        yield from db_handle.session()

    def audit(db: Session, actor: str, action: str, resource_type: str, resource_id: str | None = None, detail: dict | None = None) -> None:
        row = AuditLog(actor=actor, action=action, resource_type=resource_type, resource_id=resource_id, detail=detail or {})
        db.add(row)
        app.state.syslog.emit(
            "audit",
            {"actor": actor, "action": action, "resource_type": resource_type, "resource_id": resource_id, "detail": detail or {}},
        )

    def device_audit_changes(changes: dict[str, Any]) -> dict[str, Any]:
        safe_changes = dict(changes)
        if "push_token" in safe_changes:
            safe_changes["push_token_configured"] = bool(safe_changes.pop("push_token"))
        return safe_changes

    def append_auth_log(db: Session, auth_req: AuthRequest) -> None:
        db.add(
            AuthLogEntry(
                auth_request_id=auth_req.id,
                user_id=auth_req.user_id,
                approver_user_id=auth_req.approver_user_id,
                integration_id=auth_req.integration_id,
                username=auth_req.username,
                system=auth_req.system,
                pam_service=auth_req.pam_service,
                source_ip=auth_req.source_ip,
                status=auth_req.status,
                factor=auth_req.factor,
                fail_mode_effective=auth_req.fail_mode_effective,
                detail=auth_req.detail,
                decided_at=auth_req.decided_at,
                approved_by_device_id=auth_req.approved_by_device_id,
            )
        )

    def default_settings(db: Session) -> dict[str, Any]:
        row = db.get(Setting, "global")
        if row:
            return row.value
        value = {
            "global_fail_mode": settings.global_fail_mode,
            "auth_ttl_seconds": settings.auth_ttl_seconds,
            "push_retry_count": settings.push_retry_count,
            "require_biometric": settings.require_biometric,
            "trusted_session_window_seconds": settings.trusted_session_window_seconds,
        }
        db.add(Setting(key="global", value=value))
        try:
            db.commit()
        except IntegrityError:
            # A concurrent worker created the row first; use the stored value.
            db.rollback()
            row = db.get(Setting, "global", populate_existing=True)
            if not row:
                raise
            return row.value
        return value

    def policy_subject_key(subject_type: str, subject_id: str | None) -> str:
        return "global" if subject_type == "global" else str(subject_id)

    def validate_policy_subject(db: Session, subject_type: str, subject_id: str | None) -> str:
        if subject_type == "global":
            if subject_id:
                raise HTTPException(status_code=422, detail={"code": "bad_policy_subject", "message": "global policies must not include subject_id"})
            return "global"
        if not subject_id:
            raise HTTPException(status_code=422, detail={"code": "bad_policy_subject", "message": f"{subject_type} policies require subject_id"})
        model = User if subject_type == "user" else Integration
        if not db.get(model, subject_id):
            raise HTTPException(status_code=404, detail={"code": f"{subject_type}_not_found"})
        return subject_id

    def active_policy(db: Session, subject_type: str, subject_id: str | None = None) -> Policy | None:
        return db.scalar(
            select(Policy).where(
                Policy.subject_type == subject_type,
                Policy.subject_key == policy_subject_key(subject_type, subject_id),
                Policy.enabled.is_(True),
            )
        )

    def policy_settings(policy: Policy | None) -> dict[str, Any]:
        if not policy:
            return {}
        values = {
            "global_fail_mode": policy.fail_mode,
            "auth_ttl_seconds": policy.auth_ttl_seconds,
            "push_retry_count": policy.push_retry_count,
            "require_biometric": policy.require_biometric,
            "trusted_session_window_seconds": policy.trusted_session_window_seconds,
        }
        return {key: value for key, value in values.items() if value is not None}

    def effective_settings(db: Session, user: User | None = None, integration: Integration | None = None) -> dict[str, Any]:
        current = dict(default_settings(db))
        current.update(policy_settings(active_policy(db, "global")))
        if integration:
            current.update(policy_settings(active_policy(db, "integration", integration.id)))
        if user:
            current.update(policy_settings(active_policy(db, "user", user.id)))
        return current

    def ensure_builtin_roles(db: Session) -> None:
        for name, permissions in BUILT_IN_ROLES.items():
            role = db.scalar(select(Role).where(Role.name == name))
            if not role:
                db.add(Role(name=name, description=f"Built-in {name} role", permissions=permissions, built_in=True, enabled=True))
            elif role.built_in:
                role.permissions = permissions
                role.enabled = True
        db.flush()

    def role_permissions(db: Session, role_name: str) -> dict[str, bool] | None:
        if role_name in BUILT_IN_ROLES:
            return BUILT_IN_ROLES[role_name]
        role = db.scalar(select(Role).where(Role.name == role_name, Role.enabled.is_(True)))
        if not role:
            return None
        permissions = role.permissions or {}
        return {
            "read": bool(permissions.get("read", True)),
            "write": bool(permissions.get("write", False)),
            "admin": bool(permissions.get("admin", False)),
        }

    def require_role_exists(db: Session, role_name: str) -> None:
        if not role_permissions(db, role_name):
            raise HTTPException(status_code=422, detail={"code": "unknown_role", "message": "API key role must be an enabled RBAC role"})

    def validate_device_public_key(public_key: str, key_type: str | None = DEVICE_KEY_TYPE_ED25519) -> None:
        normalized_key_type = normalize_device_key_type(key_type)
        if not is_valid_device_public_key(public_key, normalized_key_type):
            expected = (
                "base64 for an X.509 SubjectPublicKeyInfo DER P-256 public key"
                if normalized_key_type == DEVICE_KEY_TYPE_ECDSA_P256
                else "base64 for a raw 32-byte Ed25519 public key"
            )
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "bad_public_key",
                    "message": f"public_key must be {expected}",
                },
            )

    def scoped_auth(request: Request, db: Session, key: ApiKey) -> dict[str, Any]:
        scope = db.get(ProvisionerScope, key.id)
        if not scope:
            raise HTTPException(403, detail={"code": "provisioner_scope_missing"})
        route = request.scope.get("route")
        path = getattr(route, "path", "")
        allowed = {
            ("GET", "/api/admin/whoami"),
            ("GET", "/api/admin/integrations"),
            ("POST", "/api/admin/integrations"),
            ("GET", "/api/admin/integrations/{integration_id}"),
            ("PATCH", "/api/admin/integrations/{integration_id}"),
        }
        if (request.method, path) not in allowed:
            raise HTTPException(403, detail={"code": "insufficient_scope"})
        audit(db, f"api-key:{key.id}", "api_key.use", "api_key", key.id, {"role": key.role})
        db.commit()
        return {"actor": f"api-key:{key.id}", "role": "integration-provisioner",
                "permissions": BUILT_IN_ROLES["integration-provisioner"], "key_id": key.id,
                "scope": {"principal_username": scope.principal_username,
                          "approver_username": scope.approver_username, "systems": scope.systems}}

    def system_in_scope(auth: dict, system_name: str | None) -> bool:
        # ["*"] is a fleet provisioner: any system name, same fixed binding.
        systems = auth["scope"]["systems"]
        if systems == ["*"]:
            # Same canonical form the admin allowlist enforces: no case/space/lookalike twins.
            return system_name is not None and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", system_name) is not None
        return system_name is not None and system_name in systems

    def scope_matches(auth: dict, integration: Integration) -> bool:
        scope = auth["scope"]
        return (system_in_scope(auth, integration.system_name)
                and integration.principal_username == scope["principal_username"]
                and integration.approver_username == scope["approver_username"]
                and integration.system_type == "linux-pam" and integration.fail_mode == "closed")

    async def raw_json_body(request: Request) -> dict[str, Any]:
        # Read bytes on the loop, but execute the entire SQL transaction in the
        # sync endpoint worker. Never await while holding the provisioning lock.
        return await request.json()

    @app.exception_handler(OperationalError)
    async def database_contention(request: Request, exc: OperationalError):
        code = getattr(exc.orig, "sqlstate", None) or getattr(exc.orig, "pgcode", None)
        if code == "55P03" or (db_handle.engine.dialect.name == "sqlite" and
                               "locked" in str(exc.orig).lower()):
            return JSONResponse(status_code=503, content={"detail": {
                "code": "database_busy", "message": "Reconcile state before retrying creation"}})
        raise exc

    def lock_provisioning(db: Session) -> None:
        # One lock shared by creates AND rebinding, independent of principal/key.
        # PostgreSQL advisory lock is transaction-scoped; SQLite serializes writers.
        if db.bind.dialect.name == "postgresql":
            db.execute(text("SET LOCAL lock_timeout = '5s'"))
            db.execute(text("SELECT pg_advisory_xact_lock(739102847112)"))
        elif db.bind.dialect.name == "sqlite":
            db.execute(update(User).where(User.id == "").values(username=User.username))
        else:
            raise HTTPException(503, detail={"code": "unsupported_provisioner_database"})

    def online_only(db: Session, integration: Integration) -> bool:
        return db.scalar(select(ProvisionedIntegration).where(
            ProvisionedIntegration.integration_id == integration.id)) is not None

    def integration_obj(db: Session, integration: Integration, include_secret: bool = False) -> dict:
        # Attested from durable server ownership, never supplied by clients.
        return {**obj(integration, include_secret=include_secret), "online_only": online_only(db, integration)}

    def require_admin(
        request: Request,
        authorization: str | None = Header(default=None),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        if settings.trusted_proxy_auth_enabled:
            username = request.headers.get(settings.trusted_proxy_auth_username_header)
            if username:
                proxy_secret = request.headers.get("x-pushgate-proxy-secret")
                if not proxy_secret or not constant_eq(proxy_secret, settings.trusted_proxy_auth_secret or ""):
                    raise HTTPException(status_code=403, detail={"code": "untrusted_proxy", "message": "trusted proxy secret rejected"})
                required_groups = group_list(settings.trusted_proxy_auth_admin_groups)
                presented_groups = group_list(request.headers.get(settings.trusted_proxy_auth_groups_header))
                if required_groups and not required_groups.intersection(presented_groups):
                    raise HTTPException(status_code=403, detail={"code": "proxy_group_required", "message": "Identity proxy user is missing a required PushGate admin group"})
                # Cookie-backed proxy identity needs a non-simple request marker.
                # Explicit CORS origins prevent hostile pages preflighting it.
                if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.headers.get("x-pushgate-csrf") != "1":
                    raise HTTPException(status_code=403, detail={"code": "csrf_header_required", "message": "X-PushGate-CSRF: 1 required"})
                role = settings.trusted_proxy_auth_role
                permissions = role_permissions(db, role)
                if not permissions:
                    raise HTTPException(status_code=403, detail={"code": "role_disabled", "message": "trusted proxy role is disabled or missing"})
                if request.method in {"GET", "HEAD"} and not permissions.get("read"):
                    raise HTTPException(status_code=403, detail={"code": "insufficient_scope", "message": "read scope required"})
                actor = f"proxy:{username}"
                audit(db, actor, "proxy_auth.use", "proxy_auth", detail={"role": role})
                db.commit()
                return {"actor": actor, "role": role, "permissions": permissions}

        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail={"code": "missing_token", "message": "Bearer token required"})
        token = authorization.removeprefix("Bearer ").strip()
        bootstrap_enabled = bool(settings.bootstrap_token) and settings.bootstrap_token not in {"dev-admin", "change-me", "replace-me"}
        actor = "bootstrap"
        role = "admin"
        permissions = BUILT_IN_ROLES["admin"]
        if not bootstrap_enabled or not constant_eq(token, settings.bootstrap_token or ""):
            key = db.scalar(select(ApiKey).where(ApiKey.token_hash == hash_value(token), ApiKey.enabled.is_(True)))
            if not key:
                raise HTTPException(status_code=403, detail={"code": "invalid_token", "message": "API key rejected"})
            key.last_used_at = utcnow()
            # A durable scope remains restrictive even if an operator changes role.
            if key.role == "integration-provisioner" or db.get(ProvisionerScope, key.id):
                return scoped_auth(request, db, key)
            actor = f"api-key:{key.name}"
            role = key.role
            permissions = role_permissions(db, role)
            if not permissions:
                raise HTTPException(status_code=403, detail={"code": "role_disabled", "message": "API key role is disabled or missing"})
        if request.method in {"GET", "HEAD"} and not permissions.get("read"):
            raise HTTPException(status_code=403, detail={"code": "insufficient_scope", "message": "read scope required"})
        audit(db, actor, "api_key.use", "api_key", detail={"role": role})
        db.commit()
        return {"actor": actor, "role": role, "permissions": permissions}

    def assert_write(auth: dict[str, Any]) -> None:
        if not auth["permissions"].get("write"):
            raise HTTPException(status_code=403, detail={"code": "insufficient_scope", "message": "write scope required"})

    def assert_admin(auth: dict[str, Any]) -> None:
        if not auth["permissions"].get("admin"):
            raise HTTPException(status_code=403, detail={"code": "admin_required"})

    def effective_fail_mode(db: Session, user: User, integration: Integration) -> str:
        if online_only(db, integration):
            return "closed"
        if policy := active_policy(db, "user", user.id):
            if policy.fail_mode:
                return policy.fail_mode
        if user.fail_mode:
            return user.fail_mode
        if policy := active_policy(db, "integration", integration.id):
            if policy.fail_mode:
                return policy.fail_mode
        if integration.fail_mode:
            return integration.fail_mode
        return effective_settings(db, user, integration)["global_fail_mode"]

    def request_requires_biometric(auth_req: AuthRequest, db: Session) -> bool:
        if isinstance(auth_req.detail, dict) and "require_biometric" in auth_req.detail:
            return bool(auth_req.detail["require_biometric"])
        user = db.get(User, auth_req.user_id)
        integration = db.get(Integration, auth_req.integration_id)
        return bool(effective_settings(db, user, integration).get("require_biometric"))

    def auth_event(auth_req: AuthRequest, device: Device, db: Session) -> dict[str, Any]:
        data = obj(auth_req)
        detail = auth_req.detail if isinstance(auth_req.detail, dict) else {}
        data["source_ip"] = display_source(auth_req)
        data["geolocation"] = detail.get("geolocation")
        data["approver_username"] = detail.get("approver_username") or auth_req.username
        requested_at = detail.get("timestamp")
        if isinstance(requested_at, str):
            try:
                requested_at = utc_iso(datetime.fromisoformat(requested_at.replace("Z", "+00:00")))
            except ValueError:
                requested_at = None
        data["requested_at"] = requested_at or data.get("created_at")
        data["require_biometric"] = bool(device.require_biometric or request_requires_biometric(auth_req, db))
        return {"type": "auth_request", "data": data}

    def cache_payload(db: Session, user: User, integration: Integration, fail_mode: str) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "username": user.username,
            "fail_mode": fail_mode,
            "updated_at": utcnow().isoformat(),
        }
        if integration.principal_username == user.username and not online_only(db, integration):
            codes = db.scalars(select(BackupCode).where(BackupCode.user_id == user.id, BackupCode.used_at.is_(None))).all()
            payload["totp_secret"] = user.totp_secret
            payload["last_totp_counter"] = user.totp_last_used_step
            payload["backup_code_hashes"] = [code.code_hash for code in codes]
        return payload

    def external_auth_payload(auth_req: AuthRequest) -> dict[str, Any]:
        detail = auth_req.detail if isinstance(auth_req.detail, dict) else {}
        return {
            "id": auth_req.id,
            "username": auth_req.username,
            "approver_username": detail.get("approver_username") or auth_req.username,
            "system": auth_req.system,
            "pam_service": auth_req.pam_service,
            "source_ip": auth_req.source_ip,
            "status": auth_req.status,
            "allowed": auth_req.status == "approved",
            "factor": auth_req.factor,
            "fail_mode": auth_req.fail_mode_effective,
            "expires_at": utc_iso(auth_req.expires_at),
        }

    async def notify_resolution(request_id: str, approver_user_id: str, status: str, decided_at: datetime | None) -> None:
        """Tell the approver's devices that a request is no longer pending.

        Phones clear the in-app card and the notification for a request that
        was approved or denied on another surface, or that timed out on the
        server. Delivered over the WebSocket fan-out and, for devices that
        registered a background push token, through the push provider.
        """
        event = {
            "type": "auth_decided",
            "data": {"id": request_id, "status": status, "decided_at": utc_iso(decided_at) if decided_at else None},
        }
        def load_targets() -> list[dict[str, Any]]:
            with db_handle.SessionLocal() as db:
                devices = db.scalars(
                    select(Device).where(Device.user_id == approver_user_id, Device.revoked.is_(False), Device.public_key.is_not(None))
                ).all()
                return [{"id": device.id, "push_token": device.push_token} for device in devices]

        try:
            targets = await run_in_threadpool(load_targets)
            await app.state.push_fanout.publish([target["id"] for target in targets], event)
            await app.state.push_provider.notify_event(targets, event)
        except Exception as exc:
            app.state.syslog.emit("resolution_notify_error", {"auth_request_id": request_id, "error": exc.__class__.__name__})

    def schedule_resolution(auth_req: AuthRequest) -> None:
        """Schedule notify_resolution from either the event loop or a threadpool worker."""
        approver = auth_req.approver_user_id or auth_req.user_id
        coro = notify_resolution(auth_req.id, approver, auth_req.status, auth_req.decided_at)
        loop = getattr(app.state, "loop", None)
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not None:
            running.create_task(coro)
        elif loop is not None and loop.is_running():
            asyncio.run_coroutine_threadsafe(coro, loop)
        else:
            coro.close()

    def display_source(auth_req: AuthRequest) -> str | None:
        """The requester as the phone shows it: the server-resolved machine name, else what the helper sent."""
        detail = auth_req.detail if isinstance(auth_req.detail, dict) else {}
        name = detail.get("source_name")
        if isinstance(name, str) and name:
            return name
        # A lookup that missed the creation deadline may have finished since: resends,
        # replays and retries of this request then show the name too.
        return app.state.source_names.known_name(auth_req.source_ip) or auth_req.source_ip

    def emit_auth_syslog(auth_req: AuthRequest) -> None:
        detail = auth_req.detail if isinstance(auth_req.detail, dict) else {}
        app.state.syslog.emit(
            "auth",
            {
                "id": auth_req.id,
                "username": auth_req.username,
                "approver_username": detail.get("approver_username") or auth_req.username,
                "system": auth_req.system,
                "pam_service": auth_req.pam_service,
                "source_ip": auth_req.source_ip,
                "source_name": display_source(auth_req),
                "status": auth_req.status,
                "factor": auth_req.factor,
            },
        )

    def trusted_session_active(
        db: Session,
        user: User,
        approver_user: User,
        integration: Integration,
        system: str,
        source_ip: str | None,
        pam_service: str,
        window_seconds: int,
    ) -> AuthRequest | None:
        if online_only(db, integration) or window_seconds <= 0:
            return None
        cutoff = (utcnow() - timedelta(seconds=window_seconds)).replace(tzinfo=None)
        prior = db.scalar(
            select(AuthRequest)
            .outerjoin(Device, Device.id == AuthRequest.approved_by_device_id)
            .where(
                AuthRequest.user_id == user.id,
                func.coalesce(AuthRequest.approver_user_id, AuthRequest.user_id) == approver_user.id,
                AuthRequest.integration_id == integration.id,
                AuthRequest.system == system,
                AuthRequest.source_ip == source_ip,
                AuthRequest.pam_service == pam_service,
                AuthRequest.status == "approved",
                AuthRequest.factor.in_(("push", "totp", "backup_code")),
                # Offline factors have no approving device. Push trust must
                # still belong to a live device of the current approver.
                or_(
                    AuthRequest.factor.in_(("totp", "backup_code")),
                    (Device.user_id == approver_user.id)
                    & Device.revoked.is_(False)
                    & Device.public_key.is_not(None),
                ),
                AuthRequest.consumed_at.is_not(None),
                AuthRequest.consumed_at >= cutoff,
            )
            .order_by(AuthRequest.consumed_at.desc())
        )
        return prior

    def pending_duplicate(
        db: Session,
        user: User,
        approver_user: User,
        integration: Integration,
        system: str,
        source_ip: str | None,
        pam_service: str,
        attempt_id: str,
    ) -> AuthRequest | None:
        # Only a retry of the SAME login attempt may share a request. Separate
        # attempts with identical display context each get their own approval.
        candidates = db.scalars(
            select(AuthRequest)
            .where(
                AuthRequest.user_id == user.id,
                func.coalesce(AuthRequest.approver_user_id, AuthRequest.user_id) == approver_user.id,
                AuthRequest.integration_id == integration.id,
                AuthRequest.system == system,
                AuthRequest.source_ip == source_ip,
                AuthRequest.pam_service == pam_service,
                AuthRequest.status == "pending",
                AuthRequest.expires_at > utcnow(),
            )
            .order_by(AuthRequest.created_at.desc())
            .with_for_update()
        ).all()
        for candidate in candidates:
            detail = candidate.detail if isinstance(candidate.detail, dict) else {}
            if detail.get("attempt_id") == attempt_id:
                return candidate
        return None

    def auth_attempt_id(payload: dict[str, Any]) -> str | None:
        value = payload.get("attempt_id")
        if value is None:
            return None
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", value):
            raise HTTPException(
                status_code=422,
                detail={"code": "invalid_attempt_id", "message": "attempt_id must be 16-128 URL-safe characters"},
            )
        return value

    def auth_request_expiry(
        payload: dict[str, Any],
        server_received_at: datetime,
        server_expires_at: datetime,
    ) -> datetime:
        if "client_expires_at" in payload:
            raise HTTPException(
                status_code=422,
                detail={"code": "invalid_client_timeout", "message": "use client_timeout_seconds"},
            )
        value = payload.get("client_timeout_seconds")
        if value is None:
            return server_expires_at
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise HTTPException(
                status_code=422,
                detail={"code": "invalid_client_timeout", "message": "client_timeout_seconds must be a positive finite number"},
            )
        client_timeout_seconds = float(value)
        if not math.isfinite(client_timeout_seconds) or not 0 < client_timeout_seconds <= 600:
            raise HTTPException(
                status_code=422,
                detail={"code": "invalid_client_timeout", "message": "client_timeout_seconds must be greater than 0 and at most 600"},
            )
        return min(
            server_expires_at,
            server_received_at + timedelta(seconds=client_timeout_seconds),
        )

    def lock_pending_auth_context(db: Session, user_id: str) -> None:
        # Serializing by principal makes the duplicate check and insert one atomic
        # operation across workers without requiring a new lock table.
        db.commit()
        if db.get_bind().dialect.name == "sqlite":
            db.execute(text("BEGIN IMMEDIATE"))
        else:
            db.execute(select(User.id).where(User.id == user_id).with_for_update())

    def pending_ttl(auth_req: AuthRequest) -> int:
        return max(1, int((aware(auth_req.expires_at) - utcnow()).total_seconds()))

    def expire_unconsumed_auth_requests(db: Session) -> int:
        cutoff = utcnow()
        candidate_ids = db.scalars(
            select(AuthRequest.id).where(
                AuthRequest.status.in_(("pending", "approved")),
                AuthRequest.consumed_at.is_(None),
                AuthRequest.expires_at <= cutoff,
            )
        ).all()
        expired: list[AuthRequest] = []
        for request_id in candidate_ids:
            result = db.execute(
                update(AuthRequest)
                .where(
                    AuthRequest.id == request_id,
                    AuthRequest.status.in_(("pending", "approved")),
                    AuthRequest.consumed_at.is_(None),
                    AuthRequest.expires_at <= cutoff,
                )
                .values(
                    status="timeout",
                    decided_at=func.coalesce(AuthRequest.decided_at, cutoff),
                )
                .execution_options(synchronize_session=False)
            )
            if result.rowcount != 1:
                continue
            auth_req = db.get(AuthRequest, request_id, populate_existing=True)
            if auth_req:
                append_auth_log(db, auth_req)
                app.state.auth_state.delete(auth_req.id)
                expired.append(auth_req)
        if expired:
            db.commit()
            for auth_req in expired:
                emit_auth_syslog(auth_req)
                schedule_resolution(auth_req)
                if auth_req.approved_by_device_id is None:
                    app.state.unanswered_watch.unanswered(auth_req.id, auth_req.system)
        return len(expired)

    def prune_replay_nonces(db: Session) -> int:
        cutoff = (utcnow() - timedelta(seconds=2 * max(1, settings.hmac_window_seconds))).replace(tzinfo=None)
        integration_result = db.execute(delete(Nonce).where(Nonce.created_at < cutoff))
        device_result = db.execute(delete(DeviceNonce).where(DeviceNonce.created_at < cutoff))
        return int(integration_result.rowcount or 0) + int(device_result.rowcount or 0)

    def expire_pending_once() -> None:
        with db_handle.SessionLocal() as db:
            pruned = prune_replay_nonces(db)
            expire_unconsumed_auth_requests(db)
            if pruned:
                db.commit()

    async def prewarm_source_names() -> None:
        """Name the addresses seen in the last week before the first login after a restart."""
        if not app.state.source_names.enabled:
            return
        def recent_sources() -> list[str]:
            cutoff = (utcnow() - timedelta(days=7)).replace(tzinfo=None)
            with db_handle.SessionLocal() as db:
                return list(
                    db.scalars(
                        select(AuthRequest.source_ip)
                        .where(AuthRequest.created_at >= cutoff, AuthRequest.source_ip.is_not(None))
                        .group_by(AuthRequest.source_ip)
                        .order_by(func.max(AuthRequest.created_at).desc())
                        .limit(256)
                    ).all()
                )
        try:
            sources = await run_in_threadpool(recent_sources)
            warmed = await app.state.source_names.prewarm(sources)
            SOURCE_LOG.info("source_name_prewarm addresses=%d", warmed)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            SOURCE_LOG.warning("source_name_prewarm_failed error=%s", exc.__class__.__name__)

    async def expire_pending_loop() -> None:
        # Database I/O runs in a worker thread: a stalled connection (for example
        # during a Patroni failover) must never freeze the event loop.
        while True:
            await asyncio.sleep(1)
            try:
                await run_in_threadpool(expire_pending_once)
            except Exception as exc:
                app.state.syslog.emit("auth_expiry_error", {"error": exc.__class__.__name__})

    async def push_with_retries(request_id: str, device_ids: list[str], retry_count: int, ttl_seconds: int) -> None:
        attempts = retry_count + 1
        delay = max(0.2, min(2.0, ttl_seconds / max(1, attempts)))
        def load_jobs() -> list[tuple[dict[str, Any], dict[str, Any]]] | None:
            with db_handle.SessionLocal() as db:
                auth_req = db.get(AuthRequest, request_id)
                if not auth_req or auth_req.status != "pending" or aware(auth_req.expires_at) <= utcnow():
                    return None
                devices = db.scalars(
                    select(Device).where(
                        Device.id.in_(device_ids),
                        Device.revoked.is_(False),
                        Device.public_key.is_not(None),
                    )
                ).all()
                return [
                    (
                        {"id": device.id, "push_token": device.push_token},
                        auth_event(auth_req, device, db),
                    )
                    for device in devices
                ]

        for attempt in range(attempts):
            jobs = await run_in_threadpool(load_jobs)
            if jobs is None:
                return
            for device, event in jobs:
                try:
                    await app.state.push_provider.notify_auth_request([device], event)
                except Exception as exc:
                    app.state.syslog.emit(
                        "push_error",
                        {"auth_request_id": request_id, "device_id": device.get("id"), "attempt": attempt + 1, "attempts": attempts, "error": exc.__class__.__name__},
                    )
            if attempt < attempts - 1:
                await asyncio.sleep(delay)

    def verify_device_ws_handshake(websocket: WebSocket, db: Session, device: Device) -> str | None:
        timestamp = websocket.query_params.get("timestamp")
        nonce = websocket.query_params.get("nonce")
        signature = websocket.query_params.get("signature")
        if not all([timestamp, nonce, signature]):
            return "missing_device_signature"
        if not device.public_key:
            return "device_not_enrolled"
        try:
            ts = datetime.fromtimestamp(int(timestamp), timezone.utc)
        except ValueError:
            return "bad_timestamp"
        if abs((utcnow() - ts).total_seconds()) > settings.hmac_window_seconds:
            return "clock_skew"
        message = f"ws.{device.id}.{timestamp}.{nonce}"
        if not verify_device_message_signature(device.public_key, signature, message, device.key_type):
            return "bad_device_signature"
        prune_replay_nonces(db)
        db.add(DeviceNonce(device_id=device.id, nonce=nonce))
        try:
            db.flush()
        except IntegrityError:
            return "replay"
        db.commit()
        return None

    def verify_integration_request(request: Request, body: bytes, db: Session) -> Integration:
        client_id = request.headers.get("x-pushgate-client-id")
        timestamp = request.headers.get("x-pushgate-timestamp")
        nonce = request.headers.get("x-pushgate-nonce")
        signature = request.headers.get("x-pushgate-signature")
        if not all([client_id, timestamp, nonce, signature]):
            raise HTTPException(status_code=401, detail={"code": "missing_signature", "message": "signed integration headers required"})
        try:
            ts = datetime.fromtimestamp(int(timestamp), timezone.utc)
        except ValueError:
            raise HTTPException(status_code=401, detail={"code": "bad_timestamp", "message": "timestamp must be unix seconds"}) from None
        if abs((utcnow() - ts).total_seconds()) > settings.hmac_window_seconds:
            raise HTTPException(status_code=401, detail={"code": "clock_skew", "message": "signed request outside clock-skew window"})
        integration = db.scalar(select(Integration).where(Integration.client_id == client_id, Integration.enabled.is_(True)))
        if not integration:
            raise HTTPException(status_code=403, detail={"code": "unknown_integration", "message": "integration rejected"})
        expected = integration_signature(integration.secret, request.method, request.url.path, body, timestamp, nonce)
        if not constant_eq(expected, signature):
            raise HTTPException(status_code=403, detail={"code": "bad_signature", "message": "signature mismatch"})
        prune_replay_nonces(db)
        db.add(Nonce(integration_id=integration.id, nonce=nonce))
        try:
            db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail={"code": "replay", "message": "nonce already used"}) from None
        db.commit()
        return integration

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        # Runs on the event loop, never in the threadpool: worker threads stuck
        # on the database must not make the process look dead.
        return {"ok": True, "service": settings.server_name}

    @app.get("/api/admin/settings/global")
    def get_global_settings(db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        return envelope(default_settings(db))

    @app.patch("/api/admin/settings/global")
    def patch_global_settings(payload: GlobalSettingsPatch, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        current = default_settings(db)
        current.update({k: v for k, v in payload.model_dump(exclude_unset=True).items() if v is not None})
        row = db.get(Setting, "global")
        row.value = current
        audit(db, auth["actor"], "settings.update", "settings", "global", current)
        db.commit()
        return envelope(current)

    @app.get("/api/admin/policies")
    def list_policies(
        subject_type: str | None = Query(default=None, pattern="^(global|user|integration)$"),
        subject_id: str | None = None,
        db: Session = Depends(get_db),
        auth: dict[str, str] = Depends(require_admin),
    ):
        stmt = select(Policy).order_by(Policy.created_at)
        if subject_type:
            stmt = stmt.where(Policy.subject_type == subject_type)
        if subject_id:
            stmt = stmt.where(Policy.subject_id == subject_id)
        return envelope([obj(policy) for policy in db.scalars(stmt).all()])

    @app.post("/api/admin/policies", status_code=201)
    def create_policy(payload: PolicyIn, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        subject_key = validate_policy_subject(db, payload.subject_type, payload.subject_id)
        data = payload.model_dump()
        data["subject_key"] = subject_key
        policy = Policy(**data)
        db.add(policy)
        try:
            db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail={"code": "duplicate_policy", "message": "policy name or subject already exists"}) from None
        audit(db, auth["actor"], "policy.create", "policy", policy.id, {"subject_type": policy.subject_type, "subject_id": policy.subject_id})
        db.commit()
        return envelope(obj(policy))

    @app.get("/api/admin/policies/{policy_id}")
    def get_policy(policy_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        policy = db.get(Policy, policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        return envelope(obj(policy))

    @app.patch("/api/admin/policies/{policy_id}")
    def patch_policy(policy_id: str, payload: PolicyPatch, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        policy = db.get(Policy, policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        changes = payload.model_dump(exclude_unset=True)
        for key, value in changes.items():
            setattr(policy, key, value)
        try:
            db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail={"code": "duplicate_policy", "message": "policy name already exists"}) from None
        audit(db, auth["actor"], "policy.update", "policy", policy.id, changes)
        db.commit()
        return envelope(obj(policy))

    @app.delete("/api/admin/policies/{policy_id}", status_code=204)
    def delete_policy(policy_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        policy = db.get(Policy, policy_id)
        if policy:
            db.delete(policy)
            audit(db, auth["actor"], "policy.delete", "policy", policy_id)
            db.commit()

    @app.get("/api/admin/users")
    def list_users(db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        return envelope([obj(u) for u in db.scalars(select(User).order_by(User.username)).all()])

    @app.post("/api/admin/users", status_code=201)
    def create_user(payload: UserIn, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        user = User(**payload.model_dump())
        db.add(user)
        try:
            db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail={"code": "duplicate_user", "message": "username already exists"}) from None
        audit(db, auth["actor"], "user.create", "user", user.id, {"username": user.username})
        db.commit()
        return envelope(obj(user))

    @app.get("/api/admin/users/{user_id}")
    def get_user(user_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        return envelope(obj(user))

    @app.patch("/api/admin/users/{user_id}")
    def patch_user(user_id: str, payload: UserPatch, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        for key, value in payload.model_dump(exclude_unset=True).items():
            setattr(user, key, value)
        audit(db, auth["actor"], "user.update", "user", user.id, payload.model_dump(exclude_unset=True))
        cancelled = cancel_unconsumed_for_locked_user(db, user, auth["actor"]) if user.locked else []
        db.commit()
        publish_cancellations(cancelled)
        return envelope(obj(user))

    @app.delete("/api/admin/users/{user_id}", status_code=204)
    def delete_user(user_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        user = db.get(User, user_id)
        if user:
            db.delete(user)
            audit(db, auth["actor"], "user.delete", "user", user_id)
            db.commit()

    def cancel_unconsumed_for_locked_user(db: Session, user: User, actor: str) -> list[AuthRequest]:
        """Deny every pending or approved-but-unconsumed request the locked user is part of."""
        # Flush the user row first: lock order is user, then requests, as in
        # device decisions and consumption.
        db.flush()
        rows = db.scalars(
            select(AuthRequest)
            .where(
                or_(
                    AuthRequest.user_id == user.id,
                    func.coalesce(AuthRequest.approver_user_id, AuthRequest.user_id) == user.id,
                ),
                AuthRequest.status.in_(("pending", "approved")),
                AuthRequest.consumed_at.is_(None),
            )
            .order_by(AuthRequest.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).all()
        cancelled_at = utcnow()
        for auth_req in rows:
            auth_req.status = "denied"
            auth_req.factor = "lockout" if auth_req.user_id == user.id else "approver_lockout"
            auth_req.decided_at = auth_req.decided_at or cancelled_at
            append_auth_log(db, auth_req)
            audit(db, actor, "auth.cancel_lockout", "auth_request", auth_req.id, {"user_id": user.id})
        return list(rows)

    def publish_cancellations(cancelled: list[AuthRequest]) -> None:
        for auth_req in cancelled:
            app.state.auth_state.delete(auth_req.id)
            emit_auth_syslog(auth_req)
            schedule_resolution(auth_req)

    @app.post("/api/admin/users/{user_id}/lockout")
    def lock_user(user_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        user.locked = True
        audit(db, auth["actor"], "user.lock", "user", user.id)
        cancelled = cancel_unconsumed_for_locked_user(db, user, auth["actor"])
        db.commit()
        publish_cancellations(cancelled)
        return envelope(obj(user))

    @app.delete("/api/admin/users/{user_id}/lockout")
    def unlock_user(user_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        user.locked = False
        audit(db, auth["actor"], "user.unlock", "user", user.id)
        db.commit()
        return envelope(obj(user))

    @app.post("/api/admin/users/{user_id}/totp")
    def enroll_totp(user_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        user.totp_secret = new_totp_secret()
        user.totp_last_used_step = None
        audit(db, auth["actor"], "totp.enroll", "user", user.id)
        db.commit()
        return envelope({"secret": user.totp_secret, "uri": totp_uri(user.totp_secret, user.username, "PushGate")})

    @app.post("/api/admin/users/{user_id}/backup-codes")
    def create_backup_codes(user_id: str, count: int = Query(default=10, ge=1, le=50), db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        codes = generate_backup_codes(count)
        for code in codes:
            db.add(BackupCode(user_id=user.id, code_hash=hash_value(code)))
        audit(db, auth["actor"], "backup_codes.create", "user", user.id, {"count": count})
        db.commit()
        return envelope({"codes": codes})

    @app.get("/api/admin/users/{user_id}/backup-codes")
    def list_backup_codes(user_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        if not db.get(User, user_id):
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        rows = db.scalars(select(BackupCode).where(BackupCode.user_id == user_id).order_by(BackupCode.created_at.desc())).all()
        return envelope([obj(row) for row in rows])

    @app.delete("/api/admin/users/{user_id}/backup-codes", status_code=204)
    def delete_backup_codes(user_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        if not db.get(User, user_id):
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        for row in db.scalars(select(BackupCode).where(BackupCode.user_id == user_id)).all():
            db.delete(row)
        audit(db, auth["actor"], "backup_codes.delete_all", "user", user_id)
        db.commit()

    @app.delete("/api/admin/backup-codes/{code_id}", status_code=204)
    def delete_backup_code(code_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        code = db.get(BackupCode, code_id)
        if code:
            db.delete(code)
            audit(db, auth["actor"], "backup_code.delete", "backup_code", code_id)
            db.commit()

    @app.get("/api/admin/groups")
    def list_groups(db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        return envelope([obj(g) for g in db.scalars(select(Group).order_by(Group.name)).all()])

    @app.post("/api/admin/groups", status_code=201)
    def create_group(payload: GroupIn, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        group = Group(**payload.model_dump())
        db.add(group)
        try:
            db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail={"code": "duplicate_group", "message": "group name already exists"}) from None
        audit(db, auth["actor"], "group.create", "group", group.id)
        db.commit()
        return envelope(obj(group))

    @app.get("/api/admin/groups/{group_id}")
    def get_group(group_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        group = db.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        return envelope(obj(group))

    @app.patch("/api/admin/groups/{group_id}")
    def patch_group(group_id: str, payload: GroupPatch, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        group = db.get(Group, group_id)
        if not group:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        changes = payload.model_dump(exclude_unset=True)
        for key, value in changes.items():
            setattr(group, key, value)
        try:
            db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail={"code": "duplicate_group", "message": "group name already exists"}) from None
        audit(db, auth["actor"], "group.update", "group", group.id, changes)
        db.commit()
        return envelope(obj(group))

    @app.delete("/api/admin/groups/{group_id}", status_code=204)
    def delete_group(group_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        group = db.get(Group, group_id)
        if group:
            for row in db.scalars(select(UserGroup).where(UserGroup.group_id == group_id)).all():
                db.delete(row)
            db.delete(group)
            audit(db, auth["actor"], "group.delete", "group", group_id)
            db.commit()

    @app.get("/api/admin/groups/{group_id}/users")
    def list_group_users(group_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        if not db.get(Group, group_id):
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        rows = db.scalars(
            select(User)
            .join(UserGroup, UserGroup.user_id == User.id)
            .where(UserGroup.group_id == group_id)
            .order_by(User.username)
        ).all()
        return envelope([obj(row) for row in rows])

    @app.post("/api/admin/groups/{group_id}/users/{user_id}", status_code=201)
    def add_group_user(group_id: str, user_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        if not db.get(Group, group_id):
            raise HTTPException(status_code=404, detail={"code": "group_not_found"})
        if not db.get(User, user_id):
            raise HTTPException(status_code=404, detail={"code": "user_not_found"})
        membership = db.scalar(select(UserGroup).where(UserGroup.group_id == group_id, UserGroup.user_id == user_id))
        if not membership:
            membership = UserGroup(group_id=group_id, user_id=user_id)
            db.add(membership)
            db.flush()
            audit(db, auth["actor"], "group.user.add", "group", group_id, {"user_id": user_id})
            db.commit()
        return envelope(obj(membership))

    @app.delete("/api/admin/groups/{group_id}/users/{user_id}", status_code=204)
    def remove_group_user(group_id: str, user_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        membership = db.scalar(select(UserGroup).where(UserGroup.group_id == group_id, UserGroup.user_id == user_id))
        if membership:
            db.delete(membership)
            audit(db, auth["actor"], "group.user.remove", "group", group_id, {"user_id": user_id})
            db.commit()

    @app.get("/api/admin/devices")
    def list_devices(user_id: str | None = None, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        stmt = select(Device).order_by(Device.created_at)
        if user_id:
            stmt = stmt.where(Device.user_id == user_id)
        return envelope([obj(d) for d in db.scalars(stmt).all()])

    @app.post("/api/admin/devices", status_code=201)
    def create_device(payload: DeviceIn, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        if not db.get(User, payload.user_id):
            raise HTTPException(status_code=404, detail={"code": "user_not_found"})
        enrollment_token = None
        data = payload.model_dump()
        if data.get("public_key"):
            validate_device_public_key(data["public_key"], data["key_type"])
            data["enrolled_at"] = utcnow()
            data["enrollment_expires_at"] = None
        else:
            enrollment_token = random_secret()
            data["enrollment_token_hash"] = hash_value(enrollment_token)
            data["enrollment_expires_at"] = utcnow() + timedelta(seconds=max(1, settings.enrollment_token_ttl_seconds))
        device = Device(**data)
        db.add(device)
        db.flush()
        audit(db, auth["actor"], "device.create", "device", device.id, {"kind": device.kind})
        db.commit()
        response = obj(device)
        if enrollment_token:
            response["enrollment_qr_payload"] = json.dumps(
                {
                    "device_id": device.id,
                    "enrollment_token": enrollment_token,
                    "enroll_api": "/api/v1/devices/{id}/enroll",
                    "decision_api": "/api/v1/auth/requests/{id}/decision",
                }
            )
        return envelope(response)

    @app.get("/api/admin/devices/{device_id}")
    def get_device(device_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        device = db.get(Device, device_id)
        if not device:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        return envelope(obj(device))

    @app.patch("/api/admin/devices/{device_id}")
    async def patch_device(device_id: str, payload: DevicePatch, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        device, changes = await run_in_threadpool(patch_device_sync, device_id, payload, db, auth)
        if {"public_key", "key_type", "revoked"}.intersection(changes):
            await app.state.push_fanout.publish([device.id], {"type": "device_security_changed", "data": {"id": device.id}})
        return envelope(obj(device))

    def patch_device_sync(device_id: str, payload: DevicePatch, db: Session, auth: dict[str, str]) -> tuple[Device, dict[str, Any]]:
        assert_write(auth)
        device = db.get(Device, device_id)
        if not device:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        changes = payload.model_dump(exclude_unset=True)
        if changes.get("key_type") is None and "key_type" in changes:
            raise HTTPException(status_code=422, detail={"code": "bad_key_type", "message": "key_type must be ed25519 or ecdsa_p256"})
        next_key_type = changes.get("key_type", device.key_type or DEVICE_KEY_TYPE_ED25519)
        if "public_key" in changes:
            public_key = changes["public_key"]
            if public_key:
                validate_device_public_key(public_key, next_key_type)
                device.enrollment_token_hash = None
                device.enrollment_expires_at = None
                device.enrolled_at = utcnow()
            else:
                device.enrolled_at = None
        elif "key_type" in changes and device.public_key:
            validate_device_public_key(device.public_key, next_key_type)
        for key, value in changes.items():
            setattr(device, key, value)
        audit(
            db,
            auth["actor"],
            "device.update",
            "device",
            device.id,
            device_audit_changes(changes),
        )
        db.commit()
        return device, changes

    def revoke_device_sync(device_id: str, db: Session, auth: dict[str, str]) -> str | None:
        assert_write(auth)
        device = db.get(Device, device_id)
        if not device:
            return None
        device.revoked = True
        audit(db, auth["actor"], "device.revoke", "device", device.id)
        db.commit()
        return device.id

    @app.delete("/api/admin/devices/{device_id}", status_code=204)
    async def revoke_device(device_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        revoked_id = await run_in_threadpool(revoke_device_sync, device_id, db, auth)
        if revoked_id:
            await app.state.push_fanout.publish([revoked_id], {"type": "device_security_changed", "data": {"id": revoked_id}})

    @app.post("/api/admin/devices/{device_id}/rotation")
    async def rotate_device_key(device_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        device, data = await run_in_threadpool(rotate_device_key_sync, device_id, db, auth)
        await app.state.push_fanout.publish([device.id], {"type": "device_security_changed", "data": {"id": device.id}})
        return envelope(data)

    def rotate_device_key_sync(device_id: str, db: Session, auth: dict[str, str]) -> tuple[Device, dict[str, Any]]:
        assert_write(auth)
        device = db.get(Device, device_id)
        if not device:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        enrollment_token = random_secret()
        device.public_key = None
        device.key_type = DEVICE_KEY_TYPE_ED25519
        device.enrollment_token_hash = hash_value(enrollment_token)
        device.enrollment_expires_at = utcnow() + timedelta(seconds=max(1, settings.enrollment_token_ttl_seconds))
        device.enrolled_at = None
        audit(db, auth["actor"], "device.rotate_key", "device", device.id)
        db.commit()
        data = obj(device)
        data["enrollment_qr_payload"] = json.dumps(
            {
                "device_id": device.id,
                "enrollment_token": enrollment_token,
                "enroll_api": "/api/v1/devices/{id}/enroll",
                "decision_api": "/api/v1/auth/requests/{id}/decision",
            }
        )
        return device, data

    @app.post("/api/v1/devices/{device_id}/enroll")
    def enroll_device(device_id: str, payload: DeviceEnrollIn, db: Session = Depends(get_db)):
        device = db.get(Device, device_id)
        if not device or device.revoked:
            raise HTTPException(status_code=404, detail={"code": "device_not_found"})
        if device.public_key and not device.enrollment_token_hash:
            raise HTTPException(status_code=409, detail={"code": "enrollment_consumed"})
        if not device.enrollment_token_hash or not constant_eq(device.enrollment_token_hash, hash_value(payload.enrollment_token)):
            raise HTTPException(status_code=403, detail={"code": "bad_enrollment_token"})
        if not device.enrollment_expires_at or aware(device.enrollment_expires_at) <= utcnow():
            raise HTTPException(status_code=403, detail={"code": "enrollment_token_expired"})
        validate_device_public_key(payload.public_key, payload.key_type)
        enrolled_at = utcnow()
        claimed = db.execute(
            update(Device)
            .where(
                Device.id == device_id,
                Device.revoked.is_(False),
                Device.public_key.is_(None),
                Device.enrollment_token_hash == hash_value(payload.enrollment_token),
                Device.enrollment_expires_at > enrolled_at,
            )
            .values(
                public_key=payload.public_key,
                key_type=payload.key_type,
                push_token=payload.push_token,
                enrollment_token_hash=None,
                enrollment_expires_at=None,
                enrolled_at=enrolled_at,
            )
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail={"code": "enrollment_consumed"})
        device = db.get(Device, device_id, populate_existing=True)
        if not device:
            raise HTTPException(status_code=404, detail={"code": "device_not_found"})
        audit(db, f"device:{device.id}", "device.enroll", "device", device.id)
        db.commit()
        return envelope(obj(device))

    @app.post("/api/v1/devices/{device_id}/push-token")
    def update_device_push_token(device_id: str, payload: DevicePushTokenIn, db: Session = Depends(get_db)):
        device = db.get(Device, device_id)
        if not device or device.revoked:
            raise HTTPException(status_code=404, detail={"code": "device_not_found"})
        if not device.public_key:
            raise HTTPException(status_code=403, detail={"code": "device_not_enrolled"})
        try:
            ts = datetime.fromtimestamp(int(payload.timestamp), timezone.utc)
        except ValueError:
            raise HTTPException(status_code=401, detail={"code": "bad_timestamp", "message": "timestamp must be unix seconds"}) from None
        if abs((utcnow() - ts).total_seconds()) > settings.hmac_window_seconds:
            raise HTTPException(status_code=401, detail={"code": "clock_skew", "message": "signed request outside clock-skew window"})
        message = f"push_token.{device.id}.{payload.timestamp}.{payload.nonce}.{payload.push_token}"
        if not verify_device_message_signature(device.public_key, payload.signature, message, device.key_type):
            raise HTTPException(status_code=403, detail={"code": "bad_device_signature"})
        if not unifiedpush_endpoint_allowed(payload.push_token, settings.unifiedpush_allowed_hosts):
            raise HTTPException(
                status_code=422,
                detail={"code": "push_endpoint_not_allowed", "message": "UnifiedPush endpoint host is not in PUSHGATE_UNIFIEDPUSH_ALLOWED_HOSTS"},
            )
        prune_replay_nonces(db)
        db.add(DeviceNonce(device_id=device.id, nonce=payload.nonce))
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=409, detail={"code": "replay", "message": "nonce already used"}) from None
        device.push_token = payload.push_token
        audit(db, f"device:{device.id}", "device.push_token.update", "device", device.id)
        db.commit()
        return envelope(obj(device))

    @app.get("/api/admin/whoami")
    def whoami(auth: dict = Depends(require_admin)):
        data = dict(auth)
        if "scope" in auth:
            data["capabilities"] = {"integration_metadata": "allowlisted-systems",
                                    "integration_create": "canonical-linux-pam-online-only",
                                    "integration_disable": "owned-only",
                                    "approval": False, "offline_factors": False,
                                    "trusted_session_reuse": False}
        return envelope(data)

    @app.post("/api/admin/rbac/provisioners", status_code=201)
    def issue_provisioner(payload: ProvisionerIn, db: Session = Depends(get_db), auth: dict = Depends(require_admin)):
        assert_admin(auth)
        if payload.systems != ["*"] and (len(set(payload.systems)) != len(payload.systems)
                or any(not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", v) for v in payload.systems)):
            raise HTTPException(422, detail={"code": "invalid_system_allowlist"})
        for username in (payload.principal_username, payload.approver_username):
            if not db.scalar(select(User).where(User.username == username)):
                raise HTTPException(422, detail={"code": "unknown_binding_user"})
        token = random_secret()
        key = ApiKey(name=payload.name, role="integration-provisioner", token_hash=hash_value(token))
        db.add(key)
        db.flush()
        scope = ProvisionerScope(api_key_id=key.id, principal_username=payload.principal_username,
                                 approver_username=payload.approver_username, systems=payload.systems)
        db.add(scope)
        audit(db, auth["actor"], "provisioner.issue", "api_key", key.id, payload.model_dump())
        db.commit()
        return envelope({**obj(key), "token": token, "scope": obj(scope)})

    @app.get("/api/admin/integrations")
    def list_integrations(db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        return envelope([integration_obj(db, i) for i in db.scalars(select(Integration).order_by(Integration.name)).all()
                         if "scope" not in auth or system_in_scope(auth, i.system_name)])

    @app.post("/api/admin/integrations", status_code=201)
    def create_integration(payload: IntegrationIn, raw: dict = Depends(raw_json_body), db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        if "scope" not in auth:
            assert_write(auth)
        else:
            if (set(raw) - {"name", "system_name", "principal_username", "approver_username", "system_type", "fail_mode", "enabled"}
                    or raw.get("enabled") is not True):
                raise HTTPException(403, detail={"code": "binding_outside_scope"})
            scope = auth["scope"]
            expected = {"principal_username": scope["principal_username"],
                        "approver_username": scope["approver_username"], "system_type": "linux-pam",
                        "fail_mode": "closed", "enabled": True}
            if (not system_in_scope(auth, payload.system_name) or payload.client_id is not None
                    or payload.name != "SSH " + str(payload.system_name)
                    or any(getattr(payload, k) != v for k, v in expected.items())):
                raise HTTPException(403, detail={"code": "binding_outside_scope"})
        # Serialize all native creates against provisioner reservations. SQLite's
        # write transaction / PostgreSQL advisory lock covers existing integrations.
        if payload.system_name:
            lock_provisioning(db)
            if db.get(ProvisionedIntegration, payload.system_name) or ("scope" in auth and db.scalar(
                    select(Integration.id).where(Integration.system_name == payload.system_name))):
                raise HTTPException(409, detail={"code": "system_already_bound"})
        client_id = payload.client_id or secrets.token_hex(8)
        secret = random_secret()
        integration = Integration(
            name=payload.name,
            client_id=client_id,
            secret=secret,
            system_type=payload.system_type,
            principal_username=payload.principal_username,
            approver_username=payload.approver_username,
            system_name=payload.system_name,
            fail_mode=payload.fail_mode,
            enabled=payload.enabled,
        )
        db.add(integration)
        db.flush()
        if "scope" in auth:
            db.add(ProvisionedIntegration(system_name=integration.system_name,
                                         integration_id=integration.id, api_key_id=auth["key_id"]))
            try:
                db.flush()
            except IntegrityError:
                db.rollback()
                raise HTTPException(409, detail={"code": "system_already_bound"}) from None
        audit(db, auth["actor"], "integration.create", "integration", integration.id)
        db.commit()
        data = integration_obj(db, integration, include_secret=True)
        data["secret"] = secret
        return envelope(data)

    @app.get("/api/admin/integrations/{integration_id}")
    def get_integration(integration_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        integration = db.get(Integration, integration_id)
        if not integration:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        if "scope" in auth and not system_in_scope(auth, integration.system_name):
            raise HTTPException(403, detail={"code": "binding_outside_scope"})
        return envelope(integration_obj(db, integration))

    @app.patch("/api/admin/integrations/{integration_id}")
    def patch_integration(integration_id: str, payload: IntegrationPatch, raw: dict = Depends(raw_json_body), db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        if "scope" not in auth:
            assert_write(auth)
        integration = db.get(Integration, integration_id)
        if not integration:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        if payload.system_name:
            lock_provisioning(db)
        ownership = db.scalar(select(ProvisionedIntegration).where(ProvisionedIntegration.integration_id == integration.id))
        if "scope" in auth:
            if (raw != {"enabled": False} or payload.enabled is not False
                    or not ownership or ownership.api_key_id != auth["key_id"] or not scope_matches(auth, integration)):
                raise HTTPException(403, detail={"code": "owned_disable_only"})
        # Binding of an online-only integration is immutable, even to general write.
        # Reserve its system permanently; recovery requires a deliberate operator procedure.
        if ownership and set(payload.model_fields_set) - {"enabled", "name"}:
            raise HTTPException(403, detail={"code": "immutable_provisioned_binding"})
        if payload.system_name and db.get(ProvisionedIntegration, payload.system_name):
            raise HTTPException(409, detail={"code": "system_already_bound"})
        for key, value in payload.model_dump(exclude_unset=True).items():
            setattr(integration, key, value)
        audit(db, auth["actor"], "integration.update", "integration", integration.id, payload.model_dump(exclude_unset=True))
        db.commit()
        return envelope(integration_obj(db, integration))

    @app.delete("/api/admin/integrations/{integration_id}", status_code=204)
    def delete_integration(integration_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_write(auth)
        integration = db.get(Integration, integration_id)
        if integration:
            integration.enabled = False
            audit(db, auth["actor"], "integration.disable", "integration", integration.id)
            db.commit()

    @app.get("/api/admin/rbac/api-keys")
    def list_api_keys(db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        return envelope([obj(k) for k in db.scalars(select(ApiKey).order_by(ApiKey.created_at)).all()])

    @app.post("/api/admin/rbac/api-keys", status_code=201)
    def create_api_key(payload: ApiKeyIn, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_admin(auth)
        require_role_exists(db, payload.role)
        token = random_secret()
        key = ApiKey(name=payload.name, role=payload.role, token_hash=hash_value(token))
        db.add(key)
        db.flush()
        audit(db, auth["actor"], "api_key.create", "api_key", key.id, {"role": key.role})
        db.commit()
        data = obj(key)
        data["token"] = token
        return envelope(data)

    @app.get("/api/admin/rbac/api-keys/{key_id}")
    def get_api_key(key_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        key = db.get(ApiKey, key_id)
        if not key:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        return envelope(obj(key))

    @app.patch("/api/admin/rbac/api-keys/{key_id}")
    def patch_api_key(key_id: str, payload: ApiKeyPatch, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_admin(auth)
        key = db.get(ApiKey, key_id)
        if not key:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        changes = payload.model_dump(exclude_unset=True)
        if "role" in changes:
            require_role_exists(db, changes["role"])
        for field, value in changes.items():
            setattr(key, field, value)
        audit(db, auth["actor"], "api_key.update", "api_key", key.id, changes)
        db.commit()
        return envelope(obj(key))

    @app.delete("/api/admin/rbac/api-keys/{key_id}", status_code=204)
    def delete_api_key(key_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_admin(auth)
        key = db.get(ApiKey, key_id)
        if key:
            key.enabled = False
            audit(db, auth["actor"], "api_key.disable", "api_key", key.id)
            db.commit()

    @app.get("/api/admin/rbac/roles")
    def list_roles(db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        ensure_builtin_roles(db)
        db.commit()
        return envelope([obj(role) for role in db.scalars(select(Role).order_by(Role.name)).all()])

    @app.post("/api/admin/rbac/roles", status_code=201)
    def create_role(payload: RoleIn, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_admin(auth)
        if payload.name in BUILT_IN_ROLES:
            raise HTTPException(status_code=409, detail={"code": "built_in_role", "message": "built-in role already exists"})
        permissions = {
            "read": bool(payload.permissions.get("read", True)),
            "write": bool(payload.permissions.get("write", False)),
            "admin": bool(payload.permissions.get("admin", False)),
        }
        role = Role(name=payload.name, description=payload.description, permissions=permissions, enabled=payload.enabled)
        db.add(role)
        try:
            db.flush()
        except IntegrityError:
            raise HTTPException(status_code=409, detail={"code": "duplicate_role", "message": "role name already exists"}) from None
        audit(db, auth["actor"], "role.create", "role", role.id, {"name": role.name})
        db.commit()
        return envelope(obj(role))

    @app.get("/api/admin/rbac/roles/{role_id}")
    def get_role(role_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        ensure_builtin_roles(db)
        role = db.get(Role, role_id)
        if not role:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        db.commit()
        return envelope(obj(role))

    @app.patch("/api/admin/rbac/roles/{role_id}")
    def patch_role(role_id: str, payload: RolePatch, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_admin(auth)
        role = db.get(Role, role_id)
        if not role:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        if role.built_in:
            raise HTTPException(status_code=409, detail={"code": "built_in_role", "message": "built-in roles are immutable"})
        changes = payload.model_dump(exclude_unset=True)
        if "permissions" in changes and changes["permissions"] is not None:
            permissions = changes["permissions"]
            changes["permissions"] = {
                "read": bool(permissions.get("read", True)),
                "write": bool(permissions.get("write", False)),
                "admin": bool(permissions.get("admin", False)),
            }
        for field, value in changes.items():
            setattr(role, field, value)
        audit(db, auth["actor"], "role.update", "role", role.id, changes)
        db.commit()
        return envelope(obj(role))

    @app.delete("/api/admin/rbac/roles/{role_id}", status_code=204)
    def delete_role(role_id: str, db: Session = Depends(get_db), auth: dict[str, str] = Depends(require_admin)):
        assert_admin(auth)
        role = db.get(Role, role_id)
        if role:
            if role.built_in:
                raise HTTPException(status_code=409, detail={"code": "built_in_role", "message": "built-in roles cannot be deleted"})
            role.enabled = False
            audit(db, auth["actor"], "role.disable", "role", role.id)
            db.commit()

    @app.get("/api/admin/auth-logs")
    def auth_logs(
        user: str | None = None,
        system: str | None = None,
        result: str | None = None,
        from_: str | None = Query(default=None, alias="from"),
        to: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        db: Session = Depends(get_db),
        auth: dict[str, str] = Depends(require_admin),
    ):
        expire_unconsumed_auth_requests(db)
        stmt = select(AuthLogEntry)
        if user:
            stmt = stmt.where(AuthLogEntry.username == user)
        if system:
            stmt = stmt.where(AuthLogEntry.system == system)
        if result:
            stmt = stmt.where(AuthLogEntry.status == result)
        if since := query_dt(from_):
            stmt = stmt.where(AuthLogEntry.created_at >= since)
        if until := query_dt(to):
            stmt = stmt.where(AuthLogEntry.created_at <= until)
        rows = db.scalars(stmt.order_by(AuthLogEntry.created_at.desc()).offset(offset).limit(limit)).all()
        return envelope([auth_log_obj(r) for r in rows], limit=limit, offset=offset, count=len(rows))

    @app.get("/api/admin/audit-logs")
    def audit_logs(
        actor: str | None = None,
        action: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        from_: str | None = Query(default=None, alias="from"),
        to: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        db: Session = Depends(get_db),
        auth: dict[str, str] = Depends(require_admin),
    ):
        stmt = select(AuditLog)
        if actor:
            stmt = stmt.where(AuditLog.actor == actor)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        if resource_type:
            stmt = stmt.where(AuditLog.resource_type == resource_type)
        if resource_id:
            stmt = stmt.where(AuditLog.resource_id == resource_id)
        if since := query_dt(from_):
            stmt = stmt.where(AuditLog.created_at >= since)
        if until := query_dt(to):
            stmt = stmt.where(AuditLog.created_at <= until)
        rows = db.scalars(stmt.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)).all()
        return envelope([obj(r) for r in rows], limit=limit, offset=offset, count=len(rows))

    def parse_auth_payload(body: bytes) -> dict[str, Any]:
        try:
            payload = json.loads(body.decode() or "{}")
        except json.JSONDecodeError:
            raise HTTPException(status_code=422, detail={"code": "invalid_json", "message": "request body must be JSON"}) from None
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail={"code": "invalid_json", "message": "request body must be a JSON object"})
        return payload

    def resolve_auth_context(integration: Integration, payload: dict[str, Any], db: Session) -> tuple[User, User, str]:
        requested_username = payload.get("username")
        if not isinstance(requested_username, str) or not requested_username:
            raise HTTPException(status_code=422, detail={"code": "username_required"})
        if integration.principal_username and requested_username != integration.principal_username:
            raise HTTPException(status_code=403, detail={"code": "principal_binding_mismatch"})
        username = integration.principal_username or requested_username
        user = db.scalar(select(User).where(User.username == username))
        if not user:
            raise HTTPException(status_code=404, detail={"code": "unknown_user"})

        requested_approver = payload.get("approver_username")
        if requested_approver is not None and (not isinstance(requested_approver, str) or not requested_approver):
            raise HTTPException(status_code=422, detail={"code": "invalid_approver"})
        if integration.approver_username:
            if requested_approver and requested_approver != integration.approver_username:
                raise HTTPException(status_code=403, detail={"code": "approver_binding_mismatch"})
            approver_username = integration.approver_username
            if approver_username != username and not integration.principal_username:
                raise HTTPException(status_code=403, detail={"code": "delegated_principal_binding_required"})
        else:
            if requested_approver and requested_approver != username:
                raise HTTPException(status_code=403, detail={"code": "delegated_approver_not_bound"})
            approver_username = username
        approver_user = db.scalar(select(User).where(User.username == approver_username))
        if not approver_user:
            raise HTTPException(status_code=404, detail={"code": "unknown_approver"})

        requested_system = payload.get("system")
        if requested_system is not None and (not isinstance(requested_system, str) or not requested_system):
            raise HTTPException(status_code=422, detail={"code": "invalid_system"})
        if integration.system_name:
            if requested_system and requested_system != integration.system_name:
                raise HTTPException(status_code=403, detail={"code": "system_binding_mismatch"})
            system_name = integration.system_name
        else:
            system_name = requested_system or integration.name
        return user, approver_user, system_name

    async def create_auth_request(
        integration: Integration,
        payload: dict[str, Any],
        db: Session,
    ) -> dict[str, Any]:
        # All SQL runs in a worker thread; only fan-out and task scheduling stay
        # on the event loop. The source name lookup is cached and capped
        # (source_name_timeout_ms), so it never holds a login for long.
        try:
            source_name = await app.state.source_names.display_name(payload.get("source_ip"))
        except Exception:
            source_name = None
        result, publishes, retry = await run_in_threadpool(create_auth_request_sync, integration, payload, db, source_name)
        for device_id, event in publishes:
            await app.state.push_fanout.publish([device_id], event)
        if retry is not None:
            asyncio.create_task(push_with_retries(*retry))
        return result

    def create_auth_request_sync(
        integration: Integration,
        payload: dict[str, Any],
        db: Session,
        source_name: Any = None,
    ) -> tuple[dict[str, Any], list[tuple[str, dict[str, Any]]], tuple[str, list[str], int, int] | None]:
        publishes: list[tuple[str, dict[str, Any]]] = []
        retry: tuple[str, list[str], int, int] | None = None
        user, approver_user, system_name = resolve_auth_context(integration, payload, db)
        fail_mode = effective_fail_mode(db, user, integration)
        global_settings = effective_settings(db, user, integration)
        server_received_at = utcnow()
        expires_at = auth_request_expiry(
            payload,
            server_received_at,
            server_received_at + timedelta(seconds=global_settings["auth_ttl_seconds"]),
        )
        offline_code = payload.get("offline_code")
        if online_only(db, integration) and offline_code is not None:
            raise HTTPException(403, detail={"code": "online_approval_required"})
        pam_service = payload.get("pam_service") or "ssh"
        source_ip = payload.get("source_ip")
        attempt_id = auth_attempt_id(payload)
        status = "pending"
        factor = "push"
        detail = {
            "source_ip": source_ip,
            "geolocation": payload.get("geolocation"),
            "timestamp": utcnow().isoformat(),
            "approver_username": approver_user.username,
            "require_biometric": bool(global_settings.get("require_biometric")),
        }
        if attempt_id:
            detail["attempt_id"] = attempt_id
        if isinstance(source_name, str) and source_name and source_name != source_ip:
            detail["source_name"] = source_name
        if user.locked:
            status = "denied"
            factor = "lockout"
        elif approver_user.locked:
            status = "denied"
            factor = "approver_lockout"
        elif not offline_code and (trusted_grant := trusted_session_active(
            db,
            user,
            approver_user,
            integration,
            system_name,
            source_ip,
            pam_service,
            int(global_settings.get("trusted_session_window_seconds") or 0),
        )) is not None:
            status = "approved"
            factor = "trusted_session"
            # Preserve push provenance so consume rechecks concurrent revocation.
            trusted_device_id = trusted_grant.approved_by_device_id if trusted_grant.factor == "push" else None
        elif offline_code:
            totp_step = matching_totp_counter(user.totp_secret, str(offline_code)) if user.totp_secret else None
            if totp_step is not None:
                claimed = db.execute(
                    update(User)
                    .where(
                        User.id == user.id,
                        (User.totp_last_used_step.is_(None) | (User.totp_last_used_step < totp_step)),
                    )
                    .values(totp_last_used_step=totp_step)
                    .execution_options(synchronize_session=False)
                )
                if claimed.rowcount == 1:
                    user.totp_last_used_step = totp_step
                    status = "approved"
                    factor = "totp"
                else:
                    db.refresh(user, attribute_names=["totp_last_used_step"])
                    status = "denied"
                    factor = "totp_replay"
            else:
                consumed_at = utcnow()
                claimed = db.execute(
                    update(BackupCode)
                    .where(
                        BackupCode.user_id == user.id,
                        BackupCode.code_hash == hash_value(str(offline_code)),
                        BackupCode.used_at.is_(None),
                    )
                    .values(used_at=consumed_at)
                    .execution_options(synchronize_session=False)
                )
                if claimed.rowcount == 1:
                    status = "approved"
                    factor = "backup_code"
                else:
                    status = "denied"
                    factor = "offline_code"
        if status == "pending" and attempt_id:
            lock_pending_auth_context(db, user.id)
            duplicate = pending_duplicate(db, user, approver_user, integration, system_name, source_ip, pam_service, attempt_id)
            if duplicate:
                deadline_shortened = expires_at < aware(duplicate.expires_at)
                if deadline_shortened:
                    duplicate.expires_at = expires_at
                audit(
                    db,
                    "integration:" + integration.client_id,
                    "auth.deduplicate",
                    "auth_request",
                    duplicate.id,
                    {"username": user.username, "system": system_name, "pam_service": pam_service},
                )
                db.commit()
                app.state.auth_state.put_pending(
                    duplicate.id,
                    obj(duplicate),
                    pending_ttl(duplicate),
                )
                if deadline_shortened:
                    devices = db.scalars(
                        select(Device).where(
                            Device.user_id == approver_user.id,
                            Device.revoked.is_(False),
                            Device.public_key.is_not(None),
                        )
                    ).all()
                    device_ids = [device.id for device in devices]
                    for device in devices:
                        publishes.append((device.id, auth_event(duplicate, device, db)))
                    retry = (duplicate.id, device_ids, 0, pending_ttl(duplicate))
                return envelope(
                    {
                        "id": duplicate.id,
                        "status": duplicate.status,
                        "allowed": False,
                        "expires_at": utc_iso(duplicate.expires_at),
                        "fail_mode": duplicate.fail_mode_effective,
                        "approver_username": approver_user.username,
                        "cache": cache_payload(db, user, integration, duplicate.fail_mode_effective),
                        "duplicate": True,
                    }
                ), publishes, retry
        auth_req = AuthRequest(
            user_id=user.id,
            approver_user_id=approver_user.id,
            integration_id=integration.id,
            username=user.username,
            system=system_name,
            pam_service=pam_service,
            source_ip=source_ip,
            status=status,
            factor=factor,
            approved_by_device_id=trusted_device_id if factor == "trusted_session" else None,
            fail_mode_effective=fail_mode,
            detail=detail,
            expires_at=expires_at,
            decided_at=utcnow() if status != "pending" else None,
        )
        db.add(auth_req)
        db.flush()
        append_auth_log(db, auth_req)
        audit(
            db,
            "integration:" + integration.client_id,
            "auth.start",
            "auth_request",
            auth_req.id,
            {"username": user.username, "approver_username": approver_user.username, "status": status},
        )
        db.commit()
        if auth_req.status == "pending":
            app.state.auth_state.put_pending(auth_req.id, obj(auth_req), pending_ttl(auth_req))
        emit_auth_syslog(auth_req)
        if auth_req.status == "pending":
            SOURCE_LOG.info(
                "push_text request=%s text=%s requests %s on %s from %s",
                auth_req.id[:8],
                auth_req.username,
                auth_req.pam_service,
                auth_req.system,
                display_source(auth_req) or "-",
            )
            devices = db.scalars(
                select(Device).where(Device.user_id == approver_user.id, Device.revoked.is_(False), Device.public_key.is_not(None))
            ).all()
            device_ids = []
            for device in devices:
                event = auth_event(auth_req, device, db)
                publishes.append((device.id, event))
                device_ids.append(device.id)
            retry = (
                auth_req.id,
                device_ids,
                int(global_settings.get("push_retry_count") or 0),
                pending_ttl(auth_req),
            )
        return envelope(
            {
                "id": auth_req.id,
                "status": auth_req.status,
                "allowed": auth_req.status == "approved",
                "expires_at": utc_iso(auth_req.expires_at),
                "fail_mode": fail_mode,
                "approver_username": approver_user.username,
                "cache": cache_payload(db, user, integration, fail_mode),
            }
        ), publishes, retry

    @app.post("/api/v1/auth/requests", status_code=201)
    async def start_auth(request: Request, db: Session = Depends(get_db)):
        body = await request.body()
        integration = await run_in_threadpool(verify_integration_request, request, body, db)
        return await create_auth_request(integration, parse_auth_payload(body), db)

    @app.post("/api/v1/auth/preflight")
    async def auth_preflight(request: Request, db: Session = Depends(get_db)):
        body = await request.body()
        return await run_in_threadpool(auth_preflight_sync, request, body, db)

    def auth_preflight_sync(request: Request, body: bytes, db: Session) -> dict[str, Any]:
        integration = verify_integration_request(request, body, db)
        user, approver_user, system_name = resolve_auth_context(integration, parse_auth_payload(body), db)
        active_devices = []
        if not approver_user.locked:
            active_devices = db.scalars(
                select(Device).where(
                    Device.user_id == approver_user.id,
                    Device.revoked.is_(False),
                    Device.public_key.is_not(None),
                )
            ).all()
        return envelope(
            {
                "principal_username": user.username,
                "approver_username": approver_user.username,
                "system": system_name,
                "fail_mode": effective_fail_mode(db, user, integration),
                "principal_locked": user.locked,
                "approver_locked": approver_user.locked,
                "active_approver_devices": len(active_devices),
                "online_only": online_only(db, integration),
                "integration": {
                    "client_id": integration.client_id,
                    "principal_username": integration.principal_username,
                    "approver_username": integration.approver_username,
                    "system_name": integration.system_name,
                },
            }
        )

    async def wait_for_auth_resolution(request_id: str, wait_seconds: int) -> AuthRequest | None:
        def check() -> AuthRequest | None:
            with db_handle.SessionLocal() as wait_db:
                expire_unconsumed_auth_requests(wait_db)
                return wait_db.get(AuthRequest, request_id)

        deadline = time.monotonic() + max(0, wait_seconds)
        while True:
            auth_req = await run_in_threadpool(check)
            if not auth_req or auth_req.status != "pending":
                return auth_req
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return auth_req
            await asyncio.sleep(min(0.25, remaining))

    def lock_request_users(db: Session, auth_req: AuthRequest) -> dict[str, User]:
        # Same lock order as device decisions and lockout: users (by id), then
        # the request, then the approving device.
        approver_user_id = auth_req.approver_user_id or auth_req.user_id
        return {
            user.id: user
            for user in db.scalars(
                select(User)
                .where(User.id.in_({auth_req.user_id, approver_user_id}))
                .order_by(User.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            ).all()
        }

    def approval_revoked(db: Session, auth_req: AuthRequest, users: dict[str, User]) -> str | None:
        """Why a granted approval may no longer be used, or None."""
        approver_user_id = auth_req.approver_user_id or auth_req.user_id
        principal = users.get(auth_req.user_id)
        approver = users.get(approver_user_id)
        if not principal or principal.locked:
            return "lockout"
        if not approver or approver.locked:
            return "approver_lockout"
        if auth_req.approved_by_device_id:
            device = db.scalar(
                select(Device)
                .where(Device.id == auth_req.approved_by_device_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if not device or device.revoked or not device.public_key or device.user_id != approver_user_id:
                return "device_revoked"
        return None

    def consume_approved_request(
        request_id: str,
        integration: Integration,
        db: Session,
    ) -> tuple[AuthRequest | None, bool]:
        if db.get_bind().dialect.name == "sqlite":
            db.execute(text("BEGIN IMMEDIATE"))
        current = db.get(AuthRequest, request_id)
        if not current or current.integration_id != integration.id:
            return None, False
        users = lock_request_users(db, current)
        auth_req = db.scalar(
            select(AuthRequest)
            .where(AuthRequest.id == request_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if not auth_req or auth_req.integration_id != integration.id:
            return None, False
        if auth_req.consumed_at is not None:
            # One approval admits exactly one login: a repeated consume never
            # succeeds, whoever sends it and whatever its transport nonce.
            return auth_req, False

        consumed_at = utcnow()
        if consumed_at >= aware(auth_req.expires_at):
            if auth_req.status in {"pending", "approved"}:
                was_pending = auth_req.status == "pending"
                auth_req.status = "timeout"
                if was_pending:
                    auth_req.decided_at = consumed_at
                append_auth_log(db, auth_req)
                audit(
                    db,
                    "integration:" + integration.client_id,
                    "auth.consume_expired",
                    "auth_request",
                    auth_req.id,
                )
                db.commit()
                app.state.auth_state.delete(auth_req.id)
                emit_auth_syslog(auth_req)
                if was_pending:
                    schedule_resolution(auth_req)
                    app.state.unanswered_watch.unanswered(auth_req.id, auth_req.system)
            return auth_req, False
        if auth_req.status != "approved":
            return auth_req, False
        revoked = approval_revoked(db, auth_req, users)
        if revoked:
            auth_req.status = "denied"
            auth_req.factor = revoked
            append_auth_log(db, auth_req)
            audit(
                db,
                "integration:" + integration.client_id,
                "auth.consume_revoked",
                "auth_request",
                auth_req.id,
                {"reason": revoked},
            )
            db.commit()
            app.state.auth_state.delete(auth_req.id)
            emit_auth_syslog(auth_req)
            return auth_req, False

        auth_req.consumed_at = consumed_at
        audit(
            db,
            "integration:" + integration.client_id,
            "auth.consume",
            "auth_request",
            auth_req.id,
            {"consumed_at": consumed_at.isoformat()},
        )
        db.commit()
        return auth_req, True

    @app.post("/api/v1/proxy/verify")
    async def proxy_verify(request: Request, db: Session = Depends(get_db)):
        body = await request.body()
        integration = await run_in_threadpool(verify_integration_request, request, body, db)
        payload = parse_auth_payload(body)
        wait_value = payload.get("wait_seconds")
        try:
            requested_wait = int(wait_value) if wait_value is not None else None
        except (TypeError, ValueError):
            raise HTTPException(status_code=422, detail={"code": "bad_wait_seconds", "message": "wait_seconds must be an integer"}) from None
        if requested_wait is not None and requested_wait < 0:
            raise HTTPException(status_code=422, detail={"code": "bad_wait_seconds", "message": "wait_seconds must be non-negative"})

        started = await create_auth_request(integration, payload, db)
        # create_auth_request commits its durable work, but response assembly can
        # start a read transaction. Release that connection before long-polling.
        await run_in_threadpool(db.rollback)
        data = started["data"]
        request_id = data["id"]
        expires_at = aware(datetime.fromisoformat(data["expires_at"]))
        ttl_wait = max(0, int((expires_at - utcnow()).total_seconds()) + 1)
        wait_seconds = min(requested_wait if requested_wait is not None else ttl_wait, ttl_wait, 600)
        auth_req = await wait_for_auth_resolution(request_id, wait_seconds)
        if not auth_req:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        if auth_req.status == "approved":
            auth_req, consumed = await run_in_threadpool(consume_approved_request, request_id, integration, db)
            if not auth_req:
                raise HTTPException(status_code=404, detail={"code": "not_found"})
            if not consumed and auth_req.status == "approved":
                raise HTTPException(status_code=409, detail={"code": "auth_not_consumable"})
        return envelope(external_auth_payload(auth_req))

    @app.get("/api/v1/auth/requests/{request_id}")
    def poll_auth(request_id: str, request: Request, db: Session = Depends(get_db)):
        # Plain def: FastAPI runs it in the threadpool, off the event loop.
        body = b""
        integration = verify_integration_request(request, body, db)
        expire_unconsumed_auth_requests(db)
        auth_req = db.get(AuthRequest, request_id)
        if not auth_req or auth_req.integration_id != integration.id:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        user = db.get(User, auth_req.user_id)
        detail = auth_req.detail if isinstance(auth_req.detail, dict) else {}
        return envelope(
            {
                "id": auth_req.id,
                "status": auth_req.status,
                "allowed": auth_req.status == "approved",
                "fail_mode": auth_req.fail_mode_effective,
                "approver_username": detail.get("approver_username") or auth_req.username,
                "cache": cache_payload(db, user, integration, auth_req.fail_mode_effective),
            }
        )

    @app.post("/api/v1/auth/requests/{request_id}/consume")
    async def consume_auth(request_id: str, request: Request, db: Session = Depends(get_db)):
        body = await request.body()
        auth_req, consumed = await run_in_threadpool(consume_auth_sync, request_id, request, body, db)
        if not auth_req:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        if consumed:
            return envelope(
                {
                    "id": auth_req.id,
                    "status": auth_req.status,
                    "allowed": True,
                    "consumed": True,
                    "consumed_at": utc_iso(auth_req.consumed_at),
                }
            )
        raise HTTPException(
            status_code=409,
            detail={"code": "auth_not_consumable", "status": auth_req.status},
        )

    def consume_auth_sync(request_id: str, request: Request, body: bytes, db: Session) -> tuple[AuthRequest | None, bool]:
        integration = verify_integration_request(request, body, db)
        return consume_approved_request(request_id, integration, db)

    @app.post("/api/v1/auth/requests/{request_id}/decision")
    def decide(request_id: str, payload: DecisionIn, db: Session = Depends(get_db)):
        if db.get_bind().dialect.name == "sqlite":
            db.execute(text("BEGIN IMMEDIATE"))
        auth_req = db.get(AuthRequest, request_id)
        if not auth_req:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        approver_user_id = auth_req.approver_user_id or auth_req.user_id
        users = {
            user.id: user
            for user in db.scalars(
                select(User)
                .where(User.id.in_({auth_req.user_id, approver_user_id}))
                .order_by(User.id)
                .with_for_update()
            ).all()
        }
        principal_user = users.get(auth_req.user_id)
        approver_user = users.get(approver_user_id)
        auth_req = db.scalar(
            select(AuthRequest)
            .where(AuthRequest.id == request_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if not auth_req:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        device = db.scalar(select(Device).where(Device.id == payload.device_id).with_for_update())
        if not device or device.revoked or device.user_id != approver_user_id:
            raise HTTPException(status_code=403, detail={"code": "device_rejected"})
        if not device.public_key:
            raise HTTPException(status_code=403, detail={"code": "device_not_enrolled"})
        if not verify_device_signature(device.public_key, payload.signature, request_id, payload.decision, payload.biometric_verified, device.key_type):
            raise HTTPException(status_code=403, detail={"code": "bad_device_signature"})
        if not principal_user or principal_user.locked:
            raise HTTPException(status_code=403, detail={"code": "principal_locked"})
        if not approver_user or approver_user.locked:
            raise HTTPException(status_code=403, detail={"code": "approver_locked"})
        if auth_req.status != "pending":
            return envelope({"id": auth_req.id, "status": auth_req.status, "first_response_wins": True})
        biometric_required = payload.decision == "approve" and (device.require_biometric or request_requires_biometric(auth_req, db))
        if biometric_required and not payload.biometric_verified:
            raise HTTPException(status_code=403, detail={"code": "biometric_required", "message": "approval requires biometric or device credential"})
        decided_at = utcnow()
        next_status = "timeout" if decided_at >= aware(auth_req.expires_at) else ("approved" if payload.decision == "approve" else "denied")
        result = db.execute(
            update(AuthRequest)
            .where(AuthRequest.id == request_id, AuthRequest.status == "pending")
            .values(
                status=next_status,
                decided_at=decided_at,
                approved_by_device_id=device.id if next_status != "timeout" else None,
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            db.rollback()
            current = db.get(AuthRequest, request_id, populate_existing=True)
            if not current:
                raise HTTPException(status_code=404, detail={"code": "not_found"})
            return envelope({"id": current.id, "status": current.status, "first_response_wins": True})
        auth_req = db.get(AuthRequest, request_id, populate_existing=True)
        if not auth_req:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        audit(
            db,
            f"device:{device.id}",
            "auth.decision",
            "auth_request",
            auth_req.id,
            {"decision": payload.decision, "status": auth_req.status, "biometric_verified": payload.biometric_verified},
        )
        append_auth_log(db, auth_req)
        db.commit()
        app.state.auth_state.delete(auth_req.id)
        emit_auth_syslog(auth_req)
        schedule_resolution(auth_req)
        if auth_req.status in ("approved", "denied"):
            app.state.unanswered_watch.answered()
        return envelope({"id": auth_req.id, "status": auth_req.status, "allowed": auth_req.status == "approved"})

    def ws_authenticate(websocket: WebSocket, device_id: str) -> str | None:
        """Return the device public key when the signed handshake is valid."""
        with db_handle.SessionLocal() as db:
            device = db.get(Device, device_id)
            if not device or device.revoked:
                return None
            if verify_device_ws_handshake(websocket, db, device):
                return None
            public_key = device.public_key
            expire_unconsumed_auth_requests(db)
            return public_key

    def ws_pending_page(device_id: str, authenticated_public_key: str, cursor: str) -> tuple[bool, list[dict[str, Any]], str | None]:
        """One page of pending requests: (device still valid, events, next cursor)."""
        with db_handle.SessionLocal() as db:
            device = db.get(Device, device_id)
            if not device or device.revoked or device.public_key != authenticated_public_key:
                return False, [], None
            rows = db.scalars(
                select(AuthRequest)
                .where(
                    func.coalesce(AuthRequest.approver_user_id, AuthRequest.user_id) == device.user_id,
                    AuthRequest.status == "pending",
                    AuthRequest.expires_at > utcnow(),
                    AuthRequest.id > cursor,
                )
                .order_by(AuthRequest.id)
                .limit(100)
            ).all()
            data = [auth_event(r, device, db)["data"] for r in rows]
            next_cursor = rows[-1].id if len(rows) >= 100 else None
            return True, data, next_cursor

    def ws_reconcile(
        device_id: str,
        authenticated_public_key: str,
        known_pending: set[str],
    ) -> tuple[bool, list[dict[str, Any]], set[str]]:
        """Re-read shared DB state for a connected device.

        Another edge's fan-out never reaches this process, so a long-lived
        stream periodically sends any pending request it has not announced and
        an auth_decided event for any announced request that settled since.
        Returns (device still valid, events, pending ids now announced).
        """
        with db_handle.SessionLocal() as db:
            device = db.get(Device, device_id)
            if not device or device.revoked or device.public_key != authenticated_public_key:
                return False, [], known_pending
            rows = db.scalars(
                select(AuthRequest)
                .where(
                    func.coalesce(AuthRequest.approver_user_id, AuthRequest.user_id) == device.user_id,
                    AuthRequest.status == "pending",
                    AuthRequest.expires_at > utcnow(),
                )
                .order_by(AuthRequest.id)
                .limit(500)
            ).all()
            events = [auth_event(row, device, db) for row in rows if row.id not in known_pending]
            now_pending = {row.id for row in rows}
            gone = known_pending - now_pending
            if gone:
                for row in db.scalars(select(AuthRequest).where(AuthRequest.id.in_(gone))).all():
                    if row.status == "pending":
                        # Expired but not yet swept: report once it settles.
                        now_pending.add(row.id)
                        continue
                    events.append({
                        "type": "auth_decided",
                        "data": {
                            "id": row.id,
                            "status": row.status,
                            "decided_at": utc_iso(row.decided_at) if row.decided_at else None,
                        },
                    })
            return True, events, now_pending

    def ws_device_current(device_id: str, authenticated_public_key: str) -> bool:
        with db_handle.SessionLocal() as db:
            current = db.get(Device, device_id)
            return bool(current and not current.revoked and current.public_key == authenticated_public_key)

    @app.websocket("/api/v1/devices/{device_id}/ws")
    async def device_ws(websocket: WebSocket, device_id: str):
        queue = None
        receiver = None
        next_event = None
        authenticated_public_key = None
        try:
            authenticated_public_key = await run_in_threadpool(ws_authenticate, websocket, device_id)
            if authenticated_public_key is None:
                await websocket.close(code=1008)
                return
            await websocket.accept()
            try:
                queue = await app.state.push_fanout.subscribe(device_id)
            except (ConnectionError, TimeoutError):
                await websocket.close(code=1013)
                return
            cursor = ""
            known_pending: set[str] = set()
            while True:
                valid, data, next_cursor = await run_in_threadpool(ws_pending_page, device_id, authenticated_public_key, cursor)
                if not valid:
                    await websocket.close(code=1008)
                    return
                known_pending.update(row["id"] for row in data)
                try:
                    await websocket.send_json({"type": "pending", "data": data})
                except RuntimeError:
                    return
                if next_cursor is None:
                    break
                cursor = next_cursor
            # Receiving is required even for this server-to-phone stream: without
            # it a disconnected phone leaves a subscriber behind indefinitely.
            receiver = asyncio.create_task(websocket.receive())
            reconcile_every = max(0.1, float(settings.ws_reconcile_seconds))
            next_reconcile = time.monotonic() + reconcile_every
            while True:
                try:
                    if next_event is None:
                        next_event = asyncio.create_task(queue.get())
                    done, _ = await asyncio.wait(
                        (receiver, next_event),
                        timeout=max(0.0, next_reconcile - time.monotonic()),
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if receiver in done:
                        message = receiver.result()
                        if message["type"] == "websocket.disconnect":
                            return
                        # Client messages are not part of the approval protocol.
                        await websocket.close(code=1008)
                        return
                    if next_event in done:
                        event = next_event.result()
                        next_event = None
                        if isinstance(event, FanoutDisconnected):
                            await websocket.close(code=1013)
                            return
                        if not await run_in_threadpool(ws_device_current, device_id, authenticated_public_key):
                            await websocket.close(code=1008)
                            return
                        await websocket.send_json(event)
                        event_id = (event.get("data") or {}).get("id") if isinstance(event, dict) else None
                        if event_id and event.get("type") == "auth_request":
                            known_pending.add(event_id)
                        elif event_id and event.get("type") == "auth_decided":
                            known_pending.discard(event_id)
                    if time.monotonic() >= next_reconcile:
                        next_reconcile = time.monotonic() + reconcile_every
                        try:
                            valid, events, known_pending = await run_in_threadpool(
                                ws_reconcile, device_id, authenticated_public_key, set(known_pending)
                            )
                        except Exception as exc:
                            # A database blip (failover) must not drop a live
                            # stream; the next tick retries.
                            app.state.syslog.emit("ws_reconcile_error", {"device_id": device_id, "error": exc.__class__.__name__})
                            continue
                        if not valid:
                            await websocket.close(code=1008)
                            return
                        for reconciled in events:
                            await websocket.send_json(reconciled)
                except RuntimeError:
                    return
        except WebSocketDisconnect:
            return
        finally:
            for task in (receiver, next_event):
                if task is not None:
                    task.cancel()
            for task in (receiver, next_event):
                if task is not None:
                    with suppress(asyncio.CancelledError, WebSocketDisconnect):
                        await task
            if queue:
                app.state.push_fanout.unsubscribe(device_id, queue)

    if settings.static_dir:
        static_dir = Path(settings.static_dir)
        if static_dir.exists():
            app.mount("/", StaticFiles(directory=static_dir, html=True), name="admin-web")

    return app
