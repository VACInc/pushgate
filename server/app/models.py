from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def now() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fail_mode: Mapped[str | None] = mapped_column(String(16), nullable=True)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_last_used_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    locked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    devices: Mapped[list["Device"]] = relationship(back_populates="user")


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class UserGroup(Base):
    __tablename__ = "user_groups"
    __table_args__ = (UniqueConstraint("user_id", "group_id", name="uq_user_group"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"))
    group_id: Mapped[str] = mapped_column(String(36), ForeignKey("groups.id"))


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(32), default="phone")
    key_type: Mapped[str] = mapped_column(String(32), default="ed25519", server_default="ed25519")
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    push_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    enrollment_token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    enrollment_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    require_biometric: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="devices")


class Integration(Base):
    __tablename__ = "integrations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    client_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    secret: Mapped[str] = mapped_column(String(128))
    system_type: Mapped[str] = mapped_column(String(64), default="linux-pam")
    principal_username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approver_username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    system_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fail_mode: Mapped[str | None] = mapped_column(String(16), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ProvisionerScope(Base):
    """Operator-issued, immutable scope. No grants inherited from RBAC roles."""
    __tablename__ = "provisioner_scopes"

    api_key_id: Mapped[str] = mapped_column(String(36), ForeignKey("api_keys.id"), primary_key=True)
    principal_username: Mapped[str] = mapped_column(String(128))
    approver_username: Mapped[str] = mapped_column(String(128))
    systems: Mapped[list] = mapped_column(JSON)


class ProvisionedIntegration(Base):
    """Permanent system reservation and ownership, including disabled rollbacks."""
    __tablename__ = "provisioned_integrations"

    system_name: Mapped[str] = mapped_column(String(128), primary_key=True)
    integration_id: Mapped[str] = mapped_column(String(36), ForeignKey("integrations.id"), unique=True)
    api_key_id: Mapped[str] = mapped_column(String(36), ForeignKey("api_keys.id"))


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("subject_type", "subject_key", name="uq_policy_subject"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    subject_type: Mapped[str] = mapped_column(String(32))
    subject_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    subject_key: Mapped[str] = mapped_column(String(64), index=True)
    fail_mode: Mapped[str | None] = mapped_column(String(16), nullable=True)
    auth_ttl_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    push_retry_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    require_biometric: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    trusted_session_window_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    permissions: Mapped[dict] = mapped_column(JSON, default=dict)
    built_in: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    token_hash: Mapped[str] = mapped_column(String(128), unique=True)
    role: Mapped[str] = mapped_column(String(32), default="read-only")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class BackupCode(Base):
    __tablename__ = "backup_codes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    code_hash: Mapped[str] = mapped_column(String(128), unique=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Nonce(Base):
    __tablename__ = "nonces"
    __table_args__ = (UniqueConstraint("integration_id", "nonce", name="uq_integration_nonce"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    integration_id: Mapped[str] = mapped_column(String(36), ForeignKey("integrations.id"))
    nonce: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class DeviceNonce(Base):
    __tablename__ = "device_nonces"
    __table_args__ = (UniqueConstraint("device_id", "nonce", name="uq_device_nonce"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id"), index=True)
    nonce: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class AuthRequest(Base):
    __tablename__ = "auth_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    approver_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    integration_id: Mapped[str] = mapped_column(String(36), ForeignKey("integrations.id"), index=True)
    username: Mapped[str] = mapped_column(String(128), index=True)
    system: Mapped[str] = mapped_column(String(128))
    pam_service: Mapped[str] = mapped_column(String(64), default="ssh")
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    factor: Mapped[str] = mapped_column(String(32), default="push")
    fail_mode_effective: Mapped[str] = mapped_column(String(16), default="open")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by_device_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


class AuthLogEntry(Base):
    __tablename__ = "auth_log_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    auth_request_id: Mapped[str] = mapped_column(String(36), ForeignKey("auth_requests.id"), index=True)
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    approver_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    integration_id: Mapped[str] = mapped_column(String(36), index=True)
    username: Mapped[str] = mapped_column(String(128), index=True)
    system: Mapped[str] = mapped_column(String(128))
    pam_service: Mapped[str] = mapped_column(String(64), default="ssh")
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    factor: Mapped[str] = mapped_column(String(32), default="push")
    fail_mode_effective: Mapped[str] = mapped_column(String(16), default="open")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by_device_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(128))
    resource_type: Mapped[str] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
