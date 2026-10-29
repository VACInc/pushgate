from __future__ import annotations

import ipaddress
import math
import re
import ssl
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx


_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]*$")
_PERMISSION_NAMES = ("read", "write", "admin")
_MALFORMED_JSON = object()


class PushGateProtocolError(RuntimeError):
    """The server returned a successful response outside the SDK contract."""


def _is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _base_url(value: str, allow_insecure: bool) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("base_url must be a non-empty URL")
    try:
        url = httpx.URL(value)
    except (TypeError, httpx.InvalidURL) as exc:
        raise ValueError("base_url is not a valid URL") from exc
    if url.scheme not in {"http", "https"} or not url.host:
        raise ValueError("base_url must use http or https and include a host")
    if url.userinfo:
        raise ValueError("base_url must not contain credentials")
    if url.path not in {"", "/"} or url.query or url.fragment:
        raise ValueError("base_url must not contain a path, query, or fragment")
    if url.scheme == "http" and not allow_insecure and not _is_loopback(url.host):
        raise ValueError("plain HTTP is allowed only for loopback hosts; use HTTPS or allow_insecure=True")
    return str(url.copy_with(path="/")).rstrip("/")


def _token(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("token must be a non-empty string")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
        raise ValueError("token must contain only visible ASCII characters")
    return value


def _timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError("timeout must be a positive finite number")
    return float(value)


def _segment(value: str, field: str) -> str:
    if not isinstance(value, str) or not _PATH_SEGMENT.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"{field} is not a valid path identifier")
    return value


def _permissions(value: dict[str, bool]) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise TypeError("permissions must be a mapping")
    if any(not isinstance(name, str) for name in value):
        raise TypeError("permission names must be strings")
    unknown = set(value) - set(_PERMISSION_NAMES)
    if unknown:
        raise ValueError(f"unknown permissions: {', '.join(sorted(unknown))}")
    if any(type(setting) is not bool for setting in value.values()):
        raise TypeError("permission values must be booleans")
    return {name: value.get(name, False) for name in _PERMISSION_NAMES}


class PushGateAdminClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: float = 10.0,
        *,
        allow_insecure: bool = False,
        ssl_context: ssl.SSLContext | None = None,
    ):
        if type(allow_insecure) is not bool:
            raise TypeError("allow_insecure must be a boolean")
        if ssl_context is not None:
            if not isinstance(ssl_context, ssl.SSLContext):
                raise TypeError("ssl_context must be an SSLContext")
            if ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname:
                raise ValueError("ssl_context must require certificate and hostname verification")
        self._base_url = _base_url(base_url, allow_insecure)
        self.client = httpx.Client(
            base_url=self._base_url,
            timeout=_timeout(timeout),
            headers={"Authorization": f"Bearer {_token(token)}", "Accept": "application/json"},
            follow_redirects=False,
            trust_env=False,
            verify=ssl_context if ssl_context is not None else True,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base_url={self._base_url!r})"

    def __enter__(self) -> PushGateAdminClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.client.close()

    def _data(self, response: httpx.Response) -> Any:
        response.raise_for_status()
        if response.status_code == 204:
            return None
        if "application/json" not in response.headers.get("content-type", "").lower():
            raise PushGateProtocolError(f"PushGate returned non-JSON success response ({response.status_code})")
        try:
            payload = response.json()
        except ValueError:
            payload = _MALFORMED_JSON
        if payload is _MALFORMED_JSON:
            raise PushGateProtocolError(f"PushGate returned malformed JSON success response ({response.status_code})")
        if not isinstance(payload, dict) or "data" not in payload:
            raise PushGateProtocolError(f"PushGate success response is missing its data envelope ({response.status_code})")
        return payload["data"]

    def create_user(self, username: str, display_name: str | None = None, fail_mode: str | None = None) -> dict[str, Any]:
        return self._data(self.client.post("/api/admin/users", json={"username": username, "display_name": display_name, "fail_mode": fail_mode}))

    def users(self) -> list[dict[str, Any]]:
        return self._data(self.client.get("/api/admin/users"))

    def get_user(self, user_id: str) -> dict[str, Any]:
        return self._data(self.client.get(f"/api/admin/users/{_segment(user_id, 'user_id')}"))

    def set_user_fail_mode(self, user_id: str, fail_mode: str) -> dict[str, Any]:
        return self._data(self.client.patch(f"/api/admin/users/{_segment(user_id, 'user_id')}", json={"fail_mode": fail_mode}))

    def lock_user(self, user_id: str) -> dict[str, Any]:
        return self._data(self.client.post(f"/api/admin/users/{_segment(user_id, 'user_id')}/lockout"))

    def unlock_user(self, user_id: str) -> dict[str, Any]:
        return self._data(self.client.delete(f"/api/admin/users/{_segment(user_id, 'user_id')}/lockout"))

    def enroll_totp(self, user_id: str) -> dict[str, Any]:
        return self._data(self.client.post(f"/api/admin/users/{_segment(user_id, 'user_id')}/totp"))

    def create_backup_codes(self, user_id: str, count: int = 10) -> dict[str, Any]:
        return self._data(self.client.post(f"/api/admin/users/{_segment(user_id, 'user_id')}/backup-codes", params={"count": count}))

    def backup_codes(self, user_id: str) -> list[dict[str, Any]]:
        return self._data(self.client.get(f"/api/admin/users/{_segment(user_id, 'user_id')}/backup-codes"))

    def delete_backup_code(self, code_id: str) -> None:
        self._data(self.client.delete(f"/api/admin/backup-codes/{_segment(code_id, 'code_id')}"))

    def delete_backup_codes(self, user_id: str) -> None:
        self._data(self.client.delete(f"/api/admin/users/{_segment(user_id, 'user_id')}/backup-codes"))

    def create_group(self, name: str, description: str | None = None) -> dict[str, Any]:
        return self._data(self.client.post("/api/admin/groups", json={"name": name, "description": description}))

    def get_group(self, group_id: str) -> dict[str, Any]:
        return self._data(self.client.get(f"/api/admin/groups/{_segment(group_id, 'group_id')}"))

    def update_group(self, group_id: str, **changes: Any) -> dict[str, Any]:
        return self._data(self.client.patch(f"/api/admin/groups/{_segment(group_id, 'group_id')}", json=changes))

    def delete_group(self, group_id: str) -> None:
        self._data(self.client.delete(f"/api/admin/groups/{_segment(group_id, 'group_id')}"))

    def group_users(self, group_id: str) -> list[dict[str, Any]]:
        return self._data(self.client.get(f"/api/admin/groups/{_segment(group_id, 'group_id')}/users"))

    def add_group_user(self, group_id: str, user_id: str) -> dict[str, Any]:
        return self._data(
            self.client.post(
                f"/api/admin/groups/{_segment(group_id, 'group_id')}/users/{_segment(user_id, 'user_id')}"
            )
        )

    def remove_group_user(self, group_id: str, user_id: str) -> None:
        self._data(
            self.client.delete(
                f"/api/admin/groups/{_segment(group_id, 'group_id')}/users/{_segment(user_id, 'user_id')}"
            )
        )

    def create_device(
        self,
        user_id: str,
        name: str,
        kind: str = "phone",
        require_biometric: bool = False,
        public_key: str | None = None,
        push_token: str | None = None,
        key_type: str = "ed25519",
    ) -> dict[str, Any]:
        return self._data(
            self.client.post(
                "/api/admin/devices",
                json={
                    "user_id": user_id,
                    "name": name,
                    "kind": kind,
                    "require_biometric": require_biometric,
                    "key_type": key_type,
                    "public_key": public_key,
                    "push_token": push_token,
                },
            )
        )

    def devices(self, user_id: str | None = None) -> list[dict[str, Any]]:
        params = {"user_id": user_id} if user_id else None
        return self._data(self.client.get("/api/admin/devices", params=params))

    def get_device(self, device_id: str) -> dict[str, Any]:
        return self._data(self.client.get(f"/api/admin/devices/{_segment(device_id, 'device_id')}"))

    def update_device(self, device_id: str, **changes: Any) -> dict[str, Any]:
        return self._data(self.client.patch(f"/api/admin/devices/{_segment(device_id, 'device_id')}", json=changes))

    def revoke_device(self, device_id: str) -> None:
        self._data(self.client.delete(f"/api/admin/devices/{_segment(device_id, 'device_id')}"))

    def rotate_device_key(self, device_id: str) -> dict[str, Any]:
        return self._data(self.client.post(f"/api/admin/devices/{_segment(device_id, 'device_id')}/rotation"))

    def create_integration(
        self,
        name: str,
        client_id: str | None = None,
        fail_mode: str | None = None,
        system_type: str = "linux-pam",
        enabled: bool = True,
        principal_username: str | None = None,
        approver_username: str | None = None,
        system_name: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "name": name,
            "client_id": client_id,
            "fail_mode": fail_mode,
            "system_type": system_type,
            "enabled": enabled,
        }
        if principal_username is not None:
            payload["principal_username"] = principal_username
        if approver_username is not None:
            payload["approver_username"] = approver_username
        if system_name is not None:
            payload["system_name"] = system_name
        return self._data(self.client.post("/api/admin/integrations", json=payload))

    def integrations(self) -> list[dict[str, Any]]:
        return self._data(self.client.get("/api/admin/integrations"))

    def get_integration(self, integration_id: str) -> dict[str, Any]:
        return self._data(self.client.get(f"/api/admin/integrations/{_segment(integration_id, 'integration_id')}"))

    def update_integration(self, integration_id: str, **changes: Any) -> dict[str, Any]:
        return self._data(self.client.patch(f"/api/admin/integrations/{_segment(integration_id, 'integration_id')}", json=changes))

    def delete_integration(self, integration_id: str) -> None:
        self._data(self.client.delete(f"/api/admin/integrations/{_segment(integration_id, 'integration_id')}"))

    def policies(self, subject_type: str | None = None, subject_id: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {}
        if subject_type:
            params["subject_type"] = subject_type
        if subject_id:
            params["subject_id"] = subject_id
        return self._data(self.client.get("/api/admin/policies", params=params))

    def create_policy(self, name: str, subject_type: str, subject_id: str | None = None, **settings: Any) -> dict[str, Any]:
        payload = {"name": name, "subject_type": subject_type, "subject_id": subject_id, **settings}
        return self._data(self.client.post("/api/admin/policies", json=payload))

    def get_policy(self, policy_id: str) -> dict[str, Any]:
        return self._data(self.client.get(f"/api/admin/policies/{_segment(policy_id, 'policy_id')}"))

    def update_policy(self, policy_id: str, **changes: Any) -> dict[str, Any]:
        return self._data(self.client.patch(f"/api/admin/policies/{_segment(policy_id, 'policy_id')}", json=changes))

    def delete_policy(self, policy_id: str) -> None:
        self._data(self.client.delete(f"/api/admin/policies/{_segment(policy_id, 'policy_id')}"))

    def roles(self) -> list[dict[str, Any]]:
        return self._data(self.client.get("/api/admin/rbac/roles"))

    def create_role(self, name: str, permissions: dict[str, bool], description: str | None = None, enabled: bool = True) -> dict[str, Any]:
        return self._data(
            self.client.post(
                "/api/admin/rbac/roles",
                json={"name": name, "description": description, "permissions": _permissions(permissions), "enabled": enabled},
            )
        )

    def get_role(self, role_id: str) -> dict[str, Any]:
        return self._data(self.client.get(f"/api/admin/rbac/roles/{_segment(role_id, 'role_id')}"))

    def update_role(self, role_id: str, **changes: Any) -> dict[str, Any]:
        if changes.get("permissions") is not None:
            changes["permissions"] = _permissions(changes["permissions"])
        return self._data(self.client.patch(f"/api/admin/rbac/roles/{_segment(role_id, 'role_id')}", json=changes))

    def delete_role(self, role_id: str) -> None:
        self._data(self.client.delete(f"/api/admin/rbac/roles/{_segment(role_id, 'role_id')}"))

    def api_keys(self) -> list[dict[str, Any]]:
        return self._data(self.client.get("/api/admin/rbac/api-keys"))

    def create_api_key(self, name: str, role: str = "read-only") -> dict[str, Any]:
        return self._data(self.client.post("/api/admin/rbac/api-keys", json={"name": name, "role": role}))

    def get_api_key(self, key_id: str) -> dict[str, Any]:
        return self._data(self.client.get(f"/api/admin/rbac/api-keys/{_segment(key_id, 'key_id')}"))

    def update_api_key(self, key_id: str, **changes: Any) -> dict[str, Any]:
        return self._data(self.client.patch(f"/api/admin/rbac/api-keys/{_segment(key_id, 'key_id')}", json=changes))

    def delete_api_key(self, key_id: str) -> None:
        self._data(self.client.delete(f"/api/admin/rbac/api-keys/{_segment(key_id, 'key_id')}"))

    def auth_logs(
        self,
        user: str | None = None,
        system: str | None = None,
        result: str | None = None,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if user:
            params["user"] = user
        if system:
            params["system"] = system
        if result:
            params["result"] = result
        if from_time:
            params["from"] = from_time.isoformat()
        if to_time:
            params["to"] = to_time.isoformat()
        return self._data(self.client.get("/api/admin/auth-logs", params=params))

    def audit_logs(
        self,
        action: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if action:
            params["action"] = action
        if resource_type:
            params["resource_type"] = resource_type
        if resource_id:
            params["resource_id"] = resource_id
        return self._data(self.client.get("/api/admin/audit-logs", params=params))

    def denials_last_24h(self) -> list[dict[str, Any]]:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        return self.auth_logs(result="denied", from_time=cutoff, limit=500)

    def global_settings(self) -> dict[str, Any]:
        return self._data(self.client.get("/api/admin/settings/global"))

    def update_global_settings(self, **settings: Any) -> dict[str, Any]:
        return self._data(self.client.patch("/api/admin/settings/global", json=settings))
