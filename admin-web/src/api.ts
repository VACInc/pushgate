export type FailMode = "open" | "closed";
export type DeviceKind = "phone" | "wear";

export type Settings = {
  global_fail_mode: FailMode;
  auth_ttl_seconds: number;
  push_retry_count: number;
  require_biometric: boolean;
  trusted_session_window_seconds: number;
};

export type User = {
  id: string;
  username: string;
  display_name?: string | null;
  fail_mode?: FailMode | null;
  locked: boolean;
  created_at?: string;
};

export type Device = {
  id: string;
  user_id: string;
  name: string;
  kind: DeviceKind;
  public_key?: string | null;
  push_token?: string | null;
  push_token_configured: boolean;
  revoked: boolean;
  require_biometric: boolean;
  enrollment_qr_payload?: string;
};

export type Integration = {
  id: string;
  name: string;
  client_id: string;
  system_type: string;
  principal_username?: string | null;
  approver_username?: string | null;
  system_name?: string | null;
  fail_mode?: FailMode | null;
  enabled: boolean;
  secret?: string;
};

export type IntegrationCreate = {
  name: string;
  system_type: string;
  principal_username?: string;
  approver_username?: string;
  system_name?: string;
  fail_mode?: FailMode;
};

export type IntegrationPatch = Partial<Pick<Integration, "name" | "principal_username" | "approver_username" | "system_name" | "fail_mode" | "enabled">>;

export type Group = {
  id: string;
  name: string;
  description?: string | null;
};

export type Policy = {
  id: string;
  name: string;
  description?: string | null;
  subject_type: "global" | "user" | "integration";
  subject_id?: string | null;
  subject_key: string;
  fail_mode?: FailMode | null;
  auth_ttl_seconds?: number | null;
  push_retry_count?: number | null;
  require_biometric?: boolean | null;
  trusted_session_window_seconds?: number | null;
  enabled: boolean;
};

export type Role = {
  id: string;
  name: string;
  description?: string | null;
  permissions: Record<string, boolean>;
  built_in: boolean;
  enabled: boolean;
};

export type ApiKey = {
  id: string;
  name: string;
  role: string;
  enabled: boolean;
  created_at: string;
  last_used_at?: string | null;
  token?: string;
};

export type BackupCode = {
  id: string;
  user_id: string;
  used_at?: string | null;
  created_at: string;
};

export type AuthLog = {
  id: string;
  username: string;
  system: string;
  pam_service: string;
  source_ip?: string | null;
  status: string;
  factor: string;
  created_at: string;
};

export type AuditLog = {
  id: string;
  actor: string;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  created_at: string;
};

type Envelope<T> = { data: T; meta?: Record<string, unknown> };
type Query = Record<string, string | number | boolean | undefined | null>;
type LogQuery = {
  limit?: number;
  offset?: number;
  user?: string;
  system?: string;
  result?: string;
  from?: string;
  to?: string;
  action?: string;
  resource_type?: string;
  resource_id?: string;
};

export class AdminApi {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
  ) {}

  settings() {
    return this.get<Settings>("/api/admin/settings/global");
  }

  patchSettings(payload: Partial<Settings>) {
    return this.patch<Settings>("/api/admin/settings/global", payload);
  }

  users() {
    return this.get<User[]>("/api/admin/users");
  }

  createUser(payload: { username: string; display_name?: string; fail_mode?: FailMode }) {
    return this.post<User>("/api/admin/users", payload);
  }

  patchUser(id: string, payload: Partial<Pick<User, "display_name" | "fail_mode" | "locked">>) {
    return this.patch<User>(`/api/admin/users/${pathSegment(id)}`, payload);
  }

  deleteUser(id: string) {
    return this.delete(`/api/admin/users/${pathSegment(id)}`);
  }

  lockUser(id: string) {
    return this.post<User>(`/api/admin/users/${pathSegment(id)}/lockout`, {});
  }

  unlockUser(id: string) {
    return this.delete<User>(`/api/admin/users/${pathSegment(id)}/lockout`);
  }

  enrollTotp(userId: string) {
    return this.post<{ secret: string; uri: string }>(`/api/admin/users/${pathSegment(userId)}/totp`, {});
  }

  createBackupCodes(userId: string, count = 10) {
    return this.post<{ codes: string[] }>(`/api/admin/users/${pathSegment(userId)}/backup-codes`, {}, { count });
  }

  backupCodes(userId: string) {
    return this.get<BackupCode[]>(`/api/admin/users/${pathSegment(userId)}/backup-codes`);
  }

  deleteBackupCode(codeId: string) {
    return this.delete(`/api/admin/backup-codes/${pathSegment(codeId)}`);
  }

  deleteBackupCodes(userId: string) {
    return this.delete(`/api/admin/users/${pathSegment(userId)}/backup-codes`);
  }

  groups() {
    return this.get<Group[]>("/api/admin/groups");
  }

  createGroup(payload: { name: string; description?: string }) {
    return this.post<Group>("/api/admin/groups", payload);
  }

  patchGroup(id: string, payload: Partial<Pick<Group, "name" | "description">>) {
    return this.patch<Group>(`/api/admin/groups/${pathSegment(id)}`, payload);
  }

  deleteGroup(id: string) {
    return this.delete(`/api/admin/groups/${pathSegment(id)}`);
  }

  addGroupUser(groupId: string, userId: string) {
    return this.post(`/api/admin/groups/${pathSegment(groupId)}/users/${pathSegment(userId)}`, {});
  }

  groupUsers(groupId: string) {
    return this.get<User[]>(`/api/admin/groups/${pathSegment(groupId)}/users`);
  }

  removeGroupUser(groupId: string, userId: string) {
    return this.delete(`/api/admin/groups/${pathSegment(groupId)}/users/${pathSegment(userId)}`);
  }

  devices(userId?: string) {
    return this.get<Device[]>("/api/admin/devices", { user_id: userId });
  }

  createDevice(payload: { user_id: string; name: string; kind: DeviceKind; require_biometric: boolean; public_key?: string; push_token?: string }) {
    return this.post<Device>("/api/admin/devices", payload);
  }

  patchDevice(id: string, payload: Partial<Pick<Device, "name" | "push_token" | "revoked" | "require_biometric">>) {
    return this.patch<Device>(`/api/admin/devices/${pathSegment(id)}`, payload);
  }

  rotateDeviceKey(id: string) {
    return this.post<Device>(`/api/admin/devices/${pathSegment(id)}/rotation`, {});
  }

  revokeDevice(id: string) {
    return this.delete(`/api/admin/devices/${pathSegment(id)}`);
  }

  integrations() {
    return this.get<Integration[]>("/api/admin/integrations");
  }

  createIntegration(payload: IntegrationCreate) {
    return this.post<Integration>("/api/admin/integrations", payload);
  }

  patchIntegration(id: string, payload: IntegrationPatch) {
    return this.patch<Integration>(`/api/admin/integrations/${pathSegment(id)}`, payload);
  }

  disableIntegration(id: string) {
    return this.delete(`/api/admin/integrations/${pathSegment(id)}`);
  }

  policies() {
    return this.get<Policy[]>("/api/admin/policies");
  }

  createPolicy(payload: {
    name: string;
    description?: string;
    subject_type: Policy["subject_type"];
    subject_id?: string;
    fail_mode?: FailMode;
    auth_ttl_seconds?: number;
    push_retry_count?: number;
    require_biometric?: boolean;
    trusted_session_window_seconds?: number;
  }) {
    return this.post<Policy>("/api/admin/policies", payload);
  }

  patchPolicy(id: string, payload: Partial<Pick<Policy, "name" | "description" | "fail_mode" | "auth_ttl_seconds" | "push_retry_count" | "require_biometric" | "trusted_session_window_seconds" | "enabled">>) {
    return this.patch<Policy>(`/api/admin/policies/${pathSegment(id)}`, payload);
  }

  deletePolicy(id: string) {
    return this.delete(`/api/admin/policies/${pathSegment(id)}`);
  }

  roles() {
    return this.get<Role[]>("/api/admin/rbac/roles");
  }

  createRole(payload: { name: string; description?: string; permissions: Record<string, boolean> }) {
    return this.post<Role>("/api/admin/rbac/roles", payload);
  }

  patchRole(id: string, payload: Partial<Pick<Role, "description" | "permissions" | "enabled">>) {
    return this.patch<Role>(`/api/admin/rbac/roles/${pathSegment(id)}`, payload);
  }

  disableRole(id: string) {
    return this.delete(`/api/admin/rbac/roles/${pathSegment(id)}`);
  }

  apiKeys() {
    return this.get<ApiKey[]>("/api/admin/rbac/api-keys");
  }

  createApiKey(payload: { name: string; role: string }) {
    return this.post<ApiKey>("/api/admin/rbac/api-keys", payload);
  }

  patchApiKey(id: string, payload: Partial<Pick<ApiKey, "name" | "role" | "enabled">>) {
    return this.patch<ApiKey>(`/api/admin/rbac/api-keys/${pathSegment(id)}`, payload);
  }

  disableApiKey(id: string) {
    return this.delete(`/api/admin/rbac/api-keys/${pathSegment(id)}`);
  }

  authLogs(query: LogQuery = { limit: 50 }) {
    return this.get<AuthLog[]>("/api/admin/auth-logs", query);
  }

  auditLogs(query: LogQuery = { limit: 50 }) {
    return this.get<AuditLog[]>("/api/admin/audit-logs", query);
  }

  private get<T>(path: string, query?: Query) {
    return this.request<T>(path, { method: "GET", query });
  }

  private post<T>(path: string, body: unknown, query?: Query) {
    return this.request<T>(path, { method: "POST", body: JSON.stringify(body), query });
  }

  private patch<T>(path: string, body: unknown) {
    return this.request<T>(path, { method: "PATCH", body: JSON.stringify(body) });
  }

  private delete<T = void>(path: string) {
    return this.request<T>(path, { method: "DELETE" });
  }

  private async request<T>(path: string, init: RequestInit & { query?: Query } = {}): Promise<T> {
    const url = new URL(path, validateAdminBaseUrl(this.baseUrl));
    Object.entries(init.query ?? {}).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
    });

    const headers = new Headers(init.headers);
    if (this.token.trim()) headers.set("Authorization", `Bearer ${this.token.trim()}`);
    headers.set("Accept", "application/json");
    if (init.body) headers.set("Content-Type", "application/json");

    const response = await fetch(url, {
      ...init,
      cache: "no-store",
      credentials: "same-origin",
      headers,
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
    if (response.status === 204) return undefined as T;
    const payload = await response.json().catch(() => undefined);
    if (!response.ok) {
      throw new Error(apiErrorMessage(response, payload));
    }
    if (!isRecord(payload) || !Object.prototype.hasOwnProperty.call(payload, "data")) {
      throw new Error("Admin API returned an invalid response");
    }
    return (payload as Envelope<T>).data;
  }
}

function apiErrorMessage(response: Response, payload: unknown) {
  const detail = isRecord(payload) ? payload.detail : undefined;
  if (typeof detail === "string" && detail.trim()) return detail;
  if (isRecord(detail)) {
    if (typeof detail.message === "string" && detail.message.trim()) return detail.message;
    if (typeof detail.code === "string" && detail.code.trim()) return detail.code;
  }
  return response.statusText.trim() || `Admin API request failed (${response.status})`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function validateAdminBaseUrl(value: string) {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Admin API URL is invalid");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Admin API URL must use HTTPS");
  }
  if (url.username || url.password) {
    throw new Error("Admin API URL must not include credentials");
  }
  if (url.search || url.hash) {
    throw new Error("Admin API URL must not include a query or fragment");
  }
  if (url.pathname !== "/") {
    throw new Error("Admin API URL must not include a path");
  }
  if (url.protocol !== "https:" && !isLoopbackHost(url.hostname)) {
    throw new Error("Admin API URL must use HTTPS unless it targets localhost");
  }
  return url.origin + "/";
}

function isLoopbackHost(hostname: string) {
  return hostname === "localhost" || hostname.endsWith(".localhost") || hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(hostname);
}

function pathSegment(value: string) {
  return encodeURIComponent(value);
}
