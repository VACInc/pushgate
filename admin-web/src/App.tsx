import type { FormEvent } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { ApiKey, AuditLog, AuthLog, BackupCode, Device, DeviceKind, FailMode, Group, Integration, Policy, Role, Settings, User } from "./api";
import { AdminApi } from "./api";
import { AppShell, type ScreenKey } from "./components/AppShell";
import { readSessionConnection, writeSessionConnection } from "./connectionSession";
import { EnrollmentQrModal, type EnrollmentQr } from "./components/EnrollmentQrModal";
import { Icon } from "./components/icons";
import { LoginScreen } from "./components/LoginScreen";
import { SecretModal } from "./components/SecretModal";
import { ConfirmDialog, ToastViewport, type Toast } from "./components/ui";
import { DashboardScreen } from "./screens/Dashboard";
import { DevicesScreen } from "./screens/Devices";
import { GroupsScreen } from "./screens/Groups";
import { IntegrationsScreen } from "./screens/Integrations";
import { LogsScreen } from "./screens/Logs";
import { PoliciesScreen } from "./screens/Policies";
import { RolesKeysScreen } from "./screens/RolesKeys";
import { SettingsScreen } from "./screens/Settings";
import { UsersScreen } from "./screens/Users";
import { readPersistentValue, writePersistentValue } from "./storage";
import { formBool, formNumber, formOptionalNumber, formText } from "./utils";

const sameOriginBaseUrl = typeof window === "undefined" ? "http://localhost:8000" : window.location.origin;
const defaultBaseUrl = import.meta.env.VITE_PUSHGATE_API ?? (import.meta.env.DEV ? "http://localhost:8000" : sameOriginBaseUrl);
const savedConnection = readSessionConnection(defaultBaseUrl);

type Theme = "dark" | "light";

type ConfirmState = {
  action: () => Promise<void>;
  confirmLabel?: string;
  description: string;
  success?: string;
  title: string;
  tone?: "danger" | "warning";
};

export function App() {
  const [baseUrl, setBaseUrl] = useState(savedConnection.baseUrl);
  const [token, setToken] = useState(savedConnection.token);
  const [theme, setTheme] = useState<Theme>(readTheme());
  const [activeScreen, setActiveScreen] = useState<ScreenKey>("dashboard");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => typeof window !== "undefined" && window.matchMedia("(max-width: 900px)").matches);
  const [connected, setConnected] = useState(false);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [groupMembers, setGroupMembers] = useState<User[]>([]);
  const [groupMemberGroupId, setGroupMemberGroupId] = useState("");
  const [devices, setDevices] = useState<Device[]>([]);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [backupCodes, setBackupCodes] = useState<BackupCode[]>([]);
  const [backupCodeUserId, setBackupCodeUserId] = useState("");
  const [authLogs, setAuthLogs] = useState<AuthLog[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [enrollmentQr, setEnrollmentQr] = useState<EnrollmentQr | null>(null);
  const [secretBlock, setSecretBlock] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<ConfirmState | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastId = useRef(0);

  const api = useMemo(() => new AdminApi(baseUrl, token), [baseUrl, token]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    writePersistentValue("admin.theme", theme);
  }, [theme]);

  useEffect(() => {
    void connect(baseUrl, token, { silent: true });
    // This intentionally runs once with the stored connection values.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadData(client: AdminApi) {
    const [nextSettings, nextUsers, nextGroups, nextDevices, nextIntegrations, nextPolicies, nextRoles, nextApiKeys, nextAuthLogs, nextAuditLogs] = await Promise.all([
      client.settings(),
      client.users(),
      client.groups(),
      client.devices(),
      client.integrations(),
      client.policies(),
      client.roles(),
      client.apiKeys(),
      client.authLogs(),
      client.auditLogs(),
    ]);
    setSettings(nextSettings);
    setUsers(nextUsers);
    setGroups(nextGroups);
    setDevices(nextDevices);
    setIntegrations(nextIntegrations);
    setPolicies(nextPolicies);
    setRoles(nextRoles);
    setApiKeys(nextApiKeys);
    setAuthLogs(nextAuthLogs);
    setAuditLogs(nextAuditLogs);
    setConnected(true);
  }

  async function connect(nextBaseUrl: string, nextToken: string, options: { silent?: boolean; success?: string } = {}) {
    setBusy(true);
    setError("");
    const nextApi = new AdminApi(nextBaseUrl, nextToken);
    try {
      await loadData(nextApi);
      const nextConnection = writeSessionConnection(nextBaseUrl, nextToken);
      setBaseUrl(nextConnection.baseUrl);
      setToken(nextConnection.token);
      if (options.success) addToast(options.success, "success");
      return true;
    } catch (err) {
      const message = errorMessage(err);
      setError(message);
      if (!settings) setConnected(false);
      if (!options.silent) addToast(message, "danger");
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function refresh() {
    return connect(baseUrl, token, { success: "Console refreshed" });
  }

  async function run(action: () => Promise<void>, success?: string) {
    setBusy(true);
    setError("");
    try {
      await action();
      if (success) addToast(success, "success");
      return true;
    } catch (err) {
      const message = errorMessage(err);
      setError(message);
      addToast(message, "danger");
      return false;
    } finally {
      setBusy(false);
    }
  }

  function addToast(message: string, tone: Toast["tone"]) {
    const id = ++toastId.current;
    setToasts((current) => [...current, { id, message, tone }]);
    window.setTimeout(() => setToasts((current) => current.filter((toast) => toast.id !== id)), 5200);
  }

  function askConfirm(confirmState: ConfirmState) {
    setConfirm(confirmState);
  }

  async function confirmCurrent() {
    const current = confirm;
    if (!current) return;
    setConfirm(null);
    await run(current.action, current.success);
  }

  async function copyText(value: string, label = "Copied") {
    try {
      await navigator.clipboard.writeText(value);
      addToast(label, "success");
    } catch {
      addToast("Copy failed", "danger");
    }
  }

  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    return run(async () => {
      await api.createUser({
        username: String(form.get("username")),
        display_name: String(form.get("display_name") || ""),
        fail_mode: maybeFailMode(form.get("fail_mode")),
      });
      formEl.reset();
      await loadData(api);
    }, "User created");
  }

  async function createGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    return run(async () => {
      await api.createGroup({ name: String(form.get("name")), description: String(form.get("description") || "") });
      formEl.reset();
      await loadData(api);
    }, "Group created");
  }

  async function addGroupUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    return run(async () => {
      const groupId = String(form.get("group_id"));
      await api.addGroupUser(groupId, String(form.get("user_id")));
      setGroupMemberGroupId(groupId);
      setGroupMembers(await api.groupUsers(groupId));
      formEl.reset();
      await loadData(api);
    }, "Group member added");
  }

  async function loadGroupMembersById(groupId: string) {
    if (!groupId) return false;
    return run(async () => {
      setGroupMemberGroupId(groupId);
      setGroupMembers(await api.groupUsers(groupId));
    }, "Group members loaded");
  }

  async function createDevice(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    return run(async () => {
      const device = await api.createDevice({
        user_id: String(form.get("user_id")),
        name: String(form.get("name")),
        kind: String(form.get("kind")) as DeviceKind,
        push_token: String(form.get("push_token") || ""),
        require_biometric: form.get("require_biometric") === "on",
      });
      showEnrollmentPayload(device);
      formEl.reset();
      await loadData(api);
    }, "Enrollment created");
  }

  async function createIntegration(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    return run(async () => {
      const integration = await api.createIntegration({
        name: String(form.get("name")),
        system_type: String(form.get("system_type") || "linux-pam"),
        principal_username: formText(form, "principal_username"),
        approver_username: formText(form, "approver_username"),
        system_name: formText(form, "system_name"),
        fail_mode: maybeFailMode(form.get("fail_mode")),
      });
      setEnrollmentQr(null);
      setSecretBlock(`Integration secret for ${integration.name}\n${integration.secret ?? ""}`);
      formEl.reset();
      await loadData(api);
    }, "Integration created");
  }

  async function createApiKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    return run(async () => {
      const key = await api.createApiKey({ name: String(form.get("name")), role: String(form.get("role")) as ApiKey["role"] });
      setEnrollmentQr(null);
      setSecretBlock(`API token for ${key.name}\n${key.token ?? ""}`);
      formEl.reset();
      await loadData(api);
    }, "API key created");
  }

  async function createPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    return run(async () => {
      await api.createPolicy({
        name: String(form.get("name")),
        description: formText(form, "description"),
        subject_type: String(form.get("subject_type")) as Policy["subject_type"],
        subject_id: formText(form, "subject_id"),
        fail_mode: maybeFailMode(form.get("fail_mode")),
        auth_ttl_seconds: formOptionalNumber(form, "auth_ttl_seconds"),
        push_retry_count: formOptionalNumber(form, "push_retry_count"),
        require_biometric: formBool(form, "require_biometric"),
        trusted_session_window_seconds: formOptionalNumber(form, "trusted_session_window_seconds"),
      });
      formEl.reset();
      await loadData(api);
    }, "Policy created");
  }

  async function createRole(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    return run(async () => {
      await api.createRole({
        name: String(form.get("name")),
        description: formText(form, "description"),
        permissions: {
          read: form.get("read") === "on",
          write: form.get("write") === "on",
          admin: form.get("admin") === "on",
        },
      });
      formEl.reset();
      await loadData(api);
    }, "Role created");
  }

  async function saveSettings(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    return run(async () => {
      setSettings(
        await api.patchSettings({
          global_fail_mode: String(form.get("global_fail_mode")) as FailMode,
          auth_ttl_seconds: Number(form.get("auth_ttl_seconds")),
          push_retry_count: Number(form.get("push_retry_count")),
          require_biometric: form.get("require_biometric") === "on",
          trusted_session_window_seconds: Number(form.get("trusted_session_window_seconds")),
        }),
      );
    }, "Global settings saved");
  }

  async function filterAuthLogs(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    return run(async () => {
      setAuthLogs(
        await api.authLogs({
          user: formText(form, "user"),
          system: formText(form, "system"),
          result: formText(form, "result"),
          from: formText(form, "from"),
          to: formText(form, "to"),
          limit: formNumber(form, "limit", 50),
          offset: formNumber(form, "offset", 0),
        }),
      );
    }, "Auth logs filtered");
  }

  async function filterAuditLogs(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    return run(async () => {
      setAuditLogs(
        await api.auditLogs({
          action: formText(form, "action"),
          resource_type: formText(form, "resource_type"),
          resource_id: formText(form, "resource_id"),
          limit: formNumber(form, "limit", 50),
          offset: formNumber(form, "offset", 0),
        }),
      );
    }, "Audit logs filtered");
  }

  async function setUserFailMode(user: User, value: string) {
    return run(async () => {
      const next = await api.patchUser(user.id, { fail_mode: failModeOrNull(value) });
      setUsers((current) => current.map((item) => (item.id === user.id ? next : item)));
    }, "User fail mode updated");
  }

  async function saveUserDisplayName(user: User, displayName: string) {
    return run(async () => {
      const next = await api.patchUser(user.id, { display_name: displayName || null });
      setUsers((current) => current.map((item) => (item.id === user.id ? next : item)));
    }, "User profile saved");
  }

  async function setLockout(user: User, locked: boolean) {
    return run(async () => {
      const next = locked ? await api.lockUser(user.id) : await api.unlockUser(user.id);
      setUsers((current) => current.map((item) => (item.id === user.id ? next : item)));
      await loadData(api);
    }, locked ? "User locked" : "User unlocked");
  }

  function issueTotp(user: User) {
    askConfirm({
      action: async () => {
        const totp = await api.enrollTotp(user.id);
        setEnrollmentQr(null);
        setSecretBlock(`TOTP for ${user.username}\n${totp.secret}\n${totp.uri}`);
      },
      confirmLabel: "Replace TOTP",
      description: `Create a new TOTP enrollment for ${user.username}? This replaces any existing TOTP secret, so current authenticator codes will stop working.`,
      success: "TOTP enrollment created",
      title: "Replace TOTP enrollment",
      tone: "warning",
    });
  }

  async function issueBackupCodes(user: User) {
    return run(async () => {
      const result = await api.createBackupCodes(user.id, 10);
      setEnrollmentQr(null);
      setSecretBlock(`Backup codes for ${user.username}\n${result.codes.join("\n")}`);
      setBackupCodeUserId(user.id);
      setBackupCodes(await api.backupCodes(user.id));
      await loadData(api);
    }, "Backup codes generated");
  }

  async function loadBackupCodesForUser(userId: string) {
    if (!userId) return false;
    return run(async () => {
      setBackupCodeUserId(userId);
      setBackupCodes(await api.backupCodes(userId));
    }, "Backup codes loaded");
  }

  function revokeBackupCode(code: BackupCode) {
    askConfirm({
      action: async () => {
        await api.deleteBackupCode(code.id);
        setBackupCodes(await api.backupCodes(code.user_id));
      },
      confirmLabel: "Revoke",
      description: "Revoke this backup code? The user will no longer be able to use it.",
      success: "Backup code revoked",
      title: "Revoke backup code",
      tone: "danger",
    });
  }

  function revokeBackupCodes() {
    if (!backupCodeUserId) return;
    askConfirm({
      action: async () => {
        await api.deleteBackupCodes(backupCodeUserId);
        setBackupCodes([]);
        await loadData(api);
      },
      confirmLabel: "Revoke all",
      description: "Revoke all loaded backup codes for this user? Newly generated codes will be required.",
      success: "Backup codes revoked",
      title: "Revoke all backup codes",
      tone: "danger",
    });
  }

  function removeUser(user: User) {
    askConfirm({
      action: async () => {
        await api.deleteUser(user.id);
        await loadData(api);
      },
      confirmLabel: "Delete user",
      description: `Delete ${user.username}? This removes the user from PushGate admin data.`,
      success: "User deleted",
      title: "Delete user",
      tone: "danger",
    });
  }

  function revokeDevice(device: Device) {
    askConfirm({
      action: async () => {
        await api.revokeDevice(device.id);
        await loadData(api);
      },
      confirmLabel: "Revoke",
      description: `Revoke ${device.name}? The device will no longer approve requests.`,
      success: "Device revoked",
      title: "Revoke device",
      tone: "danger",
    });
  }

  async function restoreDevice(device: Device) {
    return run(async () => {
      const next = await api.patchDevice(device.id, { revoked: false });
      setDevices((current) => current.map((item) => (item.id === device.id ? next : item)));
    }, "Device restored");
  }

  async function saveDevice(device: Device, changes: Partial<Pick<Device, "name" | "push_token">>) {
    return run(async () => {
      const next = await api.patchDevice(device.id, {
        name: changes.name,
        ...(changes.push_token !== undefined ? { push_token: changes.push_token || null } : {}),
      });
      setDevices((current) => current.map((item) => (item.id === device.id ? next : item)));
    }, "Device saved");
  }

  async function setDeviceBiometric(device: Device, requireBiometric: boolean) {
    return run(async () => {
      const next = await api.patchDevice(device.id, { require_biometric: requireBiometric });
      setDevices((current) => current.map((item) => (item.id === device.id ? next : item)));
    }, "Device biometric setting updated");
  }

  function rotateDevice(device: Device) {
    askConfirm({
      action: async () => {
        const rotated = await api.rotateDeviceKey(device.id);
        showEnrollmentPayload(rotated);
        await loadData(api);
      },
      confirmLabel: "Rotate",
      description: `Rotate enrollment for ${device.name}? This replaces its current enrollment material and shows a new payload.`,
      success: "Device enrollment rotated",
      title: "Rotate device enrollment",
      tone: "warning",
    });
  }

  async function setIntegrationFailMode(integration: Integration, value: string) {
    return run(async () => {
      const next = await api.patchIntegration(integration.id, { fail_mode: failModeOrNull(value) });
      setIntegrations((current) => current.map((item) => (item.id === integration.id ? next : item)));
    }, "Integration fail mode updated");
  }

  async function saveIntegrationDetails(
    integration: Integration,
    changes: Pick<Integration, "name" | "principal_username" | "approver_username" | "system_name">,
  ) {
    return run(async () => {
      const next = await api.patchIntegration(integration.id, changes);
      setIntegrations((current) => current.map((item) => (item.id === integration.id ? next : item)));
    }, "Integration saved");
  }

  async function setIntegrationEnabled(integration: Integration, enabled: boolean) {
    return run(async () => {
      const next = await api.patchIntegration(integration.id, { enabled });
      setIntegrations((current) => current.map((item) => (item.id === integration.id ? next : item)));
    }, enabled ? "Integration enabled" : "Integration disabled");
  }

  async function saveApiKeyName(key: ApiKey, name: string) {
    return run(async () => {
      const next = await api.patchApiKey(key.id, { name });
      setApiKeys((current) => current.map((item) => (item.id === key.id ? next : item)));
    }, "API key saved");
  }

  async function setApiKeyEnabled(key: ApiKey, enabled: boolean) {
    return run(async () => {
      const next = await api.patchApiKey(key.id, { enabled });
      setApiKeys((current) => current.map((item) => (item.id === key.id ? next : item)));
    }, enabled ? "API key enabled" : "API key disabled");
  }

  async function setApiKeyRole(key: ApiKey, role: string) {
    return run(async () => {
      const next = await api.patchApiKey(key.id, { role });
      setApiKeys((current) => current.map((item) => (item.id === key.id ? next : item)));
    }, "API key role updated");
  }

  async function setPolicyFailMode(policy: Policy, value: string) {
    return run(async () => {
      const next = await api.patchPolicy(policy.id, { fail_mode: failModeOrNull(value) });
      setPolicies((current) => current.map((item) => (item.id === policy.id ? next : item)));
    }, "Policy fail mode updated");
  }

  async function setPolicyEnabled(policy: Policy, enabled: boolean) {
    return run(async () => {
      const next = await api.patchPolicy(policy.id, { enabled });
      setPolicies((current) => current.map((item) => (item.id === policy.id ? next : item)));
    }, enabled ? "Policy enabled" : "Policy disabled");
  }

  function removePolicy(policy: Policy) {
    askConfirm({
      action: async () => {
        await api.deletePolicy(policy.id);
        await loadData(api);
      },
      confirmLabel: "Delete policy",
      description: `Delete policy ${policy.name}?`,
      success: "Policy deleted",
      title: "Delete policy",
      tone: "danger",
    });
  }

  async function setRolePermission(role: Role, permission: string, enabled: boolean) {
    return run(async () => {
      const next = await api.patchRole(role.id, { permissions: { ...role.permissions, [permission]: enabled } });
      setRoles((current) => current.map((item) => (item.id === role.id ? next : item)));
    }, "Role permission updated");
  }

  async function setRoleEnabled(role: Role, enabled: boolean) {
    return run(async () => {
      const next = await api.patchRole(role.id, { enabled });
      setRoles((current) => current.map((item) => (item.id === role.id ? next : item)));
    }, enabled ? "Role enabled" : "Role disabled");
  }

  function removeRole(role: Role) {
    askConfirm({
      action: async () => {
        await api.disableRole(role.id);
        await loadData(api);
      },
      confirmLabel: "Delete role",
      description: `Delete role ${role.name}? Existing API keys may need a different role.`,
      success: "Role deleted",
      title: "Delete role",
      tone: "danger",
    });
  }

  function removeGroup(group: Group) {
    askConfirm({
      action: async () => {
        await api.deleteGroup(group.id);
        if (groupMemberGroupId === group.id) {
          setGroupMemberGroupId("");
          setGroupMembers([]);
        }
        await loadData(api);
      },
      confirmLabel: "Delete group",
      description: `Delete group ${group.name}?`,
      success: "Group deleted",
      title: "Delete group",
      tone: "danger",
    });
  }

  async function saveGroup(group: Group, changes: Partial<Pick<Group, "name" | "description">>) {
    return run(async () => {
      const next = await api.patchGroup(group.id, {
        name: changes.name,
        description: changes.description || null,
      });
      setGroups((current) => current.map((item) => (item.id === group.id ? next : item)));
    }, "Group saved");
  }

  function removeGroupMember(user: User) {
    if (!groupMemberGroupId) return;
    askConfirm({
      action: async () => {
        await api.removeGroupUser(groupMemberGroupId, user.id);
        setGroupMembers(await api.groupUsers(groupMemberGroupId));
      },
      confirmLabel: "Remove",
      description: `Remove ${user.username} from the loaded group?`,
      success: "Group member removed",
      title: "Remove group member",
      tone: "warning",
    });
  }

  function showEnrollmentPayload(device: Device) {
    const payload = device.enrollment_qr_payload ?? "";
    setEnrollmentQr(payload ? { title: `Enrollment payload for ${device.name}`, payload } : null);
    setSecretBlock("");
  }

  function renderScreen() {
    switch (activeScreen) {
      case "dashboard":
        return <DashboardScreen auditLogs={auditLogs} authLogs={authLogs} devices={devices} onNavigate={setActiveScreen} settings={settings} users={users} />;
      case "users":
        return (
          <UsersScreen
            backupCodeUserId={backupCodeUserId}
            backupCodes={backupCodes}
            busy={busy}
            devices={devices}
            onBackupCodes={issueBackupCodes}
            onCreateDevice={createDevice}
            onCreateUser={createUser}
            onDelete={removeUser}
            onDisplayName={saveUserDisplayName}
            onFailMode={setUserFailMode}
            onLoadBackupCodes={loadBackupCodesForUser}
            onLockout={setLockout}
            onRevokeAllBackupCodes={revokeBackupCodes}
            onRevokeBackupCode={revokeBackupCode}
            onRevokeDevice={revokeDevice}
            onRestoreDevice={restoreDevice}
            onRotateDevice={rotateDevice}
            onTotp={issueTotp}
            users={users}
          />
        );
      case "devices":
        return <DevicesScreen busy={busy} devices={devices} onBiometric={setDeviceBiometric} onCreateDevice={createDevice} onRestore={restoreDevice} onRevoke={revokeDevice} onRotate={rotateDevice} onSave={saveDevice} users={users} />;
      case "integrations":
        return <IntegrationsScreen busy={busy} integrations={integrations} onCreateIntegration={createIntegration} onDetails={saveIntegrationDetails} onEnabled={setIntegrationEnabled} onFailMode={setIntegrationFailMode} />;
      case "policies":
        return <PoliciesScreen busy={busy} onCreatePolicy={createPolicy} onDelete={removePolicy} onEnabled={setPolicyEnabled} onFailMode={setPolicyFailMode} policies={policies} />;
      case "groups":
        return <GroupsScreen busy={busy} groupMemberGroupId={groupMemberGroupId} groupMembers={groupMembers} groups={groups} onAddGroupUser={addGroupUser} onCreateGroup={createGroup} onDelete={removeGroup} onLoadGroupMembers={loadGroupMembersById} onRemoveGroupMember={removeGroupMember} onSave={saveGroup} users={users} />;
      case "roles":
        return <RolesKeysScreen apiKeys={apiKeys} busy={busy} onApiKeyEnabled={setApiKeyEnabled} onApiKeyName={saveApiKeyName} onApiKeyRole={setApiKeyRole} onCreateApiKey={createApiKey} onCreateRole={createRole} onDeleteRole={removeRole} onRoleEnabled={setRoleEnabled} onRolePermission={setRolePermission} roles={roles} />;
      case "logs":
        return <LogsScreen auditLogs={auditLogs} authLogs={authLogs} busy={busy} onFilterAuditLogs={filterAuditLogs} onFilterAuthLogs={filterAuthLogs} />;
      case "settings":
        return <SettingsScreen baseUrl={baseUrl} busy={busy} onConnect={connect} onSaveSettings={saveSettings} settings={settings} token={token} />;
    }
  }

  if (!connected) {
    return (
      <>
        <LoginScreen baseUrl={baseUrl} busy={busy} error={error} onConnect={connect} onToggleTheme={() => setTheme((current) => (current === "dark" ? "light" : "dark"))} theme={theme} token={token} />
        <ToastViewport onDismiss={(id) => setToasts((current) => current.filter((toast) => toast.id !== id))} toasts={toasts} />
      </>
    );
  }

  return (
    <>
      <AppShell
        activeScreen={activeScreen}
        baseUrl={baseUrl}
        busy={busy}
        collapsed={sidebarCollapsed}
        identity={token.trim() ? "Bootstrap token" : "Proxy auth"}
        onNavigate={setActiveScreen}
        onRefresh={() => void refresh()}
        onToggleCollapsed={() => setSidebarCollapsed((current) => !current)}
        onToggleTheme={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}
        theme={theme}
      >
        {error && (
          <div className="inline-alert app-error" role="alert">
            <Icon name="alert" size={18} />
            <span>{error}</span>
          </div>
        )}
        {renderScreen()}
      </AppShell>

      <EnrollmentQrModal enrollment={enrollmentQr} onClose={() => setEnrollmentQr(null)} onCopy={copyText} />
      <SecretModal onClose={() => setSecretBlock("")} onCopy={copyText} secret={secretBlock} />
      <ConfirmDialog
        confirmLabel={confirm?.confirmLabel}
        description={confirm?.description ?? ""}
        onClose={() => setConfirm(null)}
        onConfirm={() => void confirmCurrent()}
        open={Boolean(confirm)}
        title={confirm?.title ?? "Confirm action"}
        tone={confirm?.tone}
      />
      <ToastViewport onDismiss={(id) => setToasts((current) => current.filter((toast) => toast.id !== id))} toasts={toasts} />
    </>
  );
}

function maybeFailMode(value: FormDataEntryValue | null): FailMode | undefined {
  return value === "open" || value === "closed" ? value : undefined;
}

function failModeOrNull(value: string): FailMode | null {
  return value === "open" || value === "closed" ? value : null;
}

function errorMessage(err: unknown) {
  return err instanceof Error ? err.message : "Request failed";
}

function readTheme(): Theme {
  const saved = readPersistentValue("admin.theme", "");
  return saved === "light" ? "light" : "dark";
}
