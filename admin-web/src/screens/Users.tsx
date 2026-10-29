import type { FormEvent } from "react";
import { useEffect, useMemo, useState } from "react";
import type { BackupCode, Device, User } from "../api";
import { FailModeSelect } from "../components/forms";
import { Button, Card, Chip, Drawer, EmptyState, Field, IconButton, Input, Modal, SearchField, SectionHeader, Select, Toggle } from "../components/ui";
import { formatDateTime, shortId, statusTone } from "../utils";

export function UsersScreen(props: {
  backupCodeUserId: string;
  backupCodes: BackupCode[];
  busy: boolean;
  devices: Device[];
  onBackupCodes: (user: User) => Promise<boolean>;
  onCreateDevice: (event: FormEvent<HTMLFormElement>) => Promise<boolean>;
  onCreateUser: (event: FormEvent<HTMLFormElement>) => Promise<boolean>;
  onDelete: (user: User) => void;
  onDisplayName: (user: User, displayName: string) => Promise<boolean>;
  onFailMode: (user: User, value: string) => Promise<boolean>;
  onLoadBackupCodes: (userId: string) => Promise<boolean>;
  onLockout: (user: User, locked: boolean) => Promise<boolean>;
  onRevokeAllBackupCodes: () => void;
  onRevokeBackupCode: (code: BackupCode) => void;
  onRevokeDevice: (device: Device) => void;
  onRestoreDevice: (device: Device) => Promise<boolean>;
  onRotateDevice: (device: Device) => void;
  onTotp: (user: User) => void;
  users: User[];
}) {
  const [createOpen, setCreateOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [selectedUserId, setSelectedUserId] = useState("");
  const selectedUser = props.users.find((user) => user.id === selectedUserId) ?? null;
  const filteredUsers = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return props.users;
    return props.users.filter((user) => [user.username, user.display_name, user.id, user.fail_mode].some((value) => String(value ?? "").toLowerCase().includes(needle)));
  }, [props.users, query]);

  useEffect(() => {
    if (selectedUserId && !selectedUser) setSelectedUserId("");
  }, [selectedUser, selectedUserId]);

  async function submitCreate(event: FormEvent<HTMLFormElement>) {
    if (await props.onCreateUser(event)) setCreateOpen(false);
  }

  return (
    <div className="screen-stack">
      <SectionHeader
        actions={
          <Button icon="plus" onClick={() => setCreateOpen(true)}>
            New user
          </Button>
        }
        description="Manage identities, lockouts, enrollment factors, backup codes, and per-user fail mode overrides."
        eyebrow="Directory"
        title="Users"
      />

      <Card>
        <div className="table-toolbar">
          <SearchField onChange={setQuery} placeholder="Search users" value={query} />
          <Chip tone="info">{filteredUsers.length} shown</Chip>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Fail mode</th>
                <th>State</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.map((user) => (
                <UserRow
                  busy={props.busy}
                  key={user.id}
                  onDelete={props.onDelete}
                  onFailMode={props.onFailMode}
                  onLockout={props.onLockout}
                  onManage={() => setSelectedUserId(user.id)}
                  user={user}
                />
              ))}
            </tbody>
          </table>
        </div>
        {!filteredUsers.length && <EmptyState description="Create a user before enrolling devices or issuing backup factors." title="No users found" />}
      </Card>

      <CreateUserModal busy={props.busy} onClose={() => setCreateOpen(false)} onSubmit={submitCreate} open={createOpen} />

      <UserDetailDrawer
        backupCodeUserId={props.backupCodeUserId}
        backupCodes={props.backupCodes}
        busy={props.busy}
        devices={props.devices.filter((device) => device.user_id === selectedUser?.id)}
        onBackupCodes={props.onBackupCodes}
        onClose={() => setSelectedUserId("")}
        onCreateDevice={props.onCreateDevice}
        onDelete={props.onDelete}
        onDisplayName={props.onDisplayName}
        onFailMode={props.onFailMode}
        onLoadBackupCodes={props.onLoadBackupCodes}
        onLockout={props.onLockout}
        onRevokeAllBackupCodes={props.onRevokeAllBackupCodes}
        onRevokeBackupCode={props.onRevokeBackupCode}
        onRevokeDevice={props.onRevokeDevice}
        onRestoreDevice={props.onRestoreDevice}
        onRotateDevice={props.onRotateDevice}
        onTotp={props.onTotp}
        user={selectedUser}
      />
    </div>
  );
}

function UserRow(props: {
  busy: boolean;
  onDelete: (user: User) => void;
  onFailMode: (user: User, value: string) => Promise<boolean>;
  onLockout: (user: User, locked: boolean) => Promise<boolean>;
  onManage: () => void;
  user: User;
}) {
  return (
    <tr>
      <td>
        <div className="entity-cell">
          <strong>{props.user.username}</strong>
          <span>{props.user.display_name || "No display name"}</span>
          <span className="mono">{shortId(props.user.id)}</span>
        </div>
      </td>
      <td>
        <FailModeSelect disabled={props.busy} onChange={(value) => void props.onFailMode(props.user, value)} value={props.user.fail_mode ?? ""} />
      </td>
      <td>
        <Chip tone={props.user.locked ? "danger" : "success"}>{props.user.locked ? "Locked" : "Active"}</Chip>
      </td>
      <td>
        <div className="row-actions">
          <IconButton
            disabled={props.busy}
            icon={props.user.locked ? "unlock" : "lock"}
            label={props.user.locked ? "Unlock user" : "Lock user"}
            onClick={() => void props.onLockout(props.user, !props.user.locked)}
            size="sm"
            variant="ghost"
          />
          <IconButton disabled={props.busy} icon="trash" label="Delete user" onClick={() => props.onDelete(props.user)} size="sm" variant="ghost" />
          <Button disabled={props.busy} onClick={props.onManage} size="sm" variant="secondary">
            Manage
          </Button>
        </div>
      </td>
    </tr>
  );
}

function CreateUserModal(props: { busy: boolean; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; open: boolean }) {
  return (
    <Modal description="Create an identity that can enroll PushGate factors." onClose={props.onClose} open={props.open} title="New user">
      <form className="form-stack" onSubmit={props.onSubmit}>
        <Field label="Username">
          <Input autoComplete="username" name="username" required />
        </Field>
        <Field label="Display name">
          <Input name="display_name" />
        </Field>
        <Field label="Fail mode override">
          <FailModeSelect defaultValue="" name="fail_mode" />
        </Field>
        <div className="form-actions">
          <Button onClick={props.onClose} variant="secondary">
            Cancel
          </Button>
          <Button disabled={props.busy} icon="plus" type="submit">
            Create user
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function UserDetailDrawer(props: {
  backupCodeUserId: string;
  backupCodes: BackupCode[];
  busy: boolean;
  devices: Device[];
  onBackupCodes: (user: User) => Promise<boolean>;
  onClose: () => void;
  onCreateDevice: (event: FormEvent<HTMLFormElement>) => Promise<boolean>;
  onDelete: (user: User) => void;
  onDisplayName: (user: User, displayName: string) => Promise<boolean>;
  onFailMode: (user: User, value: string) => Promise<boolean>;
  onLoadBackupCodes: (userId: string) => Promise<boolean>;
  onLockout: (user: User, locked: boolean) => Promise<boolean>;
  onRevokeAllBackupCodes: () => void;
  onRevokeBackupCode: (code: BackupCode) => void;
  onRevokeDevice: (device: Device) => void;
  onRestoreDevice: (device: Device) => Promise<boolean>;
  onRotateDevice: (device: Device) => void;
  onTotp: (user: User) => void;
  user: User | null;
}) {
  const [displayName, setDisplayName] = useState("");
  const [enrollOpen, setEnrollOpen] = useState(false);
  const visibleBackupCodes = props.backupCodeUserId === props.user?.id ? props.backupCodes : [];

  useEffect(() => {
    setDisplayName(props.user?.display_name ?? "");
  }, [props.user]);

  async function submitDevice(event: FormEvent<HTMLFormElement>) {
    if (await props.onCreateDevice(event)) setEnrollOpen(false);
  }

  return (
    <Drawer description={props.user ? `${props.user.id}` : ""} onClose={props.onClose} open={Boolean(props.user)} title={props.user?.username ?? "User"}>
      {props.user && (
        <div className="detail-stack">
          <section className="profile-header">
            <div>
              <strong>{props.user.display_name || props.user.username}</strong>
              <span className="mono">{props.user.id}</span>
            </div>
            <Chip tone={statusTone(props.user.locked ? "locked" : "active")}>{props.user.locked ? "Locked" : "Active"}</Chip>
          </section>

          <section className="detail-panel">
            <h3>Profile controls</h3>
            <div className="form-grid">
              <Field label="Display name">
                <Input onChange={(event) => setDisplayName(event.target.value)} value={displayName} />
              </Field>
              <Field label="Fail mode">
                <FailModeSelect disabled={props.busy} onChange={(value) => void props.onFailMode(props.user!, value)} value={props.user.fail_mode ?? ""} />
              </Field>
            </div>
            <div className="button-row">
              <Button disabled={props.busy || displayName === (props.user.display_name ?? "")} onClick={() => void props.onDisplayName(props.user!, displayName.trim())} variant="secondary">
                Save profile
              </Button>
              <Button disabled={props.busy} icon={props.user.locked ? "unlock" : "lock"} onClick={() => void props.onLockout(props.user!, !props.user!.locked)} variant="secondary">
                {props.user.locked ? "Unlock user" : "Lock user"}
              </Button>
              <Button disabled={props.busy} icon="trash" onClick={() => props.onDelete(props.user!)} variant="danger">
                Delete
              </Button>
            </div>
          </section>

          <section className="detail-panel">
            <div className="panel-title-row">
              <div>
                <h3>Devices</h3>
                <p>{props.devices.length} enrolled for this user.</p>
              </div>
              <Button icon="plus" onClick={() => setEnrollOpen(true)} size="sm">
                Enroll device
              </Button>
            </div>
            <div className="compact-list">
              {props.devices.map((device) => (
                <article key={device.id}>
                  <div>
                    <strong>{device.name}</strong>
                    <span>{device.kind} · <span className="mono">{shortId(device.id)}</span></span>
                  </div>
                  <Chip tone={device.revoked ? "danger" : "success"}>{device.revoked ? "Revoked" : "Active"}</Chip>
                  <div className="button-row">
                    <Button disabled={props.busy || device.revoked} onClick={() => props.onRotateDevice(device)} size="sm" variant="secondary">
                      Rotate
                    </Button>
                    <Button disabled={props.busy} onClick={() => (device.revoked ? void props.onRestoreDevice(device) : props.onRevokeDevice(device))} size="sm" variant="secondary">
                      {device.revoked ? "Restore" : "Revoke"}
                    </Button>
                  </div>
                </article>
              ))}
              {!props.devices.length && <EmptyState description="Enroll a phone or wearable to start receiving PushGate approvals." title="No devices" />}
            </div>
          </section>

          <section className="detail-panel">
            <h3>Backup factors</h3>
            <div className="button-row">
              <Button disabled={props.busy} onClick={() => props.onTotp(props.user!)} variant="secondary">
                Enroll TOTP
              </Button>
              <Button disabled={props.busy} onClick={() => void props.onBackupCodes(props.user!)} variant="secondary">
                Generate backup codes
              </Button>
              <Button disabled={props.busy} onClick={() => void props.onLoadBackupCodes(props.user!.id)} variant="secondary">
                Load codes
              </Button>
              <Button disabled={props.busy || !visibleBackupCodes.length} onClick={props.onRevokeAllBackupCodes} variant="danger">
                Revoke all
              </Button>
            </div>
            <div className="compact-list">
              {visibleBackupCodes.map((code) => (
                <article key={code.id}>
                  <div>
                    <strong className="mono">{shortId(code.id, 12)}</strong>
                    <span>{code.used_at ? `Used ${formatDateTime(code.used_at)}` : "Unused"} · Created {formatDateTime(code.created_at)}</span>
                  </div>
                  <Button disabled={props.busy} onClick={() => props.onRevokeBackupCode(code)} size="sm" variant="secondary">
                    Revoke
                  </Button>
                </article>
              ))}
              {!visibleBackupCodes.length && <EmptyState description="Load or generate backup codes to review revocation state." title="No backup codes loaded" />}
            </div>
          </section>

          <EnrollDeviceModal busy={props.busy} onClose={() => setEnrollOpen(false)} onSubmit={submitDevice} open={enrollOpen} user={props.user} />
        </div>
      )}
    </Drawer>
  );
}

function EnrollDeviceModal(props: { busy: boolean; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; open: boolean; user: User }) {
  const [requireBiometric, setRequireBiometric] = useState(false);

  return (
    <Modal description="Create the server-side enrollment, then scan the QR code that appears." onClose={props.onClose} open={props.open} title={`Enroll device for ${props.user.username}`}>
      <form className="form-stack" onSubmit={props.onSubmit}>
        <input name="user_id" type="hidden" value={props.user.id} />
        <Field label="Device name">
          <Input name="name" placeholder="Alice's iPhone" required />
        </Field>
        <Field label="Push token">
          <Input autoComplete="off" name="push_token" placeholder="Optional FCM token" type="password" />
        </Field>
        <Field label="Kind">
          <Select defaultValue="phone" name="kind">
            <option value="phone">Phone</option>
            <option value="wear">Wearable</option>
          </Select>
        </Field>
        <Toggle checked={requireBiometric} label="Require biometric" onChange={setRequireBiometric} />
        <input name="require_biometric" type="hidden" value={requireBiometric ? "on" : ""} />
        <div className="form-actions">
          <Button onClick={props.onClose} variant="secondary">
            Cancel
          </Button>
          <Button disabled={props.busy} icon="plus" type="submit">
            Create enrollment
          </Button>
        </div>
      </form>
    </Modal>
  );
}
