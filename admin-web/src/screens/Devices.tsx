import type { FormEvent } from "react";
import { useEffect, useMemo, useState } from "react";
import type { Device, User } from "../api";
import { Button, Card, Chip, Drawer, EmptyState, Field, IconButton, Input, Modal, SearchField, SectionHeader, Select, Toggle } from "../components/ui";
import { shortId } from "../utils";

export function DevicesScreen(props: {
  busy: boolean;
  devices: Device[];
  onBiometric: (device: Device, requireBiometric: boolean) => Promise<boolean>;
  onCreateDevice: (event: FormEvent<HTMLFormElement>) => Promise<boolean>;
  onRestore: (device: Device) => Promise<boolean>;
  onRevoke: (device: Device) => void;
  onRotate: (device: Device) => void;
  onSave: (device: Device, changes: Partial<Pick<Device, "name" | "push_token">>) => Promise<boolean>;
  users: User[];
}) {
  const [createOpen, setCreateOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [selectedDeviceId, setSelectedDeviceId] = useState("");
  const selectedDevice = props.devices.find((device) => device.id === selectedDeviceId) ?? null;
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return props.devices;
    return props.devices.filter((device) => [device.name, device.id, device.user_id, device.kind].some((value) => String(value ?? "").toLowerCase().includes(needle)));
  }, [props.devices, query]);

  useEffect(() => {
    if (selectedDeviceId && !selectedDevice) setSelectedDeviceId("");
  }, [selectedDevice, selectedDeviceId]);

  async function submitCreate(event: FormEvent<HTMLFormElement>) {
    if (await props.onCreateDevice(event)) setCreateOpen(false);
  }

  return (
    <div className="screen-stack">
      <SectionHeader
        actions={
          <Button icon="plus" onClick={() => setCreateOpen(true)}>
            Enroll device
          </Button>
        }
        description="Review mobile and wearable factors, revoke compromised devices, and rotate enrollment material."
        eyebrow="Factors"
        title="Devices"
      />

      <Card>
        <div className="table-toolbar">
          <SearchField onChange={setQuery} placeholder="Search devices" value={query} />
          <Chip tone="info">{filtered.length} shown</Chip>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>User</th>
                <th>Kind</th>
                <th>Push token</th>
                <th>Biometric</th>
                <th>State</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((device) => (
                <DeviceRow
                  busy={props.busy}
                  device={device}
                  key={device.id}
                  onBiometric={props.onBiometric}
                  onRestore={props.onRestore}
                  onRevoke={props.onRevoke}
                  onRotate={props.onRotate}
                  onManage={() => setSelectedDeviceId(device.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
        {!filtered.length && <EmptyState description="Enroll a device from here or from an individual user drawer." title="No devices found" />}
      </Card>

      <CreateDeviceModal busy={props.busy} onClose={() => setCreateOpen(false)} onSubmit={submitCreate} open={createOpen} users={props.users} />
      <DeviceDetailDrawer
        busy={props.busy}
        device={selectedDevice}
        onClose={() => setSelectedDeviceId("")}
        onRestore={props.onRestore}
        onRevoke={props.onRevoke}
        onRotate={props.onRotate}
        onSave={props.onSave}
      />
    </div>
  );
}

export function DeviceRow(props: {
  busy: boolean;
  device: Device;
  onBiometric: (device: Device, requireBiometric: boolean) => Promise<boolean>;
  onManage: () => void;
  onRestore: (device: Device) => Promise<boolean>;
  onRevoke: (device: Device) => void;
  onRotate: (device: Device) => void;
}) {
  return (
    <tr>
      <td>
        <div className="entity-cell">
          <strong>{props.device.name}</strong>
          <span className="mono">{shortId(props.device.id)}</span>
        </div>
      </td>
      <td className="mono">{shortId(props.device.user_id)}</td>
      <td><Chip tone="neutral">{props.device.kind}</Chip></td>
      <td>
        <span>{props.device.push_token_configured ? "Configured" : "Not configured"}</span>
      </td>
      <td>
        <Toggle checked={props.device.require_biometric} disabled={props.busy || props.device.revoked} label={props.device.require_biometric ? "Required" : "Optional"} onChange={(checked) => void props.onBiometric(props.device, checked)} />
      </td>
      <td><Chip tone={props.device.revoked ? "danger" : "success"}>{props.device.revoked ? "Revoked" : "Active"}</Chip></td>
      <td>
        <div className="row-actions">
          <Button disabled={props.busy || props.device.revoked} onClick={() => props.onRotate(props.device)} size="sm" variant="secondary">
            Rotate
          </Button>
          <IconButton
            disabled={props.busy}
            icon={props.device.revoked ? "check" : "trash"}
            label={props.device.revoked ? "Restore device" : "Revoke device"}
            onClick={() => (props.device.revoked ? void props.onRestore(props.device) : props.onRevoke(props.device))}
            size="sm"
            variant="ghost"
          />
          <Button disabled={props.busy} onClick={props.onManage} size="sm" variant="secondary">
            Manage
          </Button>
        </div>
      </td>
    </tr>
  );
}

type DeviceDetailChanges = Partial<Pick<Device, "name" | "push_token">>;

export function buildDeviceDetailChanges(name: string, replacementPushToken: string, clearPushToken: boolean): DeviceDetailChanges {
  return {
    name: name.trim(),
    ...(clearPushToken
      ? { push_token: null }
      : replacementPushToken.trim()
        ? { push_token: replacementPushToken.trim() }
        : {}),
  };
}

export function DeviceDetailDrawer(props: {
  busy: boolean;
  device: Device | null;
  onClose: () => void;
  onRestore: (device: Device) => Promise<boolean>;
  onRevoke: (device: Device) => void;
  onRotate: (device: Device) => void;
  onSave: (device: Device, changes: Partial<Pick<Device, "name" | "push_token">>) => Promise<boolean>;
}) {
  const [name, setName] = useState("");
  const [pushToken, setPushToken] = useState("");
  const [clearPushToken, setClearPushToken] = useState(false);

  useEffect(() => {
    setName(props.device?.name ?? "");
    setPushToken("");
    setClearPushToken(false);
  }, [props.device]);

  const changed = props.device ? name !== props.device.name || Boolean(pushToken.trim()) || clearPushToken : false;

  return (
    <Drawer description={props.device ? props.device.id : ""} onClose={props.onClose} open={Boolean(props.device)} title={props.device?.name ?? "Device"}>
      {props.device && (
        <div className="detail-stack">
          <section className="profile-header">
            <div>
              <strong>{props.device.name}</strong>
              <span className="mono">{props.device.user_id}</span>
            </div>
            <Chip tone={props.device.revoked ? "danger" : "success"}>{props.device.revoked ? "Revoked" : "Active"}</Chip>
          </section>

          <section className="detail-panel">
            <h3>Device details</h3>
            <div className="form-grid">
              <Field label="Device name">
                <Input onChange={(event) => setName(event.target.value)} value={name} />
              </Field>
              <Field hint="Leave blank to keep the current token. Enter a value only to replace it." label="Replacement push token">
                <Input
                  autoComplete="off"
                  disabled={clearPushToken}
                  onChange={(event) => {
                    setPushToken(event.target.value);
                    if (event.target.value) setClearPushToken(false);
                  }}
                  type="password"
                  value={pushToken}
                />
              </Field>
              <Toggle
                checked={clearPushToken}
                disabled={!props.device.push_token_configured}
                label="Clear current push token on save"
                onChange={(checked) => {
                  setClearPushToken(checked);
                  if (checked) setPushToken("");
                }}
              />
            </div>
            <div className="button-row">
              <Button
                disabled={props.busy || !changed || !name.trim()}
                onClick={() => void props.onSave(props.device!, buildDeviceDetailChanges(name, pushToken, clearPushToken))}
                variant="secondary"
              >
                Save details
              </Button>
              <Button disabled={props.busy || props.device.revoked} onClick={() => props.onRotate(props.device!)} variant="secondary">
                Rotate enrollment
              </Button>
              <Button
                disabled={props.busy}
                icon={props.device.revoked ? "check" : "trash"}
                onClick={() => (props.device!.revoked ? void props.onRestore(props.device!) : props.onRevoke(props.device!))}
                variant={props.device.revoked ? "secondary" : "danger"}
              >
                {props.device.revoked ? "Restore device" : "Revoke device"}
              </Button>
            </div>
          </section>
        </div>
      )}
    </Drawer>
  );
}

function CreateDeviceModal(props: { busy: boolean; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; open: boolean; users: User[] }) {
  const [requireBiometric, setRequireBiometric] = useState(false);

  return (
    <Modal description="Create an enrollment payload for a phone or wearable." onClose={props.onClose} open={props.open} title="Enroll device">
      <form className="form-stack" onSubmit={props.onSubmit}>
        <Field label="User">
          <Select defaultValue="" name="user_id" required>
            <option disabled value="">Select user</option>
            {props.users.map((user) => (
              <option key={user.id} value={user.id}>{user.username}</option>
            ))}
          </Select>
        </Field>
        <Field label="Device name">
          <Input name="name" required />
        </Field>
        <Field label="Push token">
          <Input autoComplete="off" name="push_token" type="password" />
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
