import type { FormEvent } from "react";
import { useEffect, useMemo, useState } from "react";
import type { ApiKey, Role } from "../api";
import { Button, Card, Chip, EmptyState, Field, IconButton, Input, Modal, SearchField, SectionHeader, Select, Toggle } from "../components/ui";
import { formatDateTime, shortId, statusTone } from "../utils";

export function RolesKeysScreen(props: {
  apiKeys: ApiKey[];
  busy: boolean;
  onApiKeyEnabled: (key: ApiKey, enabled: boolean) => Promise<boolean>;
  onApiKeyName: (key: ApiKey, name: string) => Promise<boolean>;
  onApiKeyRole: (key: ApiKey, role: string) => Promise<boolean>;
  onCreateApiKey: (event: FormEvent<HTMLFormElement>) => Promise<boolean>;
  onCreateRole: (event: FormEvent<HTMLFormElement>) => Promise<boolean>;
  onDeleteRole: (role: Role) => void;
  onRoleEnabled: (role: Role, enabled: boolean) => Promise<boolean>;
  onRolePermission: (role: Role, permission: string, enabled: boolean) => Promise<boolean>;
  roles: Role[];
}) {
  const [roleOpen, setRoleOpen] = useState(false);
  const [keyOpen, setKeyOpen] = useState(false);
  const [editingKeyId, setEditingKeyId] = useState("");
  const [query, setQuery] = useState("");
  const editingKey = props.apiKeys.find((key) => key.id === editingKeyId) ?? null;
  const filteredRoles = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return props.roles;
    return props.roles.filter((role) => [role.name, role.description, role.id].some((value) => String(value ?? "").toLowerCase().includes(needle)));
  }, [props.roles, query]);
  const filteredKeys = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return props.apiKeys;
    return props.apiKeys.filter((key) => [key.name, key.role, key.id].some((value) => String(value ?? "").toLowerCase().includes(needle)));
  }, [props.apiKeys, query]);

  useEffect(() => {
    if (editingKeyId && !editingKey) setEditingKeyId("");
  }, [editingKey, editingKeyId]);

  async function submitRole(event: FormEvent<HTMLFormElement>) {
    if (await props.onCreateRole(event)) setRoleOpen(false);
  }

  async function submitKey(event: FormEvent<HTMLFormElement>) {
    if (await props.onCreateApiKey(event)) setKeyOpen(false);
  }

  return (
    <div className="screen-stack">
      <SectionHeader
        actions={
          <>
            <Button icon="plus" onClick={() => setRoleOpen(true)} variant="secondary">New role</Button>
            <Button icon="keys" onClick={() => setKeyOpen(true)}>New API key</Button>
          </>
        }
        description="Grant scoped administrative capabilities and rotate machine access."
        eyebrow="RBAC"
        title="Roles / API Keys"
      />

      <Card>
        <div className="table-toolbar">
          <SearchField onChange={setQuery} placeholder="Search roles and keys" value={query} />
          <Chip tone="info">{filteredRoles.length + filteredKeys.length} shown</Chip>
        </div>
      </Card>

      <div className="split-grid">
        <Card>
          <SectionHeader title="Roles" description="Built-in roles are protected from edits that would change their contract." />
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Role</th>
                  <th>Read</th>
                  <th>Write</th>
                  <th>Admin</th>
                  <th>State</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredRoles.map((role) => (
                  <tr key={role.id}>
                    <td>
                      <div className="entity-cell">
                        <strong>{role.name} {role.built_in && <Chip tone="neutral">Built-in</Chip>}</strong>
                        <span>{role.description || <span className="mono">{shortId(role.id)}</span>}</span>
                      </div>
                    </td>
                    {["read", "write", "admin"].map((permission) => (
                      <td key={permission}>
                        <input
                          checked={Boolean(role.permissions?.[permission])}
                          disabled={props.busy || role.built_in}
                          onChange={(event) => void props.onRolePermission(role, permission, event.target.checked)}
                          type="checkbox"
                        />
                      </td>
                    ))}
                    <td><Chip tone={statusTone(role.enabled ? "enabled" : "disabled")}>{role.enabled ? "Enabled" : "Disabled"}</Chip></td>
                    <td>
                      <div className="row-actions">
                        <Toggle checked={role.enabled} disabled={props.busy || role.built_in} label={role.enabled ? "Enabled" : "Disabled"} onChange={(checked) => void props.onRoleEnabled(role, checked)} />
                        <IconButton disabled={props.busy || role.built_in} icon="trash" label="Delete role" onClick={() => props.onDeleteRole(role)} size="sm" variant="ghost" />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!filteredRoles.length && <EmptyState description="Create a role to grant API keys a specific permission set." title="No roles found" />}
        </Card>

        <Card>
          <SectionHeader title="API keys" description="New tokens are shown once after creation." />
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Key</th>
                  <th>Role</th>
                  <th>State</th>
                  <th>Last used</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredKeys.map((key) => (
                  <ApiKeyRow
                    apiKey={key}
                    busy={props.busy}
                    key={key.id}
                    onEnabled={props.onApiKeyEnabled}
                    onManage={() => setEditingKeyId(key.id)}
                    onRole={props.onApiKeyRole}
                    roles={props.roles}
                  />
                ))}
              </tbody>
            </table>
          </div>
          {!filteredKeys.length && <EmptyState description="Create an API key for automation or service-to-service admin tasks." title="No API keys found" />}
        </Card>
      </div>

      <CreateRoleModal busy={props.busy} onClose={() => setRoleOpen(false)} onSubmit={submitRole} open={roleOpen} />
      <CreateApiKeyModal busy={props.busy} onClose={() => setKeyOpen(false)} onSubmit={submitKey} open={keyOpen} roles={props.roles} />
      <ManageApiKeyModal apiKey={editingKey} busy={props.busy} onClose={() => setEditingKeyId("")} onName={props.onApiKeyName} />
    </div>
  );
}

function ApiKeyRow(props: {
  apiKey: ApiKey;
  busy: boolean;
  onEnabled: (key: ApiKey, enabled: boolean) => Promise<boolean>;
  onManage: () => void;
  onRole: (key: ApiKey, role: string) => Promise<boolean>;
  roles: Role[];
}) {
  return (
    <tr>
      <td>
        <div className="entity-cell">
          <strong>{props.apiKey.name}</strong>
          <span className="mono">{shortId(props.apiKey.id)}</span>
        </div>
      </td>
      <td>
        <Select disabled={props.busy} onChange={(event) => void props.onRole(props.apiKey, event.target.value)} value={props.apiKey.role}>
          {props.roles.map((role) => <option key={role.id}>{role.name}</option>)}
        </Select>
      </td>
      <td><Chip tone={statusTone(props.apiKey.enabled ? "enabled" : "disabled")}>{props.apiKey.enabled ? "Enabled" : "Disabled"}</Chip></td>
      <td>{formatDateTime(props.apiKey.last_used_at)}</td>
      <td>
        <div className="row-actions">
          <Toggle checked={props.apiKey.enabled} disabled={props.busy} label={props.apiKey.enabled ? "Enabled" : "Disabled"} onChange={(checked) => void props.onEnabled(props.apiKey, checked)} />
          <Button disabled={props.busy} onClick={props.onManage} size="sm" variant="secondary">Manage</Button>
        </div>
      </td>
    </tr>
  );
}

function ManageApiKeyModal(props: { apiKey: ApiKey | null; busy: boolean; onClose: () => void; onName: (key: ApiKey, name: string) => Promise<boolean> }) {
  const [name, setName] = useState("");

  useEffect(() => setName(props.apiKey?.name ?? ""), [props.apiKey]);

  const changed = props.apiKey ? name !== props.apiKey.name : false;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (props.apiKey && await props.onName(props.apiKey, name.trim())) props.onClose();
  }

  return (
    <Modal description={props.apiKey ? props.apiKey.id : ""} onClose={props.onClose} open={Boolean(props.apiKey)} title={props.apiKey?.name ?? "Manage API key"}>
      <form className="form-stack" onSubmit={submit}>
        <Field label="Key name"><Input onChange={(event) => setName(event.target.value)} value={name} /></Field>
        <div className="form-actions">
          <Button onClick={props.onClose} variant="secondary">Cancel</Button>
          <Button disabled={props.busy || !changed || !name.trim()} type="submit">Save key</Button>
        </div>
      </form>
    </Modal>
  );
}

function CreateRoleModal(props: { busy: boolean; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; open: boolean }) {
  return (
    <Modal description="Set the permission switches this role should grant." onClose={props.onClose} open={props.open} title="New role">
      <form className="form-stack" onSubmit={props.onSubmit}>
        <Field label="Role name"><Input name="name" required /></Field>
        <Field label="Description"><Input name="description" /></Field>
        <div className="check-grid">
          <label><input defaultChecked name="read" type="checkbox" /> Read</label>
          <label><input name="write" type="checkbox" /> Write</label>
          <label><input name="admin" type="checkbox" /> Admin</label>
        </div>
        <div className="form-actions">
          <Button onClick={props.onClose} variant="secondary">Cancel</Button>
          <Button disabled={props.busy} icon="plus" type="submit">Create role</Button>
        </div>
      </form>
    </Modal>
  );
}

function CreateApiKeyModal(props: { busy: boolean; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; open: boolean; roles: Role[] }) {
  return (
    <Modal description="The API token is revealed once after creation." onClose={props.onClose} open={props.open} title="New API key">
      <form className="form-stack" onSubmit={props.onSubmit}>
        <Field label="Key name"><Input name="name" required /></Field>
        <Field label="Role">
          <Select name="role" required defaultValue={props.roles[0]?.name ?? ""}>
            {props.roles.map((role) => <option key={role.id}>{role.name}</option>)}
          </Select>
        </Field>
        <div className="form-actions">
          <Button onClick={props.onClose} variant="secondary">Cancel</Button>
          <Button disabled={props.busy || !props.roles.length} icon="keys" type="submit">Create key</Button>
        </div>
      </form>
    </Modal>
  );
}
