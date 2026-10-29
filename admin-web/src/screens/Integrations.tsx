import type { FormEvent } from "react";
import { useEffect, useMemo, useState } from "react";
import type { Integration } from "../api";
import { FailModeSelect } from "../components/forms";
import { Button, Card, Chip, Drawer, EmptyState, Field, Input, Modal, SearchField, SectionHeader, Toggle } from "../components/ui";
import { shortId, statusTone } from "../utils";

export function IntegrationsScreen(props: {
  busy: boolean;
  integrations: Integration[];
  onCreateIntegration: (event: FormEvent<HTMLFormElement>) => Promise<boolean>;
  onDetails: (integration: Integration, changes: IntegrationDetailChanges) => Promise<boolean>;
  onEnabled: (integration: Integration, enabled: boolean) => Promise<boolean>;
  onFailMode: (integration: Integration, value: string) => Promise<boolean>;
}) {
  const [createOpen, setCreateOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [selectedIntegrationId, setSelectedIntegrationId] = useState("");
  const selectedIntegration = props.integrations.find((integration) => integration.id === selectedIntegrationId) ?? null;
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return props.integrations;
    return props.integrations.filter((integration) => [integration.name, integration.client_id, integration.id, integration.system_type, integration.principal_username, integration.approver_username, integration.system_name].some((value) => String(value ?? "").toLowerCase().includes(needle)));
  }, [props.integrations, query]);

  useEffect(() => {
    if (selectedIntegrationId && !selectedIntegration) setSelectedIntegrationId("");
  }, [selectedIntegration, selectedIntegrationId]);

  async function submitCreate(event: FormEvent<HTMLFormElement>) {
    if (await props.onCreateIntegration(event)) setCreateOpen(false);
  }

  return (
    <div className="screen-stack">
      <SectionHeader
        actions={<Button icon="plus" onClick={() => setCreateOpen(true)}>New integration</Button>}
        description="Control systems that ask PushGate for push approvals."
        eyebrow="Connected systems"
        title="Integrations"
      />

      <Card>
        <div className="table-toolbar">
          <SearchField onChange={setQuery} placeholder="Search integrations" value={query} />
          <Chip tone="info">{filtered.length} shown</Chip>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Integration</th>
                <th>Client ID</th>
                <th>Type</th>
                <th>Fail mode</th>
                <th>State</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((integration) => (
                <IntegrationRow
                  busy={props.busy}
                  integration={integration}
                  key={integration.id}
                  onEnabled={props.onEnabled}
                  onFailMode={props.onFailMode}
                  onManage={() => setSelectedIntegrationId(integration.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
        {!filtered.length && <EmptyState description="Create an integration to connect PushGate to PAM or another relying system." title="No integrations found" />}
      </Card>

      <CreateIntegrationModal busy={props.busy} onClose={() => setCreateOpen(false)} onSubmit={submitCreate} open={createOpen} />
      <IntegrationDetailDrawer
        busy={props.busy}
        integration={selectedIntegration}
        onClose={() => setSelectedIntegrationId("")}
        onDetails={props.onDetails}
        onEnabled={props.onEnabled}
        onFailMode={props.onFailMode}
      />
    </div>
  );
}

function IntegrationRow(props: {
  busy: boolean;
  integration: Integration;
  onEnabled: (integration: Integration, enabled: boolean) => Promise<boolean>;
  onFailMode: (integration: Integration, value: string) => Promise<boolean>;
  onManage: () => void;
}) {
  return (
    <tr>
      <td>
        <div className="entity-cell">
          <strong>{props.integration.name}</strong>
          <span className="mono">{shortId(props.integration.id)}</span>
        </div>
      </td>
      <td className="mono">{props.integration.client_id}</td>
      <td><Chip tone="neutral">{props.integration.system_type}</Chip></td>
      <td><FailModeSelect disabled={props.busy} onChange={(value) => void props.onFailMode(props.integration, value)} value={props.integration.fail_mode ?? ""} /></td>
      <td><Chip tone={statusTone(props.integration.enabled ? "enabled" : "disabled")}>{props.integration.enabled ? "Enabled" : "Disabled"}</Chip></td>
      <td>
        <div className="row-actions">
          <Toggle checked={props.integration.enabled} disabled={props.busy} label={props.integration.enabled ? "Enabled" : "Disabled"} onChange={(checked) => void props.onEnabled(props.integration, checked)} />
          <Button disabled={props.busy} onClick={props.onManage} size="sm" variant="secondary">
            Manage
          </Button>
        </div>
      </td>
    </tr>
  );
}

export type IntegrationDetailChanges = Pick<Integration, "name" | "principal_username" | "approver_username" | "system_name">;

export function buildIntegrationDetailChanges(name: string, principalUsername: string, approverUsername: string, systemName: string): IntegrationDetailChanges {
  return {
    name: name.trim(),
    principal_username: principalUsername.trim() || null,
    approver_username: approverUsername.trim() || null,
    system_name: systemName.trim() || null,
  };
}

export function IntegrationDetailDrawer(props: {
  busy: boolean;
  integration: Integration | null;
  onClose: () => void;
  onDetails: (integration: Integration, changes: IntegrationDetailChanges) => Promise<boolean>;
  onEnabled: (integration: Integration, enabled: boolean) => Promise<boolean>;
  onFailMode: (integration: Integration, value: string) => Promise<boolean>;
}) {
  const [name, setName] = useState(() => props.integration?.name ?? "");
  const [principalUsername, setPrincipalUsername] = useState(() => props.integration?.principal_username ?? "");
  const [approverUsername, setApproverUsername] = useState(() => props.integration?.approver_username ?? "");
  const [systemName, setSystemName] = useState(() => props.integration?.system_name ?? "");

  useEffect(() => {
    setName(props.integration?.name ?? "");
    setPrincipalUsername(props.integration?.principal_username ?? "");
    setApproverUsername(props.integration?.approver_username ?? "");
    setSystemName(props.integration?.system_name ?? "");
  }, [props.integration]);

  const changes = buildIntegrationDetailChanges(name, principalUsername, approverUsername, systemName);
  const changed = props.integration
    ? changes.name !== props.integration.name ||
      changes.principal_username !== (props.integration.principal_username ?? null) ||
      changes.approver_username !== (props.integration.approver_username ?? null) ||
      changes.system_name !== (props.integration.system_name ?? null)
    : false;

  return (
    <Drawer description={props.integration ? props.integration.id : ""} onClose={props.onClose} open={Boolean(props.integration)} title={props.integration?.name ?? "Integration"}>
      {props.integration && (
        <div className="detail-stack">
          <section className="profile-header">
            <div>
              <strong>{props.integration.name}</strong>
              <span className="mono">{props.integration.client_id}</span>
            </div>
            <Chip tone={statusTone(props.integration.enabled ? "enabled" : "disabled")}>{props.integration.enabled ? "Enabled" : "Disabled"}</Chip>
          </section>

          <section className="detail-panel">
            <h3>Integration details</h3>
            <div className="form-grid">
              <Field label="Name">
                <Input onChange={(event) => setName(event.target.value)} value={name} />
              </Field>
              <Field hint="Only requests for this protected identity are accepted." label="Principal username binding">
                <Input autoComplete="off" maxLength={128} onChange={(event) => setPrincipalUsername(event.target.value)} value={principalUsername} />
              </Field>
              <Field hint="Only this identity may approve. A separate approver also requires a principal binding." label="Approver username binding">
                <Input autoComplete="off" maxLength={128} onChange={(event) => setApproverUsername(event.target.value)} value={approverUsername} />
              </Field>
              <Field hint="Only requests naming this system are accepted." label="System name binding">
                <Input autoComplete="off" maxLength={128} onChange={(event) => setSystemName(event.target.value)} value={systemName} />
              </Field>
              <Field label="Fail mode">
                <FailModeSelect disabled={props.busy} onChange={(value) => void props.onFailMode(props.integration!, value)} value={props.integration.fail_mode ?? ""} />
              </Field>
            </div>
            <div className="button-row">
              <Button disabled={props.busy || !changed || !changes.name} onClick={() => void props.onDetails(props.integration!, changes)} variant="secondary">
                Save details
              </Button>
              <Button disabled={props.busy} onClick={() => void props.onEnabled(props.integration!, !props.integration!.enabled)} variant="secondary">
                {props.integration.enabled ? "Disable integration" : "Enable integration"}
              </Button>
            </div>
          </section>
        </div>
      )}
    </Drawer>
  );
}

export function CreateIntegrationModal(props: { busy: boolean; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; open: boolean }) {
  return (
    <Modal description="The returned secret is shown once after creation." onClose={props.onClose} open={props.open} title="New integration">
      <form className="form-stack" onSubmit={props.onSubmit}>
        <Field label="Name">
          <Input name="name" required />
        </Field>
        <Field label="System type">
          <Input defaultValue="linux-pam" list="integration-types" maxLength={64} name="system_type" />
          <datalist id="integration-types">
            <option value="linux-pam" />
            <option value="proxy" />
          </datalist>
        </Field>
        <Field hint="Optional. Restricts requests to one protected identity." label="Principal username binding">
          <Input autoComplete="off" maxLength={128} name="principal_username" />
        </Field>
        <Field hint="Optional. Restricts approvals to one identity. A separate approver also requires a principal binding." label="Approver username binding">
          <Input autoComplete="off" maxLength={128} name="approver_username" />
        </Field>
        <Field hint="Optional. Restricts requests to one system name." label="System name binding">
          <Input autoComplete="off" maxLength={128} name="system_name" />
        </Field>
        <Field label="Fail mode override">
          <FailModeSelect defaultValue="" name="fail_mode" />
        </Field>
        <div className="form-actions">
          <Button onClick={props.onClose} variant="secondary">Cancel</Button>
          <Button disabled={props.busy} icon="plus" type="submit">Create integration</Button>
        </div>
      </form>
    </Modal>
  );
}
