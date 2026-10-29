import type { FormEvent } from "react";
import { useMemo, useState } from "react";
import type { Policy } from "../api";
import { FailModeSelect, PolicyBiometricSelect } from "../components/forms";
import { Button, Card, Chip, EmptyState, Field, IconButton, Input, Modal, SearchField, SectionHeader, Select, Toggle } from "../components/ui";
import { shortId, statusTone } from "../utils";

export function PoliciesScreen(props: {
  busy: boolean;
  onCreatePolicy: (event: FormEvent<HTMLFormElement>) => Promise<boolean>;
  onDelete: (policy: Policy) => void;
  onEnabled: (policy: Policy, enabled: boolean) => Promise<boolean>;
  onFailMode: (policy: Policy, value: string) => Promise<boolean>;
  policies: Policy[];
}) {
  const [createOpen, setCreateOpen] = useState(false);
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return props.policies;
    return props.policies.filter((policy) => [policy.name, policy.description, policy.subject_type, policy.subject_id, policy.subject_key].some((value) => String(value ?? "").toLowerCase().includes(needle)));
  }, [props.policies, query]);

  async function submitCreate(event: FormEvent<HTMLFormElement>) {
    if (await props.onCreatePolicy(event)) setCreateOpen(false);
  }

  return (
    <div className="screen-stack">
      <SectionHeader
        actions={<Button icon="plus" onClick={() => setCreateOpen(true)}>New policy</Button>}
        description="Set global, user, or integration-specific authentication behavior."
        eyebrow="Access controls"
        title="Policies"
      />

      <Card>
        <div className="table-toolbar">
          <SearchField onChange={setQuery} placeholder="Search policies" value={query} />
          <Chip tone="info">{filtered.length} shown</Chip>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Policy</th>
                <th>Subject</th>
                <th>Fail mode</th>
                <th>TTL</th>
                <th>Retries</th>
                <th>Biometric</th>
                <th>Trusted window</th>
                <th>State</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((policy) => (
                <tr key={policy.id}>
                  <td>
                    <div className="entity-cell">
                      <strong>{policy.name}</strong>
                      <span>{policy.description || <span className="mono">{shortId(policy.id)}</span>}</span>
                    </div>
                  </td>
                  <td>
                    <div className="entity-cell">
                      <strong>{policy.subject_type}</strong>
                      <span className="mono">{policy.subject_id ?? policy.subject_key ?? "global"}</span>
                    </div>
                  </td>
                  <td><FailModeSelect disabled={props.busy} onChange={(value) => void props.onFailMode(policy, value)} value={policy.fail_mode ?? ""} /></td>
                  <td>{policy.auth_ttl_seconds ?? "inherit"}</td>
                  <td>{policy.push_retry_count ?? "inherit"}</td>
                  <td>{policy.require_biometric === null || policy.require_biometric === undefined ? "inherit" : String(policy.require_biometric)}</td>
                  <td>{policy.trusted_session_window_seconds ?? "inherit"}</td>
                  <td><Chip tone={statusTone(policy.enabled ? "enabled" : "disabled")}>{policy.enabled ? "Enabled" : "Disabled"}</Chip></td>
                  <td>
                    <div className="row-actions">
                      <Toggle checked={policy.enabled} disabled={props.busy} label={policy.enabled ? "Enabled" : "Disabled"} onChange={(checked) => void props.onEnabled(policy, checked)} />
                      <IconButton disabled={props.busy} icon="trash" label="Delete policy" onClick={() => props.onDelete(policy)} size="sm" variant="ghost" />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!filtered.length && <EmptyState description="Create policies to override global behavior for specific users or integrations." title="No policies found" />}
      </Card>

      <CreatePolicyModal busy={props.busy} onClose={() => setCreateOpen(false)} onSubmit={submitCreate} open={createOpen} />
    </div>
  );
}

function CreatePolicyModal(props: { busy: boolean; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void; open: boolean }) {
  return (
    <Modal description="Leave optional values blank to inherit from global settings." onClose={props.onClose} open={props.open} size="lg" title="New policy">
      <form className="form-stack" onSubmit={props.onSubmit}>
        <div className="form-grid">
          <Field label="Name">
            <Input name="name" required />
          </Field>
          <Field label="Description">
            <Input name="description" />
          </Field>
          <Field label="Subject type">
            <Select defaultValue="global" name="subject_type">
              <option value="global">Global</option>
              <option value="user">User</option>
              <option value="integration">Integration</option>
            </Select>
          </Field>
          <Field label="Subject ID">
            <Input name="subject_id" placeholder="User or integration ID" />
          </Field>
          <Field label="Fail mode">
            <FailModeSelect defaultValue="" name="fail_mode" />
          </Field>
          <Field label="Biometric">
            <PolicyBiometricSelect name="require_biometric" />
          </Field>
          <Field label="Auth TTL">
            <Input max="600" min="5" name="auth_ttl_seconds" placeholder="Seconds" type="number" />
          </Field>
          <Field label="Push retries">
            <Input max="10" min="0" name="push_retry_count" placeholder="Retries" type="number" />
          </Field>
          <Field label="Trusted window">
            <Input max="2592000" min="0" name="trusted_session_window_seconds" placeholder="Seconds" type="number" />
          </Field>
        </div>
        <div className="form-actions">
          <Button onClick={props.onClose} variant="secondary">Cancel</Button>
          <Button disabled={props.busy} icon="plus" type="submit">Create policy</Button>
        </div>
      </form>
    </Modal>
  );
}
