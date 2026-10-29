import type { FormEvent } from "react";
import type { AuditLog, AuthLog } from "../api";
import { Button, Card, Chip, EmptyState, Field, Input, SectionHeader, Select } from "../components/ui";
import { formatFullDateTime, shortId, statusTone } from "../utils";

export function LogsScreen(props: {
  auditLogs: AuditLog[];
  authLogs: AuthLog[];
  busy: boolean;
  onFilterAuditLogs: (event: FormEvent<HTMLFormElement>) => Promise<boolean>;
  onFilterAuthLogs: (event: FormEvent<HTMLFormElement>) => Promise<boolean>;
}) {
  return (
    <div className="screen-stack">
      <SectionHeader
        description="Investigate authentication outcomes and administrative activity with API-backed filters."
        eyebrow="Observability"
        title="Logs"
      />

      <div className="split-grid">
        <Card>
          <SectionHeader title="Auth log filter" description="Filter the loaded auth-log page by user, system, result, and time." />
          <form className="form-stack" onSubmit={(event) => void props.onFilterAuthLogs(event)}>
            <div className="form-grid">
              <Field label="User"><Input name="user" /></Field>
              <Field label="System"><Input name="system" /></Field>
              <Field label="Result">
                <Select defaultValue="" name="result">
                  <option value="">Any result</option>
                  <option value="pending">Pending</option>
                  <option value="approved">Approved</option>
                  <option value="denied">Denied</option>
                  <option value="timeout">Timeout</option>
                </Select>
              </Field>
              <Field label="From"><Input name="from" type="datetime-local" /></Field>
              <Field label="To"><Input name="to" type="datetime-local" /></Field>
              <Field label="Limit"><Input defaultValue="50" max="500" min="1" name="limit" type="number" /></Field>
              <Field label="Offset"><Input defaultValue="0" min="0" name="offset" type="number" /></Field>
            </div>
            <div className="form-actions">
              <Button disabled={props.busy} icon="search" type="submit">Apply auth filter</Button>
            </div>
          </form>
        </Card>

        <Card>
          <SectionHeader title="Audit log filter" description="Filter administrative events by action or resource." />
          <form className="form-stack" onSubmit={(event) => void props.onFilterAuditLogs(event)}>
            <div className="form-grid">
              <Field label="Action"><Input name="action" /></Field>
              <Field label="Resource type"><Input name="resource_type" /></Field>
              <Field label="Resource ID"><Input name="resource_id" /></Field>
              <Field label="Limit"><Input defaultValue="50" max="500" min="1" name="limit" type="number" /></Field>
              <Field label="Offset"><Input defaultValue="0" min="0" name="offset" type="number" /></Field>
            </div>
            <div className="form-actions">
              <Button disabled={props.busy} icon="search" type="submit">Apply audit filter</Button>
            </div>
          </form>
        </Card>
      </div>

      <Card>
        <SectionHeader title="Authentication logs" description={`${props.authLogs.length} loaded records`} />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>System</th>
                <th>Service</th>
                <th>Source</th>
                <th>Status</th>
                <th>Factor</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {props.authLogs.map((log) => (
                <tr key={log.id}>
                  <td>{log.username}</td>
                  <td>{log.system}</td>
                  <td>{log.pam_service}</td>
                  <td className="mono">{log.source_ip ?? ""}</td>
                  <td><Chip tone={statusTone(log.status)}>{log.status}</Chip></td>
                  <td>{log.factor}</td>
                  <td>{formatFullDateTime(log.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!props.authLogs.length && <EmptyState description="Adjust filters or wait for authentication attempts." title="No auth logs loaded" />}
      </Card>

      <Card>
        <SectionHeader title="Audit logs" description={`${props.auditLogs.length} loaded records`} />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Actor</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Resource ID</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {props.auditLogs.map((log) => (
                <tr key={log.id}>
                  <td>{log.actor}</td>
                  <td><Chip tone="neutral">{log.action}</Chip></td>
                  <td>{log.resource_type}</td>
                  <td className="mono">{log.resource_id ? shortId(log.resource_id, 12) : ""}</td>
                  <td>{formatFullDateTime(log.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!props.auditLogs.length && <EmptyState description="Administrative changes will be listed here once loaded." title="No audit logs loaded" />}
      </Card>
    </div>
  );
}
