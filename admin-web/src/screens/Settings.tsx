import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import type { Settings } from "../api";
import { RequiredFailModeSelect } from "../components/forms";
import { Button, Card, Chip, Field, Input, SectionHeader, Toggle } from "../components/ui";
import { getHostLabel } from "../utils";

export function SettingsScreen(props: {
  baseUrl: string;
  busy: boolean;
  onConnect: (baseUrl: string, token: string) => Promise<boolean>;
  onSaveSettings: (event: FormEvent<HTMLFormElement>) => Promise<boolean>;
  settings: Settings | null;
  token: string;
}) {
  const [baseUrl, setBaseUrl] = useState(props.baseUrl);
  const [token, setToken] = useState(props.token);
  const [requireBiometric, setRequireBiometric] = useState(Boolean(props.settings?.require_biometric));

  useEffect(() => setBaseUrl(props.baseUrl), [props.baseUrl]);
  useEffect(() => setToken(props.token), [props.token]);
  useEffect(() => setRequireBiometric(Boolean(props.settings?.require_biometric)), [props.settings?.require_biometric]);

  return (
    <div className="screen-stack">
      <SectionHeader
        description="Tune global authentication behavior and the console connection."
        eyebrow="Control plane"
        title="Settings"
      />

      <div className="split-grid">
        <Card>
          <SectionHeader title="Global policy defaults" description="These values apply where users, integrations, or policies inherit behavior." />
          {props.settings ? (
            <form className="form-stack" key={`${props.settings.global_fail_mode}-${props.settings.auth_ttl_seconds}-${props.settings.push_retry_count}-${props.settings.require_biometric}-${props.settings.trusted_session_window_seconds}`} onSubmit={(event) => void props.onSaveSettings(event)}>
              <div className="form-grid">
                <Field label="Fail mode">
                  <RequiredFailModeSelect defaultValue={props.settings.global_fail_mode} name="global_fail_mode" />
                </Field>
                <Field label="Auth TTL">
                  <Input defaultValue={props.settings.auth_ttl_seconds} max="600" min="5" name="auth_ttl_seconds" type="number" />
                </Field>
                <Field label="Push retries">
                  <Input defaultValue={props.settings.push_retry_count} max="10" min="0" name="push_retry_count" type="number" />
                </Field>
                <Field label="Trusted session window">
                  <Input defaultValue={props.settings.trusted_session_window_seconds} max="2592000" min="0" name="trusted_session_window_seconds" type="number" />
                </Field>
              </div>
              <Toggle checked={requireBiometric} label="Require biometric by default" onChange={setRequireBiometric} />
              <input name="require_biometric" type="hidden" value={requireBiometric ? "on" : ""} />
              <div className="form-actions">
                <Button disabled={props.busy} icon="check" type="submit">Save settings</Button>
              </div>
            </form>
          ) : (
            <p className="muted-copy">Settings are not loaded yet.</p>
          )}
        </Card>

        <Card>
          <SectionHeader title="Console connection" description="The API URL and origin-bound token last only for this browser tab. Leave the token blank when proxy auth is active." />
          <form
            className="form-stack"
            onSubmit={(event) => {
              event.preventDefault();
              void props.onConnect(baseUrl, token);
            }}
          >
            <div className="connection-summary">
              <Chip tone="success">Online</Chip>
              <span>{getHostLabel(props.baseUrl)}</span>
            </div>
            <Field label="Admin API URL">
              <Input onChange={(event) => setBaseUrl(event.target.value)} required value={baseUrl} />
            </Field>
            <Field hint="Blank uses proxy-supplied admin identity headers." label="Bearer token">
              <Input autoComplete="off" onChange={(event) => setToken(event.target.value)} type="password" value={token} />
            </Field>
            <div className="form-actions">
              <Button disabled={props.busy} icon="refresh" type="submit" variant="secondary">Reconnect</Button>
            </div>
          </form>
        </Card>
      </div>
    </div>
  );
}
