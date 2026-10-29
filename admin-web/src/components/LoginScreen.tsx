import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import { Icon } from "./icons";
import { Button, Card, Field, IconButton, Input } from "./ui";

export function LoginScreen(props: {
  baseUrl: string;
  busy: boolean;
  error: string;
  onConnect: (baseUrl: string, token: string) => Promise<boolean>;
  onToggleTheme: () => void;
  theme: "dark" | "light";
  token: string;
}) {
  const [baseUrl, setBaseUrl] = useState(props.baseUrl);
  const [token, setToken] = useState(props.token);
  const [submitted, setSubmitted] = useState(false);
  const [tokenTouched, setTokenTouched] = useState(false);

  useEffect(() => setBaseUrl(props.baseUrl), [props.baseUrl]);
  useEffect(() => setToken(props.token), [props.token]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitted(true);
    await props.onConnect(baseUrl, token);
  }

  const showError = Boolean(props.error && (submitted || tokenTouched));

  return (
    <main className="auth-page">
      <IconButton className="auth-theme" icon={props.theme === "dark" ? "sun" : "moon"} label="Toggle theme" onClick={props.onToggleTheme} variant="secondary" />
      <Card className="auth-card">
        <div className="auth-logo">
          <div className="brand-mark brand-mark--large">
            <Icon name="shield-check" size={30} />
          </div>
          <div>
            <strong>PushGate</strong>
            <span>Admin Console</span>
          </div>
        </div>
        <div className="auth-copy">
          <p className="eyebrow">Secure control plane</p>
          <h1>Open the admin console</h1>
          <p>Use the bootstrap token, or leave the token empty when a trusted proxy is supplying admin headers.</p>
        </div>
        <form className="form-stack" onSubmit={submit}>
          <Field label="Admin API URL">
            <Input autoComplete="url" onChange={(event) => setBaseUrl(event.target.value)} required value={baseUrl} />
          </Field>
          <Field hint="Blank token keeps proxy-header authentication available." label="Bootstrap bearer token">
            <Input autoComplete="off" onBlur={() => setTokenTouched(true)} onChange={(event) => setToken(event.target.value)} type="password" value={token} />
          </Field>
          {showError && (
            <div className="inline-alert" role="alert">
              <Icon name="alert" size={18} />
              <span>{props.error}</span>
            </div>
          )}
          <Button disabled={props.busy} icon="lock" type="submit">
            {props.busy ? "Connecting" : "Open console"}
          </Button>
        </form>
      </Card>
    </main>
  );
}
