import type { AuthLog, AuditLog, Device, Settings, User } from "../api";
import type { ScreenKey } from "../components/AppShell";
import { Icon, type IconName } from "../components/icons";
import { Button, Card, Chip, EmptyState, SectionHeader, StatTile } from "../components/ui";
import { formatDateTime, formatRelativeTime, isWithinLastHours, shortId, statusTone } from "../utils";

export function DashboardScreen(props: {
  auditLogs: AuditLog[];
  authLogs: AuthLog[];
  devices: Device[];
  onNavigate: (screen: ScreenKey) => void;
  settings: Settings | null;
  users: User[];
}) {
  const activeDevices = props.devices.filter((device) => !device.revoked).length;
  const pending = props.authLogs.filter((log) => log.status === "pending").length;
  const denialsLastDay = props.authLogs.filter((log) => log.status === "denied" && isWithinLastHours(log.created_at, 24)).length;
  const recentAuthLogs = props.authLogs.slice(0, 8);

  return (
    <div className="screen-stack">
      <SectionHeader
        actions={
          <>
            <Button icon="users" onClick={() => props.onNavigate("users")} variant="secondary">
              Manage users
            </Button>
            <Button icon="settings" onClick={() => props.onNavigate("settings")}>
              Global settings
            </Button>
          </>
        }
        description="A live overview of enrollment, authorization outcomes, and control-plane activity."
        eyebrow="Overview"
        title="Security posture"
      />

      <div className="stat-grid">
        <StatTile accent="neutral" detail={props.settings ? `${props.settings.global_fail_mode} fail mode` : "Settings pending"} icon="users" label="Total users" value={props.users.length} />
        <StatTile accent="neutral" detail={`${props.devices.length - activeDevices} revoked`} icon="devices" label="Enrolled devices" value={activeDevices} />
        <StatTile accent={pending ? "warning" : "neutral"} detail="From loaded auth logs" icon="activity" label="Pending requests" value={pending} />
        <StatTile accent={denialsLastDay ? "danger" : "neutral"} detail="Last 24 hours in loaded data" icon={denialsLastDay ? "alert" : "shield-check"} label="Denials" value={denialsLastDay} />
      </div>

      <div className="dashboard-grid">
        <Card>
          <SectionHeader title="Recent authentication" description="Latest loaded auth decisions by user, service, and factor." />
          {recentAuthLogs.length ? (
            <div className="feed-list">
              {recentAuthLogs.map((log) => (
                <article className="feed-item" key={log.id}>
                  <div className="feed-icon">
                    <Icon name={log.status === "approved" ? "check" : log.status === "denied" ? "alert" : "activity"} size={18} />
                  </div>
                  <div className="feed-main">
                    <div>
                      <strong>{log.username}</strong>
                      <span>{log.system || log.pam_service}</span>
                    </div>
                    <p>{log.factor} · {formatDateTime(log.created_at)}</p>
                  </div>
                  <Chip tone={statusTone(log.status)}>{log.status}</Chip>
                </article>
              ))}
            </div>
          ) : (
            <EmptyState description="Auth decisions will appear here after the console loads log data." title="No auth logs loaded" />
          )}
        </Card>

        <Card>
          <SectionHeader title="Denials last 24h" description="A compact hourly view from the loaded auth-log window." />
          <DenialBars logs={props.authLogs} />
        </Card>
      </div>

      <Card>
        <SectionHeader title="Recent audit trail" description="Administrative activity from the audit log." />
        {props.auditLogs.length ? (
          <div className="audit-list">
            {props.auditLogs.slice(0, 6).map((log) => (
              <article className="audit-row" key={log.id}>
                <div className="audit-row__icon">
                  <Icon name={auditIcon(log)} size={16} />
                </div>
                <div className="audit-row__main">
                  <strong className="mono">{log.action}</strong>
                  <span>
                    <span className="mono">{log.actor || "system"}</span>
                    {" -> "}
                    {log.resource_type}
                    {log.resource_id && <> <span className="mono">{shortId(log.resource_id, 12)}</span></>}
                  </span>
                </div>
                <time dateTime={log.created_at} title={formatDateTime(log.created_at)}>{formatRelativeTime(log.created_at)}</time>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState description="Audit events will show up once administrative actions are recorded." title="No audit events loaded" />
        )}
      </Card>
    </div>
  );
}

function auditIcon(log: AuditLog): IconName {
  const value = `${log.action} ${log.resource_type}`.toLowerCase();
  if (value.includes("delete") || value.includes("revoke") || value.includes("disable")) return "trash";
  if (value.includes("lock")) return "lock";
  if (value.includes("create") || value.includes("add") || value.includes("enroll")) return "plus";
  if (value.includes("api_key") || value.includes("key")) return "keys";
  if (value.includes("device")) return "devices";
  if (value.includes("user")) return "users";
  if (value.includes("group")) return "groups";
  if (value.includes("integration")) return "integrations";
  if (value.includes("policy")) return "policies";
  if (value.includes("setting")) return "settings";
  return "activity";
}

export function DenialBars(props: { logs: AuthLog[] }) {
  const buckets = Array.from({ length: 24 }, (_, index) => {
    const bucketStart = Date.now() - (24 - index) * 60 * 60 * 1000;
    const bucketEnd = bucketStart + 60 * 60 * 1000;
    return props.logs.filter((log) => {
      if (log.status !== "denied") return false;
      const time = new Date(log.created_at).getTime();
      return !Number.isNaN(time) && time >= bucketStart && time < bucketEnd;
    }).length;
  });
  const max = Math.max(...buckets, 1);

  if (!buckets.some(Boolean)) {
    return <EmptyState description="No denials appear in the loaded 24-hour window." title="Quiet window" />;
  }

  return (
    <div className="mini-bars" aria-label="Denials by hour" role="group">
      <p className="visually-hidden">
        Hourly denial counts, oldest to newest. {buckets.map((value, index) => `Hour ${index + 1}: ${value} denial${value === 1 ? "" : "s"}.`).join(" ")}
      </p>
      <svg aria-hidden="true" className="mini-bars__chart" preserveAspectRatio="none" viewBox={`0 0 ${buckets.length * 10} 100`}>
        {buckets.map((value, index) => {
          const height = Math.max(8, (value / max) * 100);
          return (
            <rect height={height} key={index} rx="4" width="8" x={index * 10 + 1} y={100 - height}>
              <title>{`${value} denials`}</title>
            </rect>
          );
        })}
      </svg>
    </div>
  );
}
