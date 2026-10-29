import type { ReactNode } from "react";
import { classNames, getHostLabel } from "../utils";
import { Icon, type IconName } from "./icons";
import { Button, IconButton } from "./ui";

export type ScreenKey = "dashboard" | "users" | "devices" | "integrations" | "policies" | "groups" | "roles" | "logs" | "settings";

export type NavItem = {
  key: ScreenKey;
  label: string;
  icon: IconName;
};

export const navItems: NavItem[] = [
  { key: "dashboard", label: "Dashboard", icon: "dashboard" },
  { key: "users", label: "Users", icon: "users" },
  { key: "devices", label: "Devices", icon: "devices" },
  { key: "integrations", label: "Integrations", icon: "integrations" },
  { key: "policies", label: "Policies", icon: "policies" },
  { key: "groups", label: "Groups", icon: "groups" },
  { key: "roles", label: "Roles / API Keys", icon: "keys" },
  { key: "logs", label: "Logs", icon: "logs" },
  { key: "settings", label: "Settings", icon: "settings" },
];

export function AppShell(props: {
  activeScreen: ScreenKey;
  baseUrl: string;
  busy: boolean;
  children: ReactNode;
  collapsed: boolean;
  identity: string;
  onNavigate: (screen: ScreenKey) => void;
  onRefresh: () => void;
  onToggleCollapsed: () => void;
  onToggleTheme: () => void;
  theme: "dark" | "light";
}) {
  const active = navItems.find((item) => item.key === props.activeScreen) ?? navItems[0];

  return (
    <div className={classNames("app-shell", props.collapsed && "app-shell--collapsed")}>
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <Icon name="shield-check" size={24} />
          </div>
          <div className="brand-copy">
            <strong>PushGate</strong>
            <span>Admin Console</span>
          </div>
          <IconButton className="sidebar-collapse" icon="chevron-left" label="Collapse navigation" onClick={props.onToggleCollapsed} variant="ghost" />
        </div>

        <nav aria-label="Admin sections" className="nav-list">
          {navItems.map((item) => (
            <button
              aria-current={props.activeScreen === item.key ? "page" : undefined}
              className={classNames("nav-item", props.activeScreen === item.key && "nav-item--active")}
              key={item.key}
              onClick={() => props.onNavigate(item.key)}
              title={props.collapsed ? item.label : undefined}
              type="button"
            >
              <Icon name={item.icon} size={19} />
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <div className="topbar__title">
            <IconButton className="mobile-menu" icon="menu" label="Toggle navigation" onClick={props.onToggleCollapsed} variant="ghost" />
            <div>
              <p className="eyebrow">PushGate Admin</p>
              <h1>{active.label}</h1>
            </div>
          </div>
          <div className="topbar__actions">
            <div className="health-pill" title={props.baseUrl}>
              <span className={classNames("health-dot", props.busy && "health-dot--busy")} />
              <span>{getHostLabel(props.baseUrl)}</span>
            </div>
            <div className="identity-pill">
              <Icon name={props.identity === "Proxy auth" ? "unlock" : "lock"} size={16} />
              <span>{props.identity}</span>
            </div>
            <IconButton icon={props.theme === "dark" ? "sun" : "moon"} label={`Switch to ${props.theme === "dark" ? "light" : "dark"} theme`} onClick={props.onToggleTheme} variant="secondary" />
            <Button disabled={props.busy} icon="refresh" onClick={props.onRefresh} variant="secondary">
              {props.busy ? "Working" : "Refresh"}
            </Button>
          </div>
        </header>
        <main className="content">{props.children}</main>
      </div>
    </div>
  );
}
