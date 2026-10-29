export function classNames(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(" ");
}

export function shortId(id: string, length = 8) {
  return id.slice(0, length);
}

export function formatDateTime(value?: string | null) {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

export function formatFullDateTime(value?: string | null) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

export function formatRelativeTime(value?: string | null) {
  if (!value) return "Unknown";
  const date = new Date(value);
  const time = date.getTime();
  if (Number.isNaN(time)) return value;

  const diffSeconds = Math.round((time - Date.now()) / 1000);
  const absSeconds = Math.abs(diffSeconds);
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["year", 60 * 60 * 24 * 365],
    ["month", 60 * 60 * 24 * 30],
    ["week", 60 * 60 * 24 * 7],
    ["day", 60 * 60 * 24],
    ["hour", 60 * 60],
    ["minute", 60],
  ];
  const [unit, seconds] = units.find(([, unitSeconds]) => absSeconds >= unitSeconds) ?? ["second", 1];

  return new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(Math.round(diffSeconds / seconds), unit);
}

export function statusTone(status?: string | null): "success" | "danger" | "warning" | "info" | "neutral" {
  const value = (status ?? "").toLowerCase();
  if (["approved", "success", "ok", "enabled", "active"].includes(value)) return "success";
  if (["denied", "failed", "revoked", "disabled", "locked", "error"].includes(value)) return "danger";
  if (["timeout", "expired", "warning"].includes(value)) return "warning";
  if (["pending", "open"].includes(value)) return "info";
  return "neutral";
}

export function isWithinLastHours(value: string | undefined, hours: number) {
  if (!value) return false;
  const time = new Date(value).getTime();
  if (Number.isNaN(time)) return false;
  return Date.now() - time <= hours * 60 * 60 * 1000;
}

export function getHostLabel(baseUrl: string) {
  try {
    return new URL(baseUrl).host;
  } catch {
    return baseUrl || "Not configured";
  }
}

export function formText(form: FormData, key: string): string | undefined {
  const value = String(form.get(key) || "").trim();
  return value || undefined;
}

export function formNumber(form: FormData, key: string, fallback: number): number {
  const raw = String(form.get(key) || "").trim();
  if (!raw) return fallback;
  const value = Number(raw);
  return Number.isFinite(value) ? value : fallback;
}

export function formOptionalNumber(form: FormData, key: string): number | undefined {
  const raw = String(form.get(key) || "").trim();
  if (!raw) return undefined;
  const value = Number(raw);
  return Number.isFinite(value) ? value : undefined;
}

export function formBool(form: FormData, key: string): boolean | undefined {
  const value = String(form.get(key) || "");
  if (value === "true") return true;
  if (value === "false") return false;
  return undefined;
}
