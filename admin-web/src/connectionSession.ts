import { validateAdminBaseUrl } from "./api";
import { readSessionValue, removePersistentValue, writeSessionValue } from "./storage";

const BASE_URL_KEY = "admin.baseUrl";
const TOKEN_KEY = "admin.token";
const TOKEN_ORIGIN_KEY = "admin.tokenOrigin";
const CONNECTION_KEY = "admin.connection";
const LEGACY_PERSISTENT_CONNECTION_KEYS = [BASE_URL_KEY, TOKEN_KEY, TOKEN_ORIGIN_KEY, CONNECTION_KEY];

export type SessionConnection = {
  baseUrl: string;
  token: string;
};

export function readSessionConnection(defaultBaseUrl: string): SessionConnection {
  purgeLegacyPersistentConnection();
  const stored = readSessionValue(CONNECTION_KEY, "");
  if (!stored) return { baseUrl: defaultBaseUrl, token: "" };

  try {
    const connection = JSON.parse(stored) as Partial<SessionConnection>;
    if (typeof connection.baseUrl !== "string" || typeof connection.token !== "string") throw new Error("Invalid stored connection");
    const baseUrl = validateAdminBaseUrl(connection.baseUrl);
    return { baseUrl, token: connection.token };
  } catch {
    return { baseUrl: defaultBaseUrl, token: "" };
  }
}

function purgeLegacyPersistentConnection() {
  for (const key of LEGACY_PERSISTENT_CONNECTION_KEYS) removePersistentValue(key);
}

export function writeSessionConnection(baseUrl: string, token: string): SessionConnection {
  const normalizedBaseUrl = validateAdminBaseUrl(baseUrl);
  const connection = { baseUrl: normalizedBaseUrl, token };
  // Keep the URL and token in one storage value so a partial write can never
  // bind an old token to a newly selected origin.
  writeSessionValue(CONNECTION_KEY, JSON.stringify(connection));
  return connection;
}
