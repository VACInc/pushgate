export function readPersistentValue(key: string, fallback: string) {
  return readStorage("localStorage", key, fallback);
}

export function writePersistentValue(key: string, value: string) {
  writeStorage("localStorage", key, value);
}

export function removePersistentValue(key: string) {
  removeStorageValue("localStorage", key);
}

export function readSessionValue(key: string, fallback: string) {
  return readStorage("sessionStorage", key, fallback);
}

export function writeSessionValue(key: string, value: string) {
  writeStorage("sessionStorage", key, value);
}

type StorageKind = "localStorage" | "sessionStorage";

function readStorage(kind: StorageKind, key: string, fallback: string) {
  if (typeof window === "undefined") return fallback;
  try {
    return window[kind].getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}

function writeStorage(kind: StorageKind, key: string, value: string) {
  if (typeof window === "undefined") return;
  try {
    window[kind].setItem(key, value);
  } catch {
    // Storage can be blocked by browser policy; the console still works in memory.
  }
}

function removeStorageValue(kind: StorageKind, key: string) {
  if (typeof window === "undefined") return;
  try {
    window[kind].removeItem(key);
  } catch {
    // Best-effort cleanup when browser storage is unavailable or blocked.
  }
}
