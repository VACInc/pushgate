import { afterEach, describe, expect, it, vi } from "vitest";
import { readPersistentValue, readSessionValue, writePersistentValue, writeSessionValue } from "./storage";

describe("browser storage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("keeps session values out of persistent storage", () => {
    const localStorage = storage();
    const sessionStorage = storage();
    vi.stubGlobal("window", { localStorage, sessionStorage });

    writeSessionValue("admin.token", "secret-token");

    expect(sessionStorage.getItem("admin.token")).toBe("secret-token");
    expect(localStorage.getItem("admin.token")).toBeNull();
    expect(readSessionValue("admin.token", "fallback")).toBe("secret-token");
  });

  it("persists non-secret preferences separately", () => {
    const localStorage = storage();
    const sessionStorage = storage();
    vi.stubGlobal("window", { localStorage, sessionStorage });

    writePersistentValue("admin.theme", "dark");

    expect(localStorage.getItem("admin.theme")).toBe("dark");
    expect(sessionStorage.getItem("admin.theme")).toBeNull();
    expect(readPersistentValue("admin.theme", "light")).toBe("dark");
  });

  it("falls back when browser storage is unavailable", () => {
    const unavailable = {
      getItem: vi.fn(() => {
        throw new Error("blocked");
      }),
      setItem: vi.fn(() => {
        throw new Error("blocked");
      }),
    };
    vi.stubGlobal("window", { localStorage: unavailable, sessionStorage: unavailable });

    expect(readSessionValue("admin.token", "fallback")).toBe("fallback");
    expect(() => writeSessionValue("admin.token", "secret-token")).not.toThrow();
  });
});

function storage(): Pick<Storage, "getItem" | "setItem"> {
  const values = new Map<string, string>();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
  };
}
