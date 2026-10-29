import { afterEach, describe, expect, it, vi } from "vitest";
import { readSessionConnection, writeSessionConnection } from "./connectionSession";

describe("session connection", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("keeps both the API base URL and token session-only", () => {
    const localStorage = storage();
    const sessionStorage = storage();
    vi.stubGlobal("window", { localStorage, sessionStorage });

    expect(writeSessionConnection("https://pushgate.example", "secret-token")).toEqual({
      baseUrl: "https://pushgate.example/",
      token: "secret-token",
    });

    expect(JSON.parse(sessionStorage.getItem("admin.connection") ?? "")).toEqual({
      baseUrl: "https://pushgate.example/",
      token: "secret-token",
    });
    expect(localStorage.getItem("admin.baseUrl")).toBeNull();
    expect(localStorage.getItem("admin.token")).toBeNull();
  });

  it("loads a token from its atomic connection record", () => {
    const sessionStorage = storage({
      "admin.connection": JSON.stringify({
        baseUrl: "https://pushgate.example/",
        token: "secret-token",
      }),
    });
    vi.stubGlobal("window", { localStorage: storage(), sessionStorage });

    expect(readSessionConnection("https://default.example")).toEqual({
      baseUrl: "https://pushgate.example/",
      token: "secret-token",
    });
  });

  it("falls back without a token when the connection record is invalid", () => {
    const sessionStorage = storage({
      "admin.connection": JSON.stringify({
        baseUrl: "http://attacker.example/",
        token: "secret-token",
      }),
    });
    vi.stubGlobal("window", { localStorage: storage(), sessionStorage });

    expect(readSessionConnection("https://default.example")).toEqual({
      baseUrl: "https://default.example",
      token: "",
    });
  });

  it("refuses legacy unbound session tokens", () => {
    const sessionStorage = storage({
      "admin.baseUrl": "https://pushgate.example/",
      "admin.token": "legacy-token",
    });
    vi.stubGlobal("window", { localStorage: storage(), sessionStorage });

    expect(readSessionConnection("https://default.example").token).toBe("");
  });

  it("purges legacy persistent connection values without importing them", () => {
    const localStorage = storage({
      "admin.baseUrl": "https://legacy.example/",
      "admin.token": "persistent-secret",
      "admin.tokenOrigin": "https://legacy.example",
      "admin.theme": "light",
    });
    const sessionStorage = storage({
      "admin.connection": JSON.stringify({
        baseUrl: "https://session.example/",
        token: "session-secret",
      }),
    });
    vi.stubGlobal("window", { localStorage, sessionStorage });

    expect(readSessionConnection("https://default.example")).toEqual({
      baseUrl: "https://session.example/",
      token: "session-secret",
    });
    expect(localStorage.getItem("admin.baseUrl")).toBeNull();
    expect(localStorage.getItem("admin.token")).toBeNull();
    expect(localStorage.getItem("admin.tokenOrigin")).toBeNull();
    expect(localStorage.getItem("admin.theme")).toBe("light");
  });

  it("cannot pair an old token with a new origin when storage rejects a write", () => {
    const original = JSON.stringify({ baseUrl: "https://original.example/", token: "original-token" });
    const sessionStorage = storage({ "admin.connection": original });
    sessionStorage.setItem = () => {
      throw new Error("quota exceeded");
    };
    vi.stubGlobal("window", { localStorage: storage(), sessionStorage });

    expect(writeSessionConnection("https://replacement.example", "replacement-token")).toEqual({
      baseUrl: "https://replacement.example/",
      token: "replacement-token",
    });
    expect(readSessionConnection("https://default.example")).toEqual({
      baseUrl: "https://original.example/",
      token: "original-token",
    });
  });

  it("continues reading the session when legacy cleanup is blocked", () => {
    const removeItem = vi.fn(() => {
      throw new Error("blocked");
    });
    const sessionStorage = storage({
      "admin.connection": JSON.stringify({
        baseUrl: "https://session.example/",
        token: "session-secret",
      }),
    });
    vi.stubGlobal("window", { localStorage: { removeItem }, sessionStorage });

    expect(readSessionConnection("https://default.example")).toEqual({
      baseUrl: "https://session.example/",
      token: "session-secret",
    });
    expect(removeItem).toHaveBeenCalledTimes(4);
  });
});

function storage(initial: Record<string, string> = {}): Pick<Storage, "getItem" | "setItem" | "removeItem"> {
  const values = new Map(Object.entries(initial));
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
}
