import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminApi } from "./api";

describe("AdminApi", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("adds bearer auth and omits empty query values", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        requests.push(new Request(input, init));
        return jsonResponse({ data: [{ id: "log-1" }] });
      }),
    );

    const api = new AdminApi("https://pushgate.example/", "token-1");
    const logs = await api.authLogs({ user: "alice", system: "", result: "denied", limit: 25, offset: 5 });

    expect(logs).toEqual([{ id: "log-1" }]);
    const request = requests[0];
    const url = new URL(request.url);
    expect(url.pathname).toBe("/api/admin/auth-logs");
    expect(url.searchParams.get("user")).toBe("alice");
    expect(url.searchParams.get("result")).toBe("denied");
    expect(url.searchParams.get("limit")).toBe("25");
    expect(url.searchParams.get("offset")).toBe("5");
    expect(url.searchParams.has("system")).toBe(false);
    expect(request.headers.get("authorization")).toBe("Bearer token-1");
    expect(request.headers.get("accept")).toBe("application/json");
    expect(request.cache).toBe("no-store");
    expect(request.referrerPolicy).toBe("no-referrer");
  });

  it("sets json content type and returns undefined for 204 deletes", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        requests.push(new Request(input, init));
        if (requests.length === 1) return jsonResponse({ data: { id: "user-1" } });
        return new Response(null, { status: 204 });
      }),
    );

    const api = new AdminApi("https://pushgate.example", "token-1");
    await api.createUser({ username: "alice", fail_mode: "closed" });
    expect(requests[0].method).toBe("POST");
    expect(requests[0].headers.get("content-type")).toBe("application/json");
    expect(await requests[0].json()).toEqual({ username: "alice", fail_mode: "closed" });

    await expect(api.deleteUser("user-1")).resolves.toBeUndefined();
    expect(requests[1].method).toBe("DELETE");
    expect(new URL(requests[1].url).pathname).toBe("/api/admin/users/user-1");
  });

  it("round-trips integration security bindings in create and patch payloads", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        requests.push(new Request(input, init));
        return jsonResponse({ data: { id: "integration-1" } });
      }),
    );

    const api = new AdminApi("https://pushgate.example", "token-1");
    await api.createIntegration({
      name: "Bound PAM",
      system_type: "linux-pam",
      principal_username: "service-account",
      approver_username: "operator",
      system_name: "lab-host",
      fail_mode: "closed",
    });
    await api.patchIntegration("integration-1", {
      principal_username: null,
      approver_username: "new-operator",
      system_name: null,
    });

    expect(await requests[0].json()).toEqual({
      name: "Bound PAM",
      system_type: "linux-pam",
      principal_username: "service-account",
      approver_username: "operator",
      system_name: "lab-host",
      fail_mode: "closed",
    });
    expect(await requests[1].json()).toEqual({
      principal_username: null,
      approver_username: "new-operator",
      system_name: null,
    });
  });

  it("omits bearer auth when proxy auth is used", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        requests.push(new Request(input, init));
        return jsonResponse({ data: [] });
      }),
    );

    const api = new AdminApi("https://pushgate.example", "");
    await api.users();
    expect(requests[0].headers.has("authorization")).toBe(false);
  });

  it("surfaces structured API errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ detail: { code: "insufficient_scope" } }, 403, "Forbidden")),
    );

    const api = new AdminApi("https://pushgate.example", "token-1");
    await expect(api.users()).rejects.toThrow("insufficient_scope");
  });

  it("surfaces string API errors and a useful fallback for non-json errors", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ detail: "token expired" }, 401, "Unauthorized"))
      .mockResolvedValueOnce(new Response("upstream unavailable", { status: 502 }));
    vi.stubGlobal("fetch", fetchMock);

    const api = new AdminApi("https://pushgate.example", "token-1");
    await expect(api.users()).rejects.toThrow("token expired");
    await expect(api.users()).rejects.toThrow("Admin API request failed (502)");
  });

  it("rejects malformed success responses instead of accepting undefined data", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ ok: true })));

    const api = new AdminApi("https://pushgate.example", "token-1");
    await expect(api.users()).rejects.toThrow("Admin API returned an invalid response");
  });

  it("rejects unsafe admin API URLs before sending a token", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(new AdminApi("http://pushgate.example", "token-1").users()).rejects.toThrow("must use HTTPS");
    await expect(new AdminApi("https://" + "user:password@pushgate.example", "token-1").users()).rejects.toThrow("must not include credentials");
    await expect(new AdminApi("https://pushgate.example/other", "token-1").users()).rejects.toThrow("must not include a path");
    await expect(new AdminApi("https://pushgate.example/?next=other", "token-1").users()).rejects.toThrow("must not include a query or fragment");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("allows plain HTTP only for loopback development", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ data: [] })));

    await expect(new AdminApi("http://localhost:8000", "dev-admin").users()).resolves.toEqual([]);
  });

  it("encodes dynamic path segments", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        requests.push(new Request(input, init));
        return jsonResponse({ data: { id: "user-1" } });
      }),
    );

    await new AdminApi("https://pushgate.example", "token-1").patchUser("../settings/global?unsafe=yes", { locked: true });

    expect(new URL(requests[0].url).pathname).toBe("/api/admin/users/..%2Fsettings%2Fglobal%3Funsafe%3Dyes");
    expect(new URL(requests[0].url).search).toBe("");
  });
});

function jsonResponse(body: unknown, status = 200, statusText = "OK") {
  return new Response(JSON.stringify(body), {
    status,
    statusText,
    headers: { "Content-Type": "application/json" },
  });
}
