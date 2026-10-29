import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { Device } from "../api";
import { buildDeviceDetailChanges, DeviceDetailDrawer, DeviceRow } from "./Devices";

const configuredDevice: Device = {
  id: "device-1",
  user_id: "user-1",
  name: "Phone",
  kind: "phone",
  push_token_configured: true,
  revoked: false,
  require_biometric: false,
};

function renderPushStatus(pushTokenConfigured: boolean): string {
  const device: Device = {
    id: "device-1",
    user_id: "user-1",
    name: "Phone",
    kind: "phone",
    push_token_configured: pushTokenConfigured,
    revoked: false,
    require_biometric: false,
  };

  return renderToStaticMarkup(
    <table>
      <tbody>
        <DeviceRow
          busy={false}
          device={device}
          onBiometric={vi.fn()}
          onManage={vi.fn()}
          onRestore={vi.fn()}
          onRevoke={vi.fn()}
          onRotate={vi.fn()}
        />
      </tbody>
    </table>,
  );
}

describe("DeviceRow", () => {
  it("uses the redaction-safe configuration flag for push-token status", () => {
    expect(renderPushStatus(true)).toContain("Configured");
    expect(renderPushStatus(false)).toContain("Not configured");
  });
});

describe("DeviceDetailDrawer", () => {
  it("offers an explicit clear-on-save control for configured tokens", () => {
    const markup = renderToStaticMarkup(
      <DeviceDetailDrawer
        busy={false}
        device={configuredDevice}
        onClose={vi.fn()}
        onRestore={vi.fn()}
        onRevoke={vi.fn()}
        onRotate={vi.fn()}
        onSave={vi.fn()}
      />,
    );

    expect(markup).toContain("Clear current push token on save");
  });

  it("keeps a configured token when the replacement is blank", () => {
    expect(buildDeviceDetailChanges(" Phone ", "   ", false)).toEqual({ name: "Phone" });
  });

  it("replaces a token only when a replacement is entered", () => {
    expect(buildDeviceDetailChanges("Phone", " replacement-token ", false)).toEqual({
      name: "Phone",
      push_token: "replacement-token",
    });
  });

  it("sends null only when clearing is explicitly selected", () => {
    expect(buildDeviceDetailChanges("Phone", "", true)).toEqual({ name: "Phone", push_token: null });
  });
});
