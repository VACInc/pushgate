import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { Integration } from "../api";
import { buildIntegrationDetailChanges, CreateIntegrationModal, IntegrationDetailDrawer } from "./Integrations";

const integration: Integration = {
  id: "integration-1",
  name: "Bound PAM",
  client_id: "bound-pam",
  system_type: "linux-pam",
  principal_username: "service-account",
  approver_username: "operator",
  system_name: "lab-host",
  fail_mode: "closed",
  enabled: true,
};

describe("integration security bindings", () => {
  it("renders binding fields when creating an integration", () => {
    const markup = renderToStaticMarkup(
      <CreateIntegrationModal busy={false} onClose={vi.fn()} onSubmit={vi.fn()} open />,
    );

    expect(markup).toContain('name="principal_username"');
    expect(markup).toContain('name="approver_username"');
    expect(markup).toContain('name="system_name"');
  });

  it("renders current bindings in the integration drawer", () => {
    const markup = renderToStaticMarkup(
      <IntegrationDetailDrawer
        busy={false}
        integration={integration}
        onClose={vi.fn()}
        onDetails={vi.fn()}
        onEnabled={vi.fn()}
        onFailMode={vi.fn()}
      />,
    );

    expect(markup).toContain('value="service-account"');
    expect(markup).toContain('value="operator"');
    expect(markup).toContain('value="lab-host"');
  });

  it("trims replacements and sends null when bindings are cleared", () => {
    expect(buildIntegrationDetailChanges(" Bound PAM ", "", " new-operator ", "   ")).toEqual({
      name: "Bound PAM",
      principal_username: null,
      approver_username: "new-operator",
      system_name: null,
    });
  });
});
