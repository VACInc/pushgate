import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AuthLog } from "../api";
import { DenialBars } from "./Dashboard";

describe("DenialBars", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders denial heights as SVG attributes without inline styles", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-21T12:00:00Z"));
    const log: AuthLog = {
      id: "log-1",
      username: "alice",
      system: "host-1",
      pam_service: "sshd",
      status: "denied",
      factor: "push",
      created_at: "2026-07-21T11:30:00Z",
    };

    const html = renderToStaticMarkup(<DenialBars logs={[log]} />);

    expect(html).toContain("<svg");
    expect(html).toContain("<rect");
    expect(html).toContain('aria-label="Denials by hour"');
    expect(html).toContain('role="group"');
    expect(html).toContain('class="visually-hidden"');
    expect(html).toContain("Hourly denial counts, oldest to newest.");
    expect(html).toContain("Hour 24: 1 denial.");
    expect(html).not.toContain("style=");
  });

  it("gives the single SVG the full chart box instead of one of 24 grid tracks", () => {
    const css = readFileSync(new URL("../styles.css", import.meta.url), "utf8");
    const containerRule = css.match(/\.mini-bars\s*\{([^}]*)\}/)?.[1];
    const chartRule = css.match(/\.mini-bars__chart\s*\{([^}]*)\}/)?.[1];

    expect(containerRule).toBeDefined();
    expect(containerRule).not.toMatch(/grid-template-columns/);
    expect(chartRule).toMatch(/display:\s*block/);
    expect(chartRule).toMatch(/width:\s*100%/);
    expect(chartRule).toMatch(/height:\s*100%/);
  });
});
