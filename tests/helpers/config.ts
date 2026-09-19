import type { AppConfig } from "../../src/types.js";

/** A config literal, never loadConfig(): the box's own ~/.config must not leak into a test. */
export function testConfig(overrides: Partial<AppConfig["policy"]> = {}, rules: Partial<AppConfig["rules"]> = {}): AppConfig {
  return {
    llm: { baseUrl: "http://127.0.0.1:9/v1", model: "fake", timeoutMs: 100 },
    jev: { baseUrl: "http://127.0.0.1:9", model: "jev-fake", timeoutMs: 100 },
    policy: {
      denyMode: "both",
      consecutiveThreshold: 3,
      slidingWindowMs: 300000,
      instructAgentOnDenial: true,
      headless: false,
      trustLandedScripts: true,
      ...overrides,
    },
    rules: {
      fastDeny: ["^\\s*mkfs(\\.[a-z0-9]+)?\\s+"],
      fastAllow: ["^\\s*git\\s+(status|diff|log)\\b", "^\\s*pwd$", "^\\s*cargo\\s+build\\b"],
      ...rules,
    },
    telemetry: { enabled: false, path: "" },
  };
}
