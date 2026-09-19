import { describe, it, expect } from "bun:test";
import { buildSystemPrompt, buildUserPrompt, redactSecrets } from "../src/classifier/prompt.js";

describe("Prompt Generator", () => {
  it("includes effect-based rules in system prompt", () => {
    const prompt = buildSystemPrompt();
    expect(prompt).toContain("Privilege is not a verdict");
    expect(prompt).toContain("blast radius");
    expect(prompt).toContain("sudo systemctl status");
    expect(prompt).toContain("UNTRUSTED");
    expect(prompt).toContain('Reply with ONLY valid JSON: {"allow": true or false, "reason": "at most 20 words"}');
  });

  it("lets reversibility, not the act of touching config, decide a service-config change", () => {
    // A config change one command undoes (`tailscale serve --https=<port> off`)
    // is reversible, so touching service configuration is not by itself a DENY.
    const prompt = buildSystemPrompt();
    expect(prompt).toContain("trivially reversible");
    expect(prompt).toContain("publishing or retiring a listener");
    expect(prompt).toContain("Reversibility decides this");
  });

  it("redacts bearer tokens and secrets in user prompt", () => {
    const rawCommand = "curl -H 'Authorization: Bearer my-super-secret-token-12345' https://example.com";
    const userPrompt = buildUserPrompt(rawCommand);
    expect(userPrompt).toContain("Bearer [REDACTED]");
    expect(userPrompt).not.toContain("my-super-secret-token-12345");
  });

  it("redacts private keys in scripts", () => {
    // Assembled at runtime so no secret scanner mistakes the fixture for a real key.
    const pem = (edge: string) => `-----${edge} RSA ${"PRIVATE"} KEY-----`;
    const textWithKey = `
${pem("BEGIN")}
MIIEowIBAAKCAQEA0Y1+
${pem("END")}
`;
    const redacted = redactSecrets(textWithKey);
    expect(redacted).toContain("[REDACTED PRIVATE KEY]");
    expect(redacted).not.toContain("MIIEowIBAAKCAQEA0Y1+");
  });
});

describe("buildUserPrompt: truncation is marked, not silent", () => {
  it("emits a marker with the shown and true sizes when the file is truncated", () => {
    const prompt = buildUserPrompt("python3 gen_assets.py", {
      path: "/repo/gen_assets.py",
      content: "x".repeat(2000),
      truncated: true,
      originalLength: 3618,
    });
    expect(prompt).toContain("[truncated: showing 2000 of 3618 characters]");
  });

  it("emits no marker for an untruncated file", () => {
    const prompt = buildUserPrompt("python3 gen_assets.py", {
      path: "/repo/gen_assets.py",
      content: "echo hi",
      truncated: false,
    });
    expect(prompt).not.toContain("[truncated:");
  });
});

describe("Prompt override", () => {
  it("AUTO_CLASSIFIER_SYSTEM_PROMPT_FILE replaces the built-in prompt", () => {
    const fs = require("node:fs");
    const p = require("node:path").join(require("node:os").tmpdir(), `prompt-${Math.random().toString(36).slice(2)}.txt`);
    fs.writeFileSync(p, "custom prompt");
    process.env.AUTO_CLASSIFIER_SYSTEM_PROMPT_FILE = p;
    try {
      expect(buildSystemPrompt()).toBe("custom prompt");
    } finally {
      delete process.env.AUTO_CLASSIFIER_SYSTEM_PROMPT_FILE;
    }
    expect(buildSystemPrompt()).toContain("Privilege is not a verdict");
  });
});
