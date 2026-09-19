import { describe, expect, test } from "bun:test";
import { JevClient, RISK_QUESTIONS, buildRequest, combine, type JevResponse } from "../src/classifier/jev-client.js";
import { createClassifier, LlmClient } from "../src/index.js";
import { testConfig } from "./helpers/config.js";
import { commandTransport } from "../src/classifier/jev-client.js";
import { loadConfig } from "../src/config.js";
import { isProtectedEnvOverride } from "../src/rules/self-protection.js";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const quiet = Object.fromEntries(Object.keys(RISK_QUESTIONS).map((id) => [id, { type: "noul", noul: 0.05 }]));

function reply(choice: "allow" | "deny", pAllow: number, confidence: number, risks: Record<string, number> = {}): JevResponse {
  const answers: Record<string, any> = { ...quiet };
  for (const [id, p] of Object.entries(risks)) answers[id] = { type: "noul", noul: p };
  answers.verdict = { type: "choice", choice, probabilities: { allow: pAllow, deny: 1 - pAllow }, confidence };
  return { model: "jev-test", answers };
}

describe("combine", () => {
  test("a confident allow with every risk low is an allow", () => {
    expect(combine(reply("allow", 1, 1), {}).allow).toBe(true);
  });

  test("a deny verdict denies whatever the risks say", () => {
    expect(combine(reply("deny", 0.1, 0.9), {}).allow).toBe(false);
  });

  test("one risk question over threshold overrides an allow verdict", () => {
    const r = combine(reply("allow", 0.95, 0.9, { secrets: 0.82 }), {});
    expect(r.allow).toBe(false);
    expect(r.reason).toContain("secrets 0.82");
  });

  test("an unsure allow is not an unattended allow", () => {
    expect(combine(reply("allow", 0.6, 0.3), {}).allow).toBe(false);
  });

  test("a missing risk answer fails closed", () => {
    const res = reply("allow", 1, 1);
    delete res.answers!.remote_code;
    expect(combine(res, {}).allow).toBe(false);
  });

  test("no verdict fails closed", () => {
    expect(combine({ answers: quiet as any }, {}).allow).toBe(false);
  });
});

describe("JevClient", () => {
  test("asks the verdict and every risk question about one state", async () => {
    let sent: any;
    const client = new JevClient({ model: "jev-latest" }, async (body) => {
      sent = body;
      return reply("allow", 1, 1);
    });
    const r = await client.classify("git push --force origin main");
    expect(r.source).toBe("llm");
    expect(Object.keys(sent.questions).sort()).toEqual(["verdict", ...Object.keys(RISK_QUESTIONS)].sort());
    expect(sent.state.command).toBe("git push --force origin main");
  });

  test("a script's content rides in the state, capped and redacted", () => {
    const body = buildRequest("./x.sh", { path: "x.sh", content: "export API_TOKEN=abcdefghijklmnop\nrm -rf /", provenance: "untracked" }, {});
    const file = (body.state as any).script_file;
    expect(file.provenance).toBe("untracked");
    expect(file.content).not.toContain("abcdefghijklmnop");
  });

  test("a transport failure is a transient deny, never an allow", async () => {
    const client = new JevClient({}, async () => {
      throw new Error("boom");
    });
    const r = await client.classify("ls");
    expect(r).toMatchObject({ allow: false, source: "error" });
  });
});

describe("createClassifier", () => {
  test("the chat client by default, Jev when the provider is jev", () => {
    const cfg = testConfig();
    const shipped = loadConfig(path.join(import.meta.dir, "..", "bench", "bench-config.jsonc"));
    expect(shipped.llm.provider).toBe("openai");
    expect(shipped.jev.model).toBe("jev-1.13.0");
    expect(createClassifier(shipped)).toBeInstanceOf(LlmClient);
    expect(createClassifier({ ...cfg, llm: { ...cfg.llm, provider: "jev" } })).toBeInstanceOf(JevClient);
  });
});

describe("commandTransport", () => {
  const helper = (body: string) => {
    const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "jev-helper-")), "h.sh");
    fs.writeFileSync(p, `#!/bin/sh\ncat >/dev/null\n${body}\n`, { mode: 0o755 });
    return p;
  };

  test("reads the helper's JSON response", async () => {
    const res = await commandTransport([helper(`echo '{"model":"jev-x","answers":{}}'`)])({}, 5000);
    expect(res.model).toBe("jev-x");
  });

  test("a failing helper rejects without putting its stderr in the error", async () => {
    await expect(commandTransport([helper("echo secret-ish >&2; exit 3")])({}, 5000)).rejects.toThrow(/^Jev helper exited 3$/);
  });

  test("a helper that hangs is killed at the timeout", async () => {
    await expect(commandTransport([helper("sleep 5")])({}, 200)).rejects.toThrow(/timed out/);
  });
});

describe("the gate's own variables are protected", () => {
  test("TYPESAFE_* and AUTO_CLASSIFIER_JEV_* reconfigure the gate, so setting one is refused", () => {
    expect(isProtectedEnvOverride("TYPESAFE_BASE_URL")).toBe(true);
    expect(isProtectedEnvOverride("AUTO_CLASSIFIER_JEV_COMMAND")).toBe(true);
    expect(isProtectedEnvOverride("HOME")).toBe(false);
  });
});
