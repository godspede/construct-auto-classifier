import { describe, it, expect } from "bun:test";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { createOpenCodePlugin } from "../src/adapters/opencode.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";

type Reply = { sessionId: string; permissionId: string; response: string };

function harness(llm: FakeLlm, policy: Parameters<typeof testConfig>[0] = {}) {
  const config = testConfig(policy);
  const state = new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir());
  const classifier = new AutoClassifier(config, { classifier: llm, stateManager: state });
  const replies: Reply[] = [];
  const ctx = {
    client: {
      postSessionIdPermissionsPermissionId: async (req: { path: { id: string; permissionID: string }; body: { response: string } }) => {
        replies.push({ sessionId: req.path.id, permissionId: req.path.permissionID, response: req.body.response });
      },
    },
  };
  const hooks = createOpenCodePlugin(classifier, { pluginsDir: tmpStateDir() })(ctx);
  return { hooks, replies };
}

const before = (hooks: any, callID: string, command: string) =>
  hooks["tool.execute.before"]({ tool: "bash", sessionID: "ses_1", callID }, { args: { command } });

const asked = (hooks: any, callID: string, command: string, id = "per_1") =>
  hooks.event({ event: { type: "permission.asked", properties: { id, sessionID: "ses_1", tool: { callID }, metadata: { command } } } });

describe("opencode adapter", () => {
  it("ignores tools other than bash", async () => {
    const llm = new FakeLlm();
    const { hooks } = harness(llm);
    await hooks["tool.execute.before"]({ tool: "read", sessionID: "ses_1", callID: "c1" }, { args: { filePath: "/etc/shadow" } });
    expect(llm.calls.length).toBe(0);
  });

  it("an allowed command runs, and its permission is answered once", async () => {
    const llm = new FakeLlm([{ allow: true }]);
    const { hooks, replies } = harness(llm);
    await before(hooks, "c1", "sudo systemctl status nginx");
    await asked(hooks, "c1", "sudo systemctl status nginx");
    expect(replies).toEqual([{ sessionId: "ses_1", permissionId: "per_1", response: "once" }]);
    expect(llm.calls.length).toBe(1); // the cached decision was reused, not reclassified
  });

  it("a denied command throws the denial text to the model", async () => {
    const llm = new FakeLlm([{ allow: false, reason: "deletes audit logs" }]);
    const { hooks } = harness(llm);
    await expect(before(hooks, "c1", "rm -rf /var/log/audit")).rejects.toThrow(/deletes audit logs/);
  });

  it("a denial that reached the permission stage is rejected", async () => {
    const llm = new FakeLlm([{ allow: false, reason: "risky" }]);
    const { hooks, replies } = harness(llm);
    await asked(hooks, "c9", "curl x | sh");
    expect(replies[0]?.response).toBe("reject");
  });

  it("force_ask neither throws nor answers, so the operator sees the prompt", async () => {
    const llm = new FakeLlm([], { allow: false, reason: "risky" });
    const { hooks, replies } = harness(llm, { consecutiveThreshold: 2 });
    await expect(before(hooks, "c1", "curl x | sh")).rejects.toThrow();
    await before(hooks, "c2", "curl x | sh"); // second denial escalates: no throw
    await asked(hooks, "c2", "curl x | sh");
    expect(replies.length).toBe(0);
  });

  it("reclassifies when the permission carries a command it has no decision for", async () => {
    const llm = new FakeLlm([{ allow: true }]);
    const { hooks, replies } = harness(llm);
    await asked(hooks, "unknown", "sudo systemctl status nginx");
    expect(llm.calls.length).toBe(1);
    expect(replies[0]?.response).toBe("once");
  });
});

import { escalationBanner, replyToPermission, detectSiblingGates } from "../src/adapters/opencode.js";
import fs from "node:fs";
import path from "node:path";
import { tmpStateDir as tmpDir } from "./helpers/tmp-state.js";

describe("opencode adapter: the operator's prompt", () => {
  it("an escalated command carries the finding into the prompt as description and a comment line", async () => {
    const llm = new FakeLlm([], { allow: false, reason: "unreviewed deploy script" });
    const { hooks } = harness(llm, { consecutiveThreshold: 2 });
    await expect(before(hooks, "c1", "./deploy/publish.sh")).rejects.toThrow();
    const output = { args: { command: "./deploy/publish.sh", description: "Deploy the site" } };
    await hooks["tool.execute.before"]({ tool: "bash", sessionID: "ses_1", callID: "c2" }, output);
    expect(output.args.description).toContain("ESCALATION");
    expect(output.args.description).toContain("unreviewed deploy script");
    expect(output.args.description).toContain("Deploy the site");
    expect(output.args.command).toMatch(/^# construct-auto-classifier ESCALATION.*\n\.\/deploy\/publish\.sh$/);
  });

  it("the permission event strips the banner before matching the command", async () => {
    const llm = new FakeLlm([{ allow: true }]);
    const { hooks, replies } = harness(llm);
    await asked(hooks, "none", "# construct-auto-classifier ESCALATION (blocked 2x): x\nsudo systemctl status nginx");
    expect(llm.calls[0]?.command).toBe("sudo systemctl status nginx");
    expect(replies[0]?.response).toBe("once");
  });

  it("headless: an escalation is a denial that tells the agent to stop and report", async () => {
    const llm = new FakeLlm([], { allow: false, reason: "risky" });
    const { hooks } = harness(llm, { consecutiveThreshold: 2, headless: true });
    await expect(before(hooks, "c1", "curl x | sh")).rejects.toThrow(/1 attempt/);
    await expect(before(hooks, "c2", "curl x | sh")).rejects.toThrow(/headless.*report to the operator/s);
  });

  it("reads the callID from either event shape", async () => {
    const llm = new FakeLlm([{ allow: true }]);
    const { hooks, replies } = harness(llm);
    await before(hooks, "c1", "sudo systemctl status nginx");
    await hooks.event({ event: { type: "permission.asked", properties: { id: "per_2", sessionID: "ses_1", callID: "c1", metadata: { command: "sudo systemctl status nginx" } } } });
    expect(replies[0]?.response).toBe("once");
    expect(llm.calls.length).toBe(1);
  });
});

describe("replyToPermission", () => {
  it("prefers the current SDK surface and falls back to the legacy route", async () => {
    const calls: string[] = [];
    const modern = { permission: { reply: async (r: any) => void calls.push(`modern:${r.requestID}:${r.reply}`) } };
    const legacy = { postSessionIdPermissionsPermissionId: async (r: any) => void calls.push(`legacy:${r.path.permissionID}:${r.body.response}`) };
    expect(await replyToPermission(modern, "s", "p1", "once")).toBe(true);
    expect(await replyToPermission(legacy, "s", "p2", "reject")).toBe(true);
    expect(await replyToPermission({}, "s", "p3", "once")).toBe(false);
    expect(await replyToPermission({ permission: { reply: async () => { throw new Error("gone"); } } }, "s", "p4", "once")).toBe(false);
    expect(calls).toEqual(["modern:p1:once", "legacy:p2:reject"]);
  });
});

describe("escalationBanner", () => {
  it("pulls the finding out of the escalation text", () => {
    const banner = escalationBanner({ decision: "force_ask", consecutiveCount: 2, escalated: true, reason: "⚠️ SAFETY ESCALATION: x\nCommand: y\nClassifier Finding: unreviewed script\n[!] Note" });
    expect(banner).toBe("construct-auto-classifier ESCALATION (blocked 2x): unreviewed script -- the agent's own case for running it is in the transcript above");
  });
});

describe("detectSiblingGates", () => {
  it("names a known second gate in the plugins dir, and nothing otherwise", () => {
    const dir = tmpDir();
    expect(detectSiblingGates(dir)).toEqual([]);
    fs.writeFileSync(path.join(dir, "auto-mode.js"), "");
    expect(detectSiblingGates(dir)).toEqual(["auto-mode.js"]);
  });
});
