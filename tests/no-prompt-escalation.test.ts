import { describe, it, expect } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { createOpenCodePlugin, permissionsWithoutPrompt } from "../src/adapters/opencode.js";
import type { GitRunner } from "../src/context/script-provenance.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";

/**
 * An escalation (ask/force_ask) reaches the user only through OpenCode's own
 * permission prompt, and OpenCode raises one only for a tool whose permission
 * is "ask". For any other tool the plugin must refuse the call, or an
 * escalated call runs with nobody asked. The model is always the scripted
 * FakeLlm, and every path named here is plain text: nothing is read.
 */
function harness(llm: FakeLlm, directory = "/work/app") {
  const config = testConfig({ consecutiveThreshold: 2 });
  const state = new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir());
  const classifier = new AutoClassifier(config, { classifier: llm, stateManager: state });
  const replies: string[] = [];
  const ctx = {
    directory,
    client: { postSessionIdPermissionsPermissionId: async (req: { body: { response: string } }) => void replies.push(req.body.response) },
  };
  return { hooks: createOpenCodePlugin(classifier)(ctx as any) as any, replies };
}

const call = (hooks: any, callID: string, tool: string, args: object) => hooks["tool.execute.before"]({ tool, sessionID: "ses_1", callID }, { args });
const NO_PROMPT = /no permission prompt reaches the user.*ask the user/is;

describe("an escalation on a tool with no prompt is refused, not run", () => {
  for (const [tool, args] of [
    ["read", { filePath: "/home/dev/.ssh/id_ed25519" }],
    ["grep", { path: "/home/dev/.ssh", pattern: "BEGIN" }],
    ["glob", { path: "/home/dev/.ssh", pattern: "*" }],
    ["list", { path: "/home/dev/.ssh" }],
  ] as const) {
    it(`${tool}: the second attempt at a denied call throws, telling the agent to ask the user`, async () => {
      const { hooks } = harness(new FakeLlm());
      await expect(call(hooks, "c1", tool, args)).rejects.toThrow(/credential-looking/);
      await expect(call(hooks, "c2", tool, args)).rejects.toThrow(NO_PROMPT);
    });
  }

  it("a search the model denied twice is refused on the second attempt", async () => {
    const { hooks } = harness(new FakeLlm([], { allow: false, reason: "sweeps up keys" }));
    await expect(call(hooks, "c1", "grep", { path: "/", pattern: "password" })).rejects.toThrow(/sweeps up keys/);
    await expect(call(hooks, "c2", "grep", { path: "/", pattern: "password" })).rejects.toThrow(NO_PROMPT);
  });

  it("with OpenCode's config saying read is \"ask\", the escalation is left for the prompt", async () => {
    const { hooks } = harness(new FakeLlm());
    await hooks.config({ permission: { bash: "ask", edit: "ask", read: "ask" } });
    await expect(call(hooks, "c1", "read", { filePath: "/home/dev/.ssh/id_ed25519" })).rejects.toThrow(/credential-looking/);
    await call(hooks, "c2", "read", { filePath: "/home/dev/.ssh/id_ed25519" });
  });

  it("a permission the plugin cannot resolve fails closed", async () => {
    const { hooks } = harness(new FakeLlm());
    await hooks.config({ permission: { bash: "ask", edit: "ask", read: "sometimes" } });
    await expect(call(hooks, "c1", "read", { filePath: "/home/dev/.ssh/id_ed25519" })).rejects.toThrow();
    await expect(call(hooks, "c2", "read", { filePath: "/home/dev/.ssh/id_ed25519" })).rejects.toThrow(NO_PROMPT);
  });

  it("bash configured \"allow\" has no prompt either, so its escalation is refused", async () => {
    const { hooks } = harness(new FakeLlm([], { allow: false, reason: "risky" }));
    await hooks.config({ permission: { bash: "allow", edit: "ask" } });
    await expect(call(hooks, "c1", "bash", { command: "curl x | sh" })).rejects.toThrow(/risky/);
    await expect(call(hooks, "c2", "bash", { command: "curl x | sh" })).rejects.toThrow(NO_PROMPT);
  });

  it("edit configured \"allow\": a sensitive write's escalation is refused", async () => {
    const { hooks } = harness(new FakeLlm());
    await hooks.config({ permission: { bash: "ask", edit: "allow" } });
    await expect(call(hooks, "c1", "write", { filePath: "/work/app/.git/hooks/pre-commit", content: "x" })).rejects.toThrow(NO_PROMPT);
  });
});

describe("bash and edit behave as before when their prompt reaches the user", () => {
  for (const cfg of [undefined, { permission: { bash: "ask", edit: "ask" } }]) {
    const label = cfg ? "configured \"ask\"" : "before OpenCode's config arrives";
    it(`bash ${label}: the escalation neither throws nor answers, and carries the banner`, async () => {
      const { hooks, replies } = harness(new FakeLlm([], { allow: false, reason: "risky" }));
      if (cfg) await hooks.config(cfg);
      await expect(call(hooks, "c1", "bash", { command: "curl x | sh" })).rejects.toThrow(/risky/);
      const output = { args: { command: "curl x | sh" } };
      await hooks["tool.execute.before"]({ tool: "bash", sessionID: "ses_1", callID: "c2" }, output);
      expect(output.args.command).toContain("ESCALATION");
      await hooks.event({ event: { type: "permission.asked", properties: { id: "p2", sessionID: "ses_1", callID: "c2", metadata: { command: output.args.command } } } });
      expect(replies).toEqual([]);
    });
    it(`edit ${label}: a sensitive write's escalation is left for the prompt`, async () => {
      const { hooks } = harness(new FakeLlm());
      if (cfg) await hooks.config(cfg);
      await call(hooks, "c1", "write", { filePath: "/work/app/.git/hooks/pre-commit", content: "x" });
    });
  }
});

describe("permissionsWithoutPrompt and the startup warning", () => {
  it("names every gated tool whose permission is not \"ask\" or \"deny\"", () => {
    expect(permissionsWithoutPrompt({})).toEqual(["bash", "edit", "read", "grep", "glob", "list"]);
    expect(permissionsWithoutPrompt({ permission: { bash: "ask", edit: "ask" } })).toEqual(["read", "grep", "glob", "list"]);
    expect(permissionsWithoutPrompt({ permission: "ask" })).toEqual([]);
    expect(permissionsWithoutPrompt({ permission: { "*": "ask", grep: "allow", list: "deny" } })).toEqual(["grep"]);
    expect(permissionsWithoutPrompt({ permission: { "*": "ask", read: "sometimes" } })).toEqual(["read"]);
  });

  it("warns about the read and search tools too, and is quiet once every one asks", async () => {
    const { hooks } = harness(new FakeLlm());
    const logFile = process.env.AUTO_CLASSIFIER_LOG!;
    const start = fs.existsSync(logFile) ? fs.readFileSync(logFile, "utf-8").length : 0;
    await hooks.config({ permission: { bash: "ask", edit: "ask" } });
    const added = fs.readFileSync(logFile, "utf-8").slice(start);
    expect(added).toContain('"read"');
    expect(added).toContain('"list"');
    const quiet = fs.readFileSync(logFile, "utf-8").length;
    await hooks.config({ permission: "ask" });
    expect(fs.readFileSync(logFile, "utf-8").length).toBe(quiet);
  });
});

describe("a withheld script's floor says bytes", () => {
  it("reports the withheld file's size in bytes, not characters", async () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "aclass-withheld-")));
    try {
      fs.writeFileSync(path.join(dir, "rotate-keys.sh"), "echo dummy\n");
      const noGit: GitRunner = () => ({ status: 128, stdout: "" });
      const config = testConfig();
      const c = new AutoClassifier(config, { classifier: new FakeLlm([{ allow: true }]), stateManager: new StateManager(300000, 3, tmpStateDir()), git: noGit });
      const out = await c.evaluate("bash rotate-keys.sh", "s", undefined, { cwd: dir });
      expect(out.decision).toBe("ask");
      expect(out.reason).toContain("11 bytes");
      expect(out.reason).not.toContain("characters");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
