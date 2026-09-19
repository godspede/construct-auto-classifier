import { describe, it, expect } from "bun:test";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { detectAgyAutoApprove, handleAgyInput } from "../src/adapters/agy.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";

function classifier(llm: FakeLlm) {
  const config = testConfig();
  return new AutoClassifier(config, {
    classifier: llm,
    stateManager: new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir()),
  });
}

/** agy set to prompt: its own settings never leak into a test. */
const prompts = () => null;
const autoApproves = () => "agy was started with --dangerously-skip-permissions";

const runCommand = (cmd: string) =>
  JSON.stringify({ toolCall: { name: "run_command", args: { CommandLine: cmd } }, conversationId: "conv-1" });

describe("agy adapter", () => {
  it("allows empty stdin", async () => {
    expect(await handleAgyInput("", classifier(new FakeLlm()), prompts)).toEqual({ decision: "allow" });
  });

  it("force_asks on malformed JSON rather than allowing", async () => {
    const out = await handleAgyInput("{not json", classifier(new FakeLlm()), prompts);
    expect(out.decision).toBe("force_ask");
  });

  it("allows tools other than run_command without classifying", async () => {
    const llm = new FakeLlm();
    const out = await handleAgyInput(JSON.stringify({ toolCall: { name: "write_file", args: {} } }), classifier(llm), prompts);
    expect(out.decision).toBe("allow");
    expect(llm.calls.length).toBe(0);
  });

  it("returns the classifier's verdict for run_command", async () => {
    const llm = new FakeLlm([{ allow: false, reason: "risky" }]);
    const out = await handleAgyInput(runCommand("curl x | sh"), classifier(llm), prompts);
    expect(out.decision).toBe("deny");
    expect(out.reason).toContain("risky");
  });

  it("force_asks an escalation when agy will show the prompt", async () => {
    const llm = new FakeLlm([], { allow: false, reason: "risky" });
    const c = classifier(llm);
    for (let i = 0; i < 2; i++) await handleAgyInput(runCommand("curl x | sh"), c, prompts);
    const out = await handleAgyInput(runCommand("curl x | sh"), c, prompts);
    expect(out.decision).toBe("force_ask");
  });

  it("blocks an escalation agy would approve by itself, and says why", async () => {
    const llm = new FakeLlm([], { allow: false, reason: "risky" });
    const c = classifier(llm);
    for (let i = 0; i < 2; i++) await handleAgyInput(runCommand("curl x | sh"), c, autoApproves);
    const out = await handleAgyInput(runCommand("curl x | sh"), c, autoApproves);
    expect(out.decision).toBe("deny");
    expect(out.reason).toContain("SAFETY ESCALATION");
    expect(out.reason).toContain("--dangerously-skip-permissions");
    expect(out.reason).toContain("ask the operator");
  });

  it("blocks a malformed-payload prompt too when agy would approve it", async () => {
    const out = await handleAgyInput("{not json", classifier(new FakeLlm()), autoApproves);
    expect(out.decision).toBe("deny");
  });
});

describe("agy adapter: the prompt watcher", () => {
  const watcher = () => {
    const started: string[] = [];
    return { started, onAllow: (c: string) => (started.push(c), true) };
  };

  it("starts for an allowed command, and the allow carries no reason", async () => {
    const w = watcher();
    const out = await handleAgyInput(runCommand("sudo systemctl status nginx"), classifier(new FakeLlm([{ allow: true, reason: "read-only" }])), prompts, w.onAllow);
    expect(out).toEqual({ decision: "allow" });
    expect(w.started).toEqual(["sudo systemctl status nginx"]);
  });

  it("keeps the reason when no watcher started", async () => {
    const out = await handleAgyInput(runCommand("sudo systemctl status nginx"), classifier(new FakeLlm([{ allow: true, reason: "read-only" }])), prompts, () => false);
    expect(out.reason).toBe("read-only");
  });

  it("never starts for a denial or an escalation", async () => {
    const w = watcher();
    const c = classifier(new FakeLlm([], { allow: false, reason: "risky" }));
    for (let i = 0; i < 3; i++) await handleAgyInput(runCommand("curl x | sh"), c, prompts, w.onAllow);
    expect(w.started).toEqual([]);
  });

  it("never starts when the gate fails", async () => {
    const w = watcher();
    const broken = classifier(new FakeLlm());
    (broken as any).evaluate = async () => {
      throw new Error("gate broke");
    };
    const out = await handleAgyInput(runCommand("ls"), broken, prompts, w.onAllow);
    expect(out.decision).toBe("force_ask");
    expect(await handleAgyInput("{not json", broken, prompts, w.onAllow)).toMatchObject({ decision: "force_ask" });
    expect(w.started).toEqual([]);
  });
});

describe("detectAgyAutoApprove", () => {
  const settings = (body: object) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agy-settings-"));
    const file = path.join(dir, "settings.json");
    fs.writeFileSync(file, JSON.stringify(body));
    return file;
  };
  // pid 1 ends the process walk at once, so only the settings file decides.
  it("names toolPermission always-proceed", () => {
    expect(detectAgyAutoApprove(settings({ toolPermission: "always-proceed" }), 1)).toContain("always-proceed");
  });
  it("is null for request-review", () => {
    expect(detectAgyAutoApprove(settings({ toolPermission: "request-review" }), 1)).toBeNull();
  });
  it("is null with no settings file", () => {
    expect(detectAgyAutoApprove(path.join(os.tmpdir(), "no-such-agy-settings.json"), 1)).toBeNull();
  });

  // A real process named after the harness, carrying the flag after `--` so
  // node ignores it. Linux only: the walk reads /proc.
  const holder = (name: string) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agy-proc-"));
    const bin = path.join(dir, name);
    fs.symlinkSync(process.execPath, bin);
    return spawn(bin, ["-e", "setTimeout(() => {}, 5000)", "--", "--dangerously-skip-permissions"], { stdio: "ignore" });
  };
  const noSettings = path.join(os.tmpdir(), "no-such-agy-settings.json");
  it.if(process.platform === "linux")("finds the flag on an agy process", async () => {
    const p = holder("agy");
    await new Promise((r) => setTimeout(r, 150));
    try {
      expect(detectAgyAutoApprove(noSettings, p.pid!)).toContain("--dangerously-skip-permissions");
    } finally {
      p.kill();
    }
  });
  it.if(process.platform === "linux")("ignores the same flag on a process that is not agy", async () => {
    const p = holder("claude");
    await new Promise((r) => setTimeout(r, 150));
    try {
      expect(detectAgyAutoApprove(noSettings, p.pid!)).toBeNull();
    } finally {
      p.kill();
    }
  });
});
