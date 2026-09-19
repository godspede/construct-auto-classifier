import { describe, it, expect } from "bun:test";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { detectAgyAutoApprove, handleAgyInput, splitCommandLine, windowsProcessReader } from "../src/adapters/agy.js";
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

describe("detectAgyAutoApprove on Windows", () => {
  const noSettings = path.join(os.tmpdir(), "no-such-agy-settings.json");
  // The shape PowerShell's ConvertTo-Json gives Get-CimInstance Win32_Process.
  const snapshot = (rows: Array<[number, number, string | null]>) => () =>
    JSON.stringify(rows.map(([ProcessId, ParentProcessId, CommandLine]) => ({ ProcessId, ParentProcessId, CommandLine })));

  it("finds the flag on agy.exe above the hook, through a shell", () => {
    const read = windowsProcessReader(snapshot([
      [40, 30, String.raw`"C:\Program Files\nodejs\node.exe" C:/Users/z/.config/auto-classifier/auto-classifier-cli.js agy`],
      [30, 20, String.raw`C:\WINDOWS\system32\cmd.exe /c node ...`],
      [20, 10, String.raw`"C:\Users\z\AppData\Local\agy\bin\agy.exe" --dangerously-skip-permissions`],
    ]));
    expect(detectAgyAutoApprove(noSettings, 30, read)).toContain("--dangerously-skip-permissions");
  });
  it("is null for agy.exe started without the flag", () => {
    const read = windowsProcessReader(snapshot([[20, 10, String.raw`"C:\agy\bin\agy.exe"`]]));
    expect(detectAgyAutoApprove(noSettings, 20, read)).toBeNull();
  });
  it("ignores the same flag on a process that is not agy", () => {
    const read = windowsProcessReader(snapshot([
      [20, 10, String.raw`C:\bin\claude.exe --dangerously-skip-permissions`],
      [10, 4, null],
    ]));
    expect(detectAgyAutoApprove(noSettings, 20, read)).toBeNull();
  });
  it("refuses to guess when the process table cannot be read", () => {
    const read = windowsProcessReader(() => {
      throw new Error("powershell.exe not found");
    });
    expect(detectAgyAutoApprove(noSettings, 20, read)).toContain("could not check");
  });
  it("takes one snapshot for the whole walk", () => {
    let calls = 0;
    const read = windowsProcessReader(() => {
      calls++;
      return snapshot([[30, 20, "cmd.exe"], [20, 10, String.raw`C:\agy.exe`]])();
    });
    detectAgyAutoApprove(noSettings, 30, read);
    expect(calls).toBe(1);
  });
  it.if(process.platform === "win32")("reads the real process table", () => {
    // This test process's own parent is in the snapshot, so the walk runs
    // and, finding no agy above it, ends without a reason.
    expect(detectAgyAutoApprove(noSettings, process.ppid, windowsProcessReader())).toBeNull();
  });
});

describe("splitCommandLine", () => {
  it("keeps a quoted path with spaces as one argument", () => {
    expect(splitCommandLine(String.raw`"C:\Program Files\agy\agy.exe" --dangerously-skip-permissions x`)).toEqual([
      String.raw`C:\Program Files\agy\agy.exe`,
      "--dangerously-skip-permissions",
      "x",
    ]);
  });
});
