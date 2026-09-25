import { describe, it, expect } from "bun:test";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { CANNOT_CHECK, agyLogLiveMode, detectAgyAutoApprove, handleAgyInput, handleAgyPreInvocation, procReader, splitCommandLine, windowsProcessReader } from "../src/adapters/agy.js";
import { getTimeoutFilePath, recordTimeout } from "../src/adapters/agy-accept.js";
import { logPath } from "../src/log.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";

function classifier(llm: FakeLlm, alwaysProceedEscalations?: "run" | "stop") {
  const config = { ...testConfig(), agy: { alwaysProceedEscalations } };
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

  it("blocks an escalation agy would approve by itself, and says why, under alwaysProceedEscalations stop", async () => {
    const llm = new FakeLlm([], { allow: false, reason: "risky" });
    const c = classifier(llm, "stop");
    for (let i = 0; i < 2; i++) await handleAgyInput(runCommand("curl x | sh"), c, autoApproves);
    const out = await handleAgyInput(runCommand("curl x | sh"), c, autoApproves);
    expect(out.decision).toBe("deny");
    expect(out.reason).toContain("SAFETY ESCALATION");
    expect(out.reason).toContain("--dangerously-skip-permissions");
    expect(out.reason).toContain("ask the user");
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
      // Walk only up to the spawned holder process itself so the ambient harness
      // (when this test runs under agy --dangerously-skip-permissions) is not walked into.
      const read = (pid: number) => (pid === p.pid ? procReader(pid) : null);
      expect(detectAgyAutoApprove(noSettings, p.pid!, read)).toBeNull();
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
      [40, 30, String.raw`"C:\Program Files\nodejs\node.exe" C:/Users/dev/construct-auto-classifier/bin/auto-classifier.js agy`],
      [30, 20, String.raw`C:\WINDOWS\system32\cmd.exe /c node ...`],
      [20, 10, String.raw`"C:\Users\dev\AppData\Local\agy\bin\agy.exe" --dangerously-skip-permissions`],
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

describe("handleAgyPreInvocation", () => {
  it("injects ephemeralMessage when a timeout occurred for this session", () => {
    recordTimeout({
      sessionId: "preinv-test-sess",
      target: { kind: "command", command: "rm -rf ./data" },
      timedOutAt: Date.now(),
      timeoutMinutes: 5,
    });

    const out = handleAgyPreInvocation({ conversationId: "preinv-test-sess" });
    expect(out.injectSteps.length).toBe(1);
    expect(out.injectSteps[0]?.ephemeralMessage).toContain("User Unavailable - Timeout");
    expect(out.injectSteps[0]?.ephemeralMessage).toContain("rm -rf ./data");
    expect(out.injectSteps[0]?.ephemeralMessage).toContain("5 minutes");
    expect(out.injectSteps[0]?.ephemeralMessage).toContain("Do NOT try to achieve this step another way");

    // Second call consumes nothing
    const out2 = handleAgyPreInvocation({ conversationId: "preinv-test-sess" });
    expect(out2.injectSteps.length).toBe(0);
  });

  it("returns empty injectSteps when no timeout occurred", () => {
    const out = handleAgyPreInvocation({ conversationId: "no-timeout-sess" });
    expect(out.injectSteps.length).toBe(0);
  });
});

describe("agy adapter: escalation watcher trigger", () => {
  it("triggers onEscalate callback when a command escalates", async () => {
    const escalated: Array<{ kind: string; command?: string }> = [];
    const onEscalate = (target: any) => {
      escalated.push(target);
      return true;
    };

    const c = classifier(new FakeLlm([], { allow: false, reason: "needs review" }));
    for (let i = 0; i < 2; i++) await handleAgyInput(runCommand("rm -rf ./data"), c, prompts);
    const out = await handleAgyInput(runCommand("rm -rf ./data"), c, prompts, () => true, onEscalate);

    expect(out.decision).toBe("force_ask");
    expect(escalated.length).toBe(1);
    expect(escalated[0]?.command).toBe("rm -rf ./data");
  });
});


describe("agyLogLiveMode", () => {
  // agy 1.2.7's log lines, as written to ~/.gemini/antigravity-cli/log.
  const START = (pid: number) => `I0920 00:50:36.262961      23 server.go:1584] Starting language server process with pid ${pid}`;
  const SURFACED = 'I0920 22:54:06.732081    1086 tool_confirmation_manager.go:225] Surfacing tool confirmation: "RunCommand" at step 525';
  const AUTO = 'I0921 12:08:46.861485    1086 tool_confirmation_manager.go:193] Always-proceed: auto-approving tool confirmation "RunCommand" at step 1023';
  const logDir = (files: Record<string, string[]>) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agy-log-"));
    for (const [name, lines] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), lines.join("\n") + "\n");
    return dir;
  };

  it("names always-proceed when the running agy last approved a confirmation by itself", () => {
    const read = agyLogLiveMode(logDir({
      "cli-20260920_005036.log": [START(939414), SURFACED, AUTO],
      "cli-20260921_124007.log": [START(936805), SURFACED],
    }));
    expect(read(939414)).toContain("always-proceed");
    expect(read(936805)).toBeNull();
  });

  it("is null once the running agy surfaces a confirmation again", () => {
    expect(agyLogLiveMode(logDir({ "cli-1.log": [START(7), AUTO, SURFACED] }))(7)).toBeNull();
  });

  it("is null for a pid no log names, and with no log directory", () => {
    expect(agyLogLiveMode(logDir({ "cli-1.log": [START(7), AUTO] }))(8)).toBeNull();
    expect(agyLogLiveMode(path.join(os.tmpdir(), "no-such-agy-log-dir"))(7)).toBeNull();
  });

  // A running agy keeps the mode /settings switched it to, even after
  // settings.json is rewritten: settings.json can say request-review while
  // every escalation runs with no prompt.
  it("lets detectAgyAutoApprove see always-proceed that settings.json no longer shows", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agy-settings-"));
    const settings = path.join(dir, "settings.json");
    fs.writeFileSync(settings, JSON.stringify({ toolPermission: "request-review" }));
    const read = (pid: number) => (pid === 20 ? { args: ["/home/dev/.local/bin/agy"], ppid: 1 } : pid === 30 ? { args: ["/bin/sh"], ppid: 20 } : null);

    const live = agyLogLiveMode(logDir({ "cli-1.log": [START(20), SURFACED, AUTO] }));
    expect(detectAgyAutoApprove(settings, 30, read, live)).toContain("always-proceed");

    const asking = agyLogLiveMode(logDir({ "cli-1.log": [START(20), AUTO, SURFACED] }));
    expect(detectAgyAutoApprove(settings, 30, read, asking)).toBeNull();
  });
});

describe("agy adapter: a blocked escalation", () => {
  it("starts no timeout watcher, since no prompt will show", async () => {
    const escalated: unknown[] = [];
    const c = classifier(new FakeLlm([], { allow: false, reason: "needs review" }), "stop");
    for (let i = 0; i < 2; i++) await handleAgyInput(runCommand("rm -rf ./data"), c, autoApproves, () => false, () => true);
    const out = await handleAgyInput(runCommand("rm -rf ./data"), c, autoApproves, () => false, (t) => (escalated.push(t), true));
    expect(out.decision).toBe("deny");
    expect(escalated).toEqual([]);
  });
});

describe("test isolation", () => {
  it("keeps the real log, timeout records and tmux panes out of reach", () => {
    const real = path.join(os.homedir(), ".config", "auto-classifier");
    expect(logPath()?.startsWith(real)).toBe(false);
    expect(getTimeoutFilePath("s").startsWith(real)).toBe(false);
    expect(process.env.TMUX).toBeUndefined();
    expect(process.env.TMUX_PANE).toBeUndefined();
  });
});

describe("agy adapter: an escalation under always-proceed, alwaysProceedEscalations run (default)", () => {
  const escalate = async (c: AutoClassifier, why: () => string | null, escalated: unknown[] = []) => {
    for (let i = 0; i < 2; i++) await handleAgyInput(runCommand("curl x | sh"), c, why, () => false, () => true);
    return handleAgyInput(runCommand("curl x | sh"), c, why, () => false, (t) => (escalated.push(t), true));
  };

  it("runs as the operator chose, logged and recorded with source always-proceed", async () => {
    const telemetry = path.join(tmpStateDir(), "t.jsonl");
    const c = classifier(new FakeLlm([], { allow: false, reason: "risky" }));
    c.getConfig().telemetry = { enabled: true, path: telemetry };
    const escalated: unknown[] = [];
    const out = await escalate(c, () => "the running agy is approving tool confirmations by itself (always-proceed)", escalated);

    expect(out.decision).toBe("force_ask");
    expect(escalated).toEqual([]); // no prompt will show, so no timeout watcher
    const rows = fs.readFileSync(telemetry, "utf-8").trim().split("\n").map((l) => JSON.parse(l));
    const ran = rows.filter((r) => r.source === "always-proceed");
    expect(ran).toHaveLength(1);
    expect(ran[0]).toMatchObject({ decision: "allow", command: "curl x | sh" });
    expect(ran[0].reason).toContain("always-proceed");
    expect(fs.readFileSync(process.env.AUTO_CLASSIFIER_LOG!, "utf-8")).toContain('agy: escalation ran unattended (always-proceed)');
  });

  it("still blocks when the gate could not tell whether agy would prompt", async () => {
    const out = await escalate(classifier(new FakeLlm([], { allow: false, reason: "risky" })), () => CANNOT_CHECK);
    expect(out.decision).toBe("deny");
  });

  it("still blocks a gate failure agy would approve", async () => {
    expect((await handleAgyInput("{not json", classifier(new FakeLlm()), autoApproves)).decision).toBe("deny");
  });
});
