import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { createOpenCodePlugin } from "../src/adapters/opencode.js";
import { judgeFileWrite } from "../src/rules/file-write.js";
import { isGatePath, isSecretPath, protectGateFile, selfProtectionDenial } from "../src/rules/self-protection.js";
import { isSensitiveWriteTarget } from "../src/rules/sensitive-write.js";
import { analyzeCommand } from "../src/rules/command-shape.js";
import { findReferencedFiles } from "../src/context/file-references.js";
import type { GitRunner } from "../src/context/script-provenance.js";
import type { FileContext } from "../src/types.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";

/**
 * What the gate shows the model, what it remembers, and what it protects.
 * Every fixture is a throwaway `mkdtemp` tree holding dummy
 * files, with HOME pointed at a directory inside it; nothing outside it is
 * read or written, and the model is always the scripted FakeLlm.
 */
let saved: string | undefined;
let base = "";
let home = "";

beforeEach(() => {
  saved = process.env.HOME;
  base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "aclass-findings-")));
  home = path.join(base, "home");
  for (const d of [path.join(home, ".ssh"), path.join(home, ".config", "auto-classifier"), path.join(base, "a"), path.join(base, "b"), path.join(base, "ws")]) {
    fs.mkdirSync(d, { recursive: true });
  }
  fs.writeFileSync(path.join(home, ".ssh", "id_ed25519"), "dummy key");
  fs.writeFileSync(path.join(home, ".config", "auto-classifier", "config.jsonc"), "{}");
  process.env.HOME = home;
});

afterEach(() => {
  if (saved === undefined) delete process.env.HOME;
  else process.env.HOME = saved;
  fs.rmSync(base, { recursive: true, force: true });
});

/** No repository anywhere: every git call fails, so no real git runs. */
const noGit: GitRunner = () => ({ status: 128, stdout: "" });

function build(llm: FakeLlm, rules: Parameters<typeof testConfig>[1] = {}) {
  const config = testConfig({}, rules);
  const state = new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir());
  return new AutoClassifier(config, { classifier: llm, stateManager: state, git: noGit });
}

function plugin(llm: FakeLlm, directory: string) {
  return createOpenCodePlugin(build(llm))({ client: {}, directory } as any) as any;
}
const call = (h: any, tool: string, args: object) => h["tool.execute.before"]({ tool, sessionID: "ses_1", callID: "c1" }, { args });

describe("a remembered allow answers only for everything the model was shown", () => {
  it("does not answer the same command in a different working directory", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "fine here" }], { allow: false, reason: "not fine there" });
    const c = build(llm);
    expect((await c.evaluate("make deploy", "s", undefined, { cwd: path.join(base, "a") })).decision).toBe("allow");
    const other = await c.evaluate("make deploy", "s", undefined, { cwd: path.join(base, "b") });
    expect(other.decision).toBe("deny");
    expect(llm.calls.length).toBe(2);
  });

  it("does not answer when a second attached file changed", async () => {
    const dir = path.join(base, "a");
    fs.writeFileSync(path.join(dir, "one.sql"), "SELECT 1;");
    fs.writeFileSync(path.join(dir, "two.sql"), "SELECT 2;");
    const llm = new FakeLlm([{ allow: true, reason: "reads" }], { allow: false, reason: "now it drops a table" });
    const c = build(llm);
    const cmd = "psql -f one.sql -f two.sql";
    expect((await c.evaluate(cmd, "s", undefined, { cwd: dir })).decision).toBe("allow");
    fs.writeFileSync(path.join(dir, "two.sql"), "DROP TABLE users;");
    expect((await c.evaluate(cmd, "s", undefined, { cwd: dir })).decision).toBe("deny");
    expect(llm.calls.length).toBe(2);
  });

  it("does not answer when an attached file other than the first changed alongside a given script", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "fine" }], { allow: false, reason: "changed" });
    const c = build(llm);
    const shown = (second: string): FileContext => ({
      path: "/repo/run.sh",
      content: "echo hi",
      attachedFiles: [{ path: "a.txt", content: "a", executed: false }, { path: "b.txt", content: second, executed: false }],
    });
    const cwd = path.join(base, "ws");
    expect((await c.evaluate("./run.sh a.txt b.txt", "s", shown("b"), { cwd })).decision).toBe("allow");
    expect((await c.evaluate("./run.sh a.txt b.txt", "s", shown("b changed"), { cwd })).decision).toBe("deny");
    expect(llm.calls.length).toBe(2);
  });

  it("does not answer a relative file write placed from a different workspace", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "fine" }], { allow: false, reason: "lands elsewhere" });
    // No scratch root: the fixture lives under the machine's temp directory.
    const c = build(llm, { scratchWriteRoots: [] });
    expect((await c.evaluateFileOp("write", "../out/notes.txt", "s", "x", { cwd: path.join(base, "a") })).decision).toBe("allow");
    expect((await c.evaluateFileOp("write", "../out/notes.txt", "s", "x", { cwd: path.join(base, "b", "deep") })).decision).toBe("deny");
    expect(llm.calls.length).toBe(2);
  });

  it("control: the same command, directory and files are still answered from the cache", async () => {
    const dir = path.join(base, "a");
    fs.writeFileSync(path.join(dir, "one.sql"), "SELECT 1;");
    fs.writeFileSync(path.join(dir, "two.sql"), "SELECT 2;");
    const llm = new FakeLlm([{ allow: true, reason: "reads" }]);
    const c = build(llm);
    await c.evaluate("psql -f one.sql -f two.sql", "s", undefined, { cwd: dir });
    const again = await c.evaluate("psql -f one.sql -f two.sql", "s", undefined, { cwd: dir });
    expect(again.decision).toBe("allow");
    expect(again.reason).toContain("same verdict");
    expect(llm.calls.length).toBe(1);
  });
});

describe("the gate's config and credential directories are not reachable by read or search", () => {
  it("counts a .jsonc config or auth file under ~/.config as credential-looking, like .json", () => {
    expect(isSecretPath("~/.config/tea/config.jsonc")).toBe(true);
    expect(isSecretPath("/home/dev/.config/some-cli/auth.jsonc")).toBe(true);
    expect(isSecretPath("/work/deploy/credentials.jsonc")).toBe(true);
    expect(isSecretPath("/work/tsconfig.jsonc")).toBe(false);
  });

  it("denies an OpenCode read of a .jsonc auth file", async () => {
    const llm = new FakeLlm();
    const out = await build(llm).evaluateFileOp("read", "~/.config/some-cli/config.jsonc", "s", undefined, { cwd: path.join(base, "ws") });
    expect(out.decision).toBe("deny");
  });

  for (const tool of ["grep", "glob", "list"]) {
    it(`refuses ${tool} scoped at the gate's own config directory`, async () => {
      const llm = new FakeLlm([], { allow: true, reason: "model would allow" });
      await expect(call(plugin(llm, path.join(base, "ws")), tool, { path: path.join(home, ".config", "auto-classifier") })).rejects.toThrow(/safety classifier/);
      expect(llm.calls.length).toBe(0);
    });
  }

  it("the library refuses a search scoped inside the gate's config directory too", async () => {
    const llm = new FakeLlm([], { allow: true, reason: "model would allow" });
    const out = await build(llm).evaluateSearchScope("grep", "~/.config/auto-classifier", "s", { cwd: path.join(base, "ws") });
    expect(out.decision).toBe("deny");
    expect(llm.calls.length).toBe(0);
  });

  for (const [what, scope] of [
    ["the home directory", () => home],
    ["~ as written", () => "~"],
    ["~/.config, which holds the gate's config", () => path.join(home, ".config")],
    ["the filesystem root", () => "/"],
  ] as const) {
    it(`sends a search scoped at ${what} to the model instead of allowing it`, async () => {
      const llm = new FakeLlm();
      const out = await build(llm).evaluateSearchScope("grep", scope(), "s", { cwd: path.join(base, "ws") });
      expect(llm.calls.length).toBe(1);
      expect(out.decision).toBe("deny");
    });
  }

  it("sends a search with no path to the model when the workspace is the home directory", async () => {
    const llm = new FakeLlm();
    await build(llm).evaluateSearchScope("glob", undefined, "s", { cwd: home });
    expect(llm.calls.length).toBe(1);
  });

  it("a model allow of such a search is an allow", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "looks for TODOs" }]);
    const out = await build(llm).evaluateSearchScope("grep", "~", "s", { cwd: path.join(base, "ws") });
    expect(out.decision).toBe("allow");
  });

  it("control: a search inside an ordinary workspace is still allowed with no model call", async () => {
    const llm = new FakeLlm();
    const ws = path.join(base, "ws");
    expect((await build(llm).evaluateSearchScope("grep", path.join(ws, "src"), "s", { cwd: ws })).decision).toBe("allow");
    expect((await build(llm).evaluateSearchScope("list", undefined, "s", { cwd: ws })).decision).toBe("allow");
    expect(llm.calls.length).toBe(0);
  });
});

describe("a gate or credential file referenced by a command is withheld from the model", () => {
  it("attaches a gate file as a withheld note instead of skipping it silently", () => {
    const cfg = path.join(home, ".config", "auto-classifier", "config.jsonc");
    fs.writeFileSync(cfg, '{"llm": {"apiKey": "dummy-gate-value"}}');
    const found = findReferencedFiles(`jq . ${cfg}`, path.join(base, "ws"));
    expect(found.length).toBe(1);
    expect(found[0]!.content).toContain("withheld");
    expect(found[0]!.content).not.toContain("dummy-gate-value");
  });

  it("attaches a credential-looking file as a withheld note, not its redacted content", () => {
    const ws = path.join(base, "ws");
    fs.writeFileSync(path.join(ws, "credentials.json"), '{"password": "dummy-secret-value"}');
    const found = findReferencedFiles("jq . credentials.json", ws);
    expect(found.length).toBe(1);
    expect(found[0]!.content).toContain("withheld");
    expect(found[0]!.content).not.toContain("dummy-secret-value");
    expect(found[0]!.executed).toBe(false);
  });

  it("control: an ordinary referenced file is still attached with its content", () => {
    const ws = path.join(base, "ws");
    fs.writeFileSync(path.join(ws, "notes.md"), "plain notes");
    expect(findReferencedFiles("cat notes.md", ws)[0]?.content).toBe("plain notes");
  });

  it("withholds an executed credential-named script, and a model allow of it floors to ask", async () => {
    const ws = path.join(base, "ws");
    fs.writeFileSync(path.join(ws, "rotate-keys.sh"), "echo dummy-script-body\n");
    const llm = new FakeLlm([{ allow: true, reason: "fine" }]);
    const out = await build(llm).evaluate("bash rotate-keys.sh", "s", undefined, { cwd: ws });
    expect(llm.calls.length).toBe(1);
    expect(JSON.stringify(llm.calls[0]!.fileContext)).not.toContain("dummy-script-body");
    expect(out.decision).toBe("ask");
  });

  it("withholds an executed script inside the gate's config directory, and floors its allow", async () => {
    const script = path.join(home, ".config", "auto-classifier", "hook.sh");
    fs.writeFileSync(script, "echo dummy-gate-script\n");
    const llm = new FakeLlm([{ allow: true, reason: "fine" }]);
    const out = await build(llm).evaluate(`bash ${script}`, "s", undefined, { cwd: path.join(base, "ws") });
    expect(JSON.stringify(llm.calls[0]!.fileContext)).not.toContain("dummy-gate-script");
    expect(out.decision).toBe("ask");
  });
});

describe("agy's file writes check credential-looking paths", () => {
  const ws = ["/work/app"];
  for (const p of ["/work/app/certs/server.pem", "/work/app/config/credentials.json", "/work/app/.ssh/authorized_keys"]) {
    it(`escalates a write to ${p}, even inside the workspace`, () => {
      const v = judgeFileWrite(p, ws, "linux");
      expect(v.decision).toBe("escalate");
      expect(v.decision === "escalate" && v.reason).toContain("credential-looking");
    });
  }
  it("control: an ordinary workspace file is still allowed", () => {
    expect(judgeFileWrite("/work/app/src/index.ts", ws, "linux")).toEqual({ decision: "allow" });
  });
});

describe("the startup-location rule means the system's etc, not any folder named etc", () => {
  for (const p of ["/etc/x", "/etc/cron.d/x", "/private/etc/hosts", "/usr/local/etc/nginx/nginx.conf", "/opt/homebrew/etc/x.conf", String.raw`C:\Windows\System32\drivers\etc\hosts`]) {
    it(`still flags ${p}`, () => expect(isSensitiveWriteTarget(p)).toBe(true));
  }
  for (const p of ["/home/dev/src/etc/app/x.ts", "~/etc/notes", "/work/app/etc/config.yml", "etc/x"]) {
    it(`no longer flags ${p}`, () => expect(isSensitiveWriteTarget(p)).toBe(false));
  }

  it("agy: a workspace under ~/src/etc/ no longer escalates every write", () => {
    expect(judgeFileWrite("/home/dev/src/etc/app/src/x.ts", ["/home/dev/src/etc/app"], "linux")).toEqual({ decision: "allow" });
  });
  it("agy: /etc/x still escalates", () => {
    expect(judgeFileWrite("/etc/x", ["/"], "linux").decision).toBe("escalate");
  });
  it("agy: a relative etc/ path is judged where it resolves", () => {
    expect(judgeFileWrite("etc/x", ["/"], "linux").decision).toBe("escalate");
    expect(judgeFileWrite("etc/x", ["/work/app"], "linux")).toEqual({ decision: "allow" });
  });

  it("OpenCode: a write in a workspace under a folder named etc is allowed with no model call", async () => {
    const ws = path.join(base, "src", "etc", "app");
    fs.mkdirSync(ws, { recursive: true });
    const llm = new FakeLlm();
    expect((await build(llm).evaluateFileOp("write", "x.ts", "s", "x", { cwd: ws })).decision).toBe("allow");
    expect(llm.calls.length).toBe(0);
  });
  it("OpenCode: a relative etc/ write from / still goes to the model", async () => {
    const llm = new FakeLlm();
    await build(llm).evaluateFileOp("write", "etc/cron.d/x", "s", "x", { cwd: "/" });
    expect(llm.calls.length).toBe(1);
  });
});

describe("a hard link to a gate file is the gate", () => {
  it("a hard link to a registered gate file is a gate path", () => {
    const gate = path.join(base, "a", "registered.jsonc");
    fs.writeFileSync(gate, "{}");
    protectGateFile(gate);
    const hard = path.join(base, "ws", "innocent.txt");
    fs.linkSync(gate, hard);
    expect(isGatePath(hard)).toBe(true);
    expect(isGatePath("innocent.txt", path.join(base, "ws"))).toBe(true);
    expect(judgeFileWrite(hard, [path.join(base, "ws")], process.platform).decision).toBe("deny");
    expect(selfProtectionDenial(analyzeCommand("echo x > innocent.txt"), path.join(base, "ws"))).not.toBeNull();
  });

  it("a hard link to the config in the gate's directory is a gate path, and OpenCode refuses a write to it", async () => {
    const hard = path.join(base, "ws", "cfg-copy.txt");
    fs.linkSync(path.join(home, ".config", "auto-classifier", "config.jsonc"), hard);
    expect(isGatePath(hard)).toBe(true);
    const llm = new FakeLlm([], { allow: true, reason: "model would allow" });
    await expect(call(plugin(llm, path.join(base, "ws")), "write", { filePath: hard, content: "{}" })).rejects.toThrow(/safety classifier/);
  });

  it("control: an unrelated hard link, and an ordinary file, are not gate paths", () => {
    const a = path.join(base, "ws", "a.txt");
    fs.writeFileSync(a, "x");
    fs.linkSync(a, path.join(base, "ws", "b.txt"));
    fs.writeFileSync(path.join(base, "ws", "c.txt"), "x");
    expect(isGatePath(path.join(base, "ws", "b.txt"))).toBe(false);
    expect(isGatePath(path.join(base, "ws", "c.txt"))).toBe(false);
  });
});
