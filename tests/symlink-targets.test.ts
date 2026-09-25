import { describe, it, expect } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { createOpenCodePlugin } from "../src/adapters/opencode.js";
import { judgeFileWrite } from "../src/rules/file-write.js";
import { installRoot } from "../src/rules/self-protection.js";
import { resolveRealPath, targetLocations } from "../src/rules/workspace.js";
import { findReferencedFiles } from "../src/context/file-references.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";

/**
 * Every file-tool rule decides on where a write actually lands, with every
 * symlink followed, as well as on the path as written. Each fixture here is a
 * throwaway directory tree: a workspace, a scratch root configured to lie
 * inside the fixture (so nothing depends on the machine's own /tmp), and an
 * "outside" directory that is inside no root at all. Links are created by the
 * tests themselves and point only at dummy files in that tree. Nothing is ever
 * written through them; only verdicts are read.
 */
function fixture() {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "aclass-symlink-")));
  const dirs = {
    base,
    ws: path.join(base, "ws"),
    scratch: path.join(base, "scratch"),
    outside: path.join(base, "outside"),
    home: path.join(base, "home"),
  };
  for (const d of [dirs.ws, dirs.scratch, dirs.outside, path.join(dirs.outside, "sub"), path.join(dirs.home, ".ssh"), path.join(dirs.home, ".config", "auto-classifier"), path.join(dirs.ws, ".git", "hooks"), path.join(dirs.ws, "real")]) {
    fs.mkdirSync(d, { recursive: true });
  }
  fs.writeFileSync(path.join(dirs.outside, "dummy.txt"), "dummy");
  fs.writeFileSync(path.join(dirs.home, ".ssh", "id_ed25519"), "dummy");
  fs.writeFileSync(path.join(dirs.home, ".config", "auto-classifier", "config.jsonc"), "{}");
  fs.writeFileSync(path.join(dirs.home, ".bashrc"), "dummy");
  fs.writeFileSync(path.join(dirs.ws, "real", "file.txt"), "dummy");
  return dirs;
}

type Dirs = ReturnType<typeof fixture>;

function build(llm: FakeLlm, d: Dirs, scratchWriteRoots: string[] = [d.scratch + "/"]) {
  const config = testConfig({}, { scratchWriteRoots });
  const state = new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir());
  return new AutoClassifier(config, { classifier: llm, stateManager: state });
}

const link = (target: string, at: string) => {
  fs.symlinkSync(target, at);
  return at;
};

const patchFor = (...targets: string[]) => ["*** Begin Patch", ...targets.flatMap((t) => [`*** Update File: ${t}`, "@@", "-a", "+b"]), "*** End Patch"].join("\n");

describe("resolveRealPath follows every link the kernel would", () => {
  it("follows a link as the last component", () => {
    const d = fixture();
    const l = link(path.join(d.outside, "dummy.txt"), path.join(d.scratch, "l"));
    expect(resolveRealPath(l)).toBe(path.join(d.outside, "dummy.txt"));
  });
  it("follows a dangling link to where a write through it would create its target", () => {
    const d = fixture();
    const l = link(path.join(d.outside, "not-yet.txt"), path.join(d.scratch, "dangling"));
    expect(resolveRealPath(l)).toBe(path.join(d.outside, "not-yet.txt"));
  });
  it("follows a link in a directory component, with the rest not existing yet", () => {
    const d = fixture();
    link(d.outside, path.join(d.scratch, "dir"));
    expect(resolveRealPath(path.join(d.scratch, "dir", "new", "f.txt"))).toBe(path.join(d.outside, "new", "f.txt"));
  });
  it("follows a dangling link in a directory component", () => {
    const d = fixture();
    link(path.join(d.outside, "gone"), path.join(d.scratch, "dir"));
    expect(resolveRealPath(path.join(d.scratch, "dir", "f.txt"))).toBe(path.join(d.outside, "gone", "f.txt"));
  });
  it("follows a link to a link, and a relative link from the directory it sits in", () => {
    const d = fixture();
    link(path.join("..", "outside", "dummy.txt"), path.join(d.scratch, "second"));
    const first = link("second", path.join(d.scratch, "first"));
    expect(resolveRealPath(first)).toBe(path.join(d.outside, "dummy.txt"));
  });
  it("applies .. after a link to the link's target, as the kernel does", () => {
    const d = fixture();
    link(path.join(d.outside, "sub"), path.join(d.ws, "into"));
    expect(resolveRealPath(`${d.ws}/into/../x.txt`)).toBe(path.join(d.outside, "x.txt"));
  });
  it("stops on a link loop instead of spinning", () => {
    const d = fixture();
    link(path.join(d.scratch, "b"), path.join(d.scratch, "a"));
    link(path.join(d.scratch, "a"), path.join(d.scratch, "b"));
    expect(typeof resolveRealPath(path.join(d.scratch, "a", "x"))).toBe("string");
  });
  it("names both the lettered and the landed location of a target", () => {
    const d = fixture();
    link(path.join(d.outside, "dummy.txt"), path.join(d.ws, "l"));
    expect(targetLocations("l", d.ws).sort()).toEqual([path.join(d.outside, "dummy.txt"), path.join(d.ws, "l")].sort());
    expect(targetLocations("relative/only")).toEqual([]);
  });
});

describe("OpenCode write/edit/patch: a scratch root is judged where the write lands", () => {
  for (const tool of ["write", "edit"] as const) {
    it(`${tool}: a link under a scratch root to a file outside every root goes to the model`, async () => {
      const d = fixture();
      const l = link(path.join(d.outside, "dummy.txt"), path.join(d.scratch, "l"));
      const llm = new FakeLlm();
      const out = await build(llm, d).evaluateFileOp(tool, l, "s", "x", { cwd: d.ws });
      expect(out.decision).not.toBe("allow");
      expect(llm.calls.length).toBe(1);
    });
  }

  it("patch: a link under a scratch root to a file outside every root goes to the model", async () => {
    const d = fixture();
    const l = link(path.join(d.outside, "dummy.txt"), path.join(d.scratch, "l"));
    const llm = new FakeLlm();
    const out = await build(llm, d).evaluatePatch(patchFor(l), "s", { cwd: d.ws });
    expect(out.decision).not.toBe("allow");
    expect(llm.calls.length).toBe(1);
  });

  it("a dangling link, a directory link and a link to a link under a scratch root all go to the model", async () => {
    const d = fixture();
    const dangling = link(path.join(d.outside, "new.txt"), path.join(d.scratch, "dangling"));
    link(d.outside, path.join(d.scratch, "dir"));
    link(path.join(d.outside, "dummy.txt"), path.join(d.scratch, "second"));
    const chained = link(path.join(d.scratch, "second"), path.join(d.scratch, "first"));
    for (const target of [dangling, path.join(d.scratch, "dir", "new.txt"), chained]) {
      const llm = new FakeLlm();
      const out = await build(llm, d).evaluateFileOp("write", target, "s", "x", { cwd: d.ws });
      expect(out.decision).not.toBe("allow");
      expect(llm.calls.length).toBe(1);
    }
  });

  it("a workspace under a scratch root: a link inside it pointing outside is not let through by the scratch check", async () => {
    const d = fixture();
    const ws = path.join(d.scratch, "ws");
    fs.mkdirSync(ws);
    link(path.join(d.outside, "dummy.txt"), path.join(ws, "l"));
    const llm = new FakeLlm();
    const out = await build(llm, d).evaluateFileOp("write", "l", "s", "x", { cwd: ws });
    expect(out.decision).not.toBe("allow");
    expect(llm.calls.length).toBe(1);
    const llm2 = new FakeLlm();
    const patched = await build(llm2, d).evaluatePatch(patchFor("l"), "s", { cwd: ws });
    expect(patched.decision).not.toBe("allow");
    expect(llm2.calls.length).toBe(1);
  });

  it("a link as the last component under a scratch root is never scratch, even pointing back into it", async () => {
    const d = fixture();
    fs.writeFileSync(path.join(d.scratch, "inside.txt"), "dummy");
    const l = link(path.join(d.scratch, "inside.txt"), path.join(d.scratch, "l"));
    const llm = new FakeLlm();
    const out = await build(llm, d).evaluateFileOp("write", l, "s", "x", { cwd: d.ws });
    expect(llm.calls.length).toBe(1);
    expect(out.decision).not.toBe("allow");
  });

  it("still allows, with no model call, a scratch directory reached through a link that stays in the root", async () => {
    const d = fixture();
    fs.mkdirSync(path.join(d.scratch, "realdir"));
    link(path.join(d.scratch, "realdir"), path.join(d.scratch, "dl"));
    const llm = new FakeLlm();
    const out = await build(llm, d).evaluateFileOp("write", path.join(d.scratch, "dl", "f.txt"), "s", "x", { cwd: d.ws });
    expect(out.decision).toBe("allow");
    expect(llm.calls.length).toBe(0);
  });

  it("a scratch root written without a trailing slash does not cover a sibling sharing its prefix", async () => {
    const d = fixture();
    fs.mkdirSync(path.join(d.base, "scratchx"));
    const llm = new FakeLlm();
    const out = await build(llm, d, [d.scratch]).evaluateFileOp("write", path.join(d.base, "scratchx", "f.txt"), "s", "x", { cwd: d.ws });
    expect(out.decision).not.toBe("allow");
    expect(llm.calls.length).toBe(1);
  });
});

describe("OpenCode write/edit: the workspace is judged where the write lands", () => {
  it("a link inside the workspace pointing outside goes to the model; one pointing inside is allowed", async () => {
    const d = fixture();
    link(path.join(d.outside, "dummy.txt"), path.join(d.ws, "out"));
    link(path.join(d.ws, "real", "file.txt"), path.join(d.ws, "in"));
    const llm = new FakeLlm();
    const c = build(llm, d, []);
    expect((await c.evaluateFileOp("write", "out", "s", "x", { cwd: d.ws })).decision).not.toBe("allow");
    expect(llm.calls.length).toBe(1);
    expect((await c.evaluateFileOp("write", "in", "s", "x", { cwd: d.ws })).decision).toBe("allow");
    expect(llm.calls.length).toBe(1);
  });

  it("`link/..` is judged where the kernel puts it, not where its letters fold to", async () => {
    const d = fixture();
    link(path.join(d.outside, "sub"), path.join(d.ws, "into"));
    const llm = new FakeLlm();
    const out = await build(llm, d, []).evaluateFileOp("write", "into/../x.txt", "s", "x", { cwd: d.ws });
    expect(out.decision).not.toBe("allow");
    expect(llm.calls.length).toBe(1);
  });

  it("a link to a sensitive place inside the workspace escalates as that place does", async () => {
    const d = fixture();
    link(path.join(d.ws, ".git", "hooks"), path.join(d.ws, "hooks"));
    const llm = new FakeLlm();
    const out = await build(llm, d, []).evaluateFileOp("write", "hooks/pre-commit", "s", "x", { cwd: d.ws });
    expect(out.decision).toBe("force_ask");
    expect(llm.calls.length).toBe(0);
  });

  it("a link to a shell startup file is judged by the model even when the link sits in the workspace", async () => {
    const d = fixture();
    link(path.join(d.home, ".bashrc"), path.join(d.ws, "rc"));
    const llm = new FakeLlm();
    const out = await build(llm, d, []).evaluateFileOp("edit", "rc", "s", "x", { cwd: d.ws });
    expect(out.decision).not.toBe("allow");
    expect(llm.calls.length).toBe(1);
  });
});

describe("OpenCode: a link to a secret or to the gate is refused like the thing itself", () => {
  it("read, write and patch of a link to a credential file are denied with no model call", async () => {
    const d = fixture();
    link(path.join(d.home, ".ssh", "id_ed25519"), path.join(d.ws, "k"));
    const llm = new FakeLlm();
    const c = build(llm, d);
    const read = await c.evaluateFileOp("read", "k", "s", undefined, { cwd: d.ws });
    expect(read.decision).toBe("deny");
    const write = await c.evaluateFileOp("write", path.join(d.ws, "k"), "s", "x", { cwd: d.ws });
    expect(write.decision).toBe("deny");
    const patched = await c.evaluatePatch(patchFor("k"), "s", { cwd: d.ws });
    expect(patched.decision).toBe("deny");
    expect(llm.calls.length).toBe(0);
  });

  it("a search scoped through a link into a credential directory is denied", async () => {
    const d = fixture();
    link(path.join(d.home, ".ssh"), path.join(d.ws, "keys"));
    const c = build(new FakeLlm(), d);
    expect((await c.evaluateSearchScope("grep", path.join(d.ws, "keys"), "s")).decision).toBe("deny");
    expect((await c.evaluateSearchScope("glob", "keys", "s", { cwd: d.ws })).decision).toBe("deny");
    expect((await c.evaluateSearchScope("list", "real", "s", { cwd: d.ws })).decision).toBe("allow");
  });

  it("write, edit and patch of a link to the gate's config are denied with no model call", async () => {
    const d = fixture();
    link(path.join(d.home, ".config", "auto-classifier", "config.jsonc"), path.join(d.scratch, "cfg"));
    link(path.join(d.home, ".config", "auto-classifier"), path.join(d.ws, "gate"));
    const llm = new FakeLlm();
    const c = build(llm, d);
    for (const tool of ["write", "edit"] as const) {
      expect((await c.evaluateFileOp(tool, path.join(d.scratch, "cfg"), "s", "x", { cwd: d.ws })).decision).toBe("deny");
      expect((await c.evaluateFileOp(tool, "gate/telemetry.jsonl", "s", "x", { cwd: d.ws })).decision).toBe("deny");
    }
    expect((await c.evaluatePatch(patchFor("gate/config.jsonc"), "s", { cwd: d.ws })).decision).toBe("deny");
    expect(llm.calls.length).toBe(0);
  });

  it("a write reaching the gate's own code through `link/..` is denied", async () => {
    const d = fixture();
    const root = installRoot();
    expect(root).not.toBeNull();
    link(path.join(root!, "src"), path.join(d.ws, "code"));
    const llm = new FakeLlm();
    const out = await build(llm, d, []).evaluateFileOp("write", "code/../package.json", "s", "x", { cwd: d.ws });
    expect(out.decision).toBe("deny");
    expect(llm.calls.length).toBe(0);
  });

  it("the plugin refuses a read of a link to the gate's config before the ladder runs", async () => {
    const d = fixture();
    link(path.join(d.home, ".config", "auto-classifier", "config.jsonc"), path.join(d.ws, "cfg"));
    const config = testConfig();
    const classifier = new AutoClassifier(config, { classifier: new FakeLlm(), stateManager: new StateManager(300000, 3, tmpStateDir()) });
    const h = createOpenCodePlugin(classifier)({ client: {}, directory: d.ws } as any) as any;
    const call = (tool: string, args: object) => h["tool.execute.before"]({ tool, sessionID: "ses_1", callID: "c1" }, { args });
    await expect(call("read", { filePath: "cfg" })).rejects.toThrow(/safety classifier itself/);
    await expect(call("write", { filePath: path.join(d.ws, "cfg"), content: "" })).rejects.toThrow(/safety classifier itself/);
  });
});

describe("agy judgeFileWrite: judged where the write lands", () => {
  it("escalates a link inside the workspace that points outside it, as the target itself does", () => {
    const d = fixture();
    link(path.join(d.outside, "dummy.txt"), path.join(d.ws, "l"));
    const direct = judgeFileWrite(path.join(d.outside, "dummy.txt"), [d.ws]);
    const viaLink = judgeFileWrite(path.join(d.ws, "l"), [d.ws]);
    expect(direct.decision).toBe("escalate");
    expect(viaLink.decision).toBe("escalate");
    expect(viaLink.decision === "escalate" && viaLink.reason).toContain("outside the session's workspace");
    expect(judgeFileWrite("l", [d.ws]).decision).toBe("escalate");
  });

  it("escalates a dangling link, a directory link, a link to a link and `link/..` that land outside", () => {
    const d = fixture();
    link(path.join(d.outside, "new.txt"), path.join(d.ws, "dangling"));
    link(d.outside, path.join(d.ws, "dir"));
    link(path.join(d.outside, "dummy.txt"), path.join(d.ws, "second"));
    link("second", path.join(d.ws, "first"));
    link(path.join(d.outside, "sub"), path.join(d.ws, "into"));
    for (const target of ["dangling", "dir/new.txt", "first", "into/../x.txt"]) {
      expect(judgeFileWrite(target, [d.ws]).decision).toBe("escalate");
    }
  });

  it("allows a link that stays inside the workspace", () => {
    const d = fixture();
    link(path.join(d.ws, "real", "file.txt"), path.join(d.ws, "in"));
    expect(judgeFileWrite("in", [d.ws])).toEqual({ decision: "allow" });
  });

  it("escalates a link to a sensitive place inside the workspace", () => {
    const d = fixture();
    link(path.join(d.ws, ".git", "hooks"), path.join(d.ws, "hooks"));
    const v = judgeFileWrite("hooks/pre-commit", [d.ws]);
    expect(v.decision).toBe("escalate");
    expect(v.decision === "escalate" && v.reason).toContain("git's own directory");
  });

  it("denies a link to the gate's config", () => {
    const d = fixture();
    link(path.join(d.home, ".config", "auto-classifier", "config.jsonc"), path.join(d.ws, "cfg"));
    expect(judgeFileWrite("cfg", [d.ws]).decision).toBe("deny");
  });

  it("escalates a sensitive startup file inside a workspace that is the home directory, directly or through a link", () => {
    const d = fixture();
    const direct = judgeFileWrite(path.join(d.home, ".bashrc"), [d.home]);
    expect(direct.decision).toBe("escalate");
    link(path.join(d.home, ".bashrc"), path.join(d.home, "rc"));
    expect(judgeFileWrite("rc", [d.home]).decision).toBe("escalate");
  });
});

describe("shell self-protection: a symlink to one of the gate's files counts as that file", () => {
  it("denies a redirect into a link to the gate's config, with no model call", async () => {
    const d = fixture();
    link(path.join(d.home, ".config", "auto-classifier", "config.jsonc"), path.join(d.ws, "cfg"));
    const llm = new FakeLlm();
    const out = await build(llm, d).evaluate("echo x > cfg", "s", undefined, { cwd: d.ws });
    expect(out.decision).toBe("deny");
    expect(out.reason).toContain("self-protection");
    expect(llm.calls.length).toBe(0);
  });
});

describe("attached file references: a link to the gate's config is never shown", () => {
  it("withholds a referenced file whose link lands in the gate's config", () => {
    const d = fixture();
    link(path.join(d.home, ".config", "auto-classifier", "config.jsonc"), path.join(d.ws, "notes.json"));
    fs.writeFileSync(path.join(d.ws, "plain.json"), "{}");
    const found = findReferencedFiles("cat notes.json plain.json", d.ws);
    expect(found.map((f) => f.path)).toEqual(["notes.json", "plain.json"]);
    expect(found[0]!.content).toContain("withheld");
  });
});
