import { describe, it, expect, afterAll } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { analyzeCommand } from "../src/rules/command-shape.js";
import { installRoot, isInstallPath, resolveInstallRoot, selfProtectionDenial } from "../src/rules/self-protection.js";
import { evaluateFastRules } from "../src/rules/fast-rules.js";
import { judgeFileWrite } from "../src/rules/file-write.js";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { handleAgyInput } from "../src/adapters/agy.js";
import { createOpenCodePlugin } from "../src/adapters/opencode.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";

// The gate refuses changes to its own code: the directory it runs from (its
// package root) or, for a single-file bundle or compiled binary, that file.
// Tests run from source, so the live install root is this checkout.

const REPO = path.resolve(import.meta.dir, "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-install-root-"));
afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

function pkg(dir: string, name = "construct-auto-classifier"): string {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name }));
  return dir;
}
function file(p: string): string {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, "// code\n");
  return p;
}
const url = (p: string) => pathToFileURL(p).href;

describe("resolveInstallRoot: every shape the gate runs in", () => {
  it("a source run (src/rules/self-protection.ts) resolves to the package root", () => {
    const root = pkg(path.join(tmp, "source"));
    expect(resolveInstallRoot(url(file(path.join(root, "src", "rules", "self-protection.ts"))))).toBe(root);
  });

  it("a built dist bundle (dist/cli.js, which bin/auto-classifier.js imports) resolves to the package root", () => {
    const root = pkg(path.join(tmp, "dist-shape"));
    expect(resolveInstallRoot(url(file(path.join(root, "dist", "cli.js"))))).toBe(root);
    expect(resolveInstallRoot(url(file(path.join(root, "dist", "opencode-plugin.js"))))).toBe(root);
  });

  it("an npm install under node_modules resolves to the package, not the project using it", () => {
    const project = pkg(path.join(tmp, "project"), "someone-elses-app");
    const root = pkg(path.join(project, "node_modules", "construct-auto-classifier"));
    expect(resolveInstallRoot(url(file(path.join(root, "dist", "index.js"))))).toBe(root);
  });

  it("a single-file bundle copied somewhere with no package of its own is that file", () => {
    const bundle = file(path.join(tmp, "plugins", "auto-classifier.js"));
    expect(resolveInstallRoot(url(bundle))).toBe(bundle);
    pkg(path.join(tmp, "other-pkg"), "not-the-gate");
    const other = file(path.join(tmp, "other-pkg", "dist", "gate.js"));
    expect(resolveInstallRoot(url(other))).toBe(other);
  });

  it("a compiled binary (bun --compile) is the executable itself", () => {
    expect(resolveInstallRoot("file:///$bunfs/root/auto-classifier", "/usr/local/bin/auto-classifier")).toBe("/usr/local/bin/auto-classifier");
    expect(resolveInstallRoot("file:///B:/~BUN/root/auto-classifier.exe", "C:\\tools\\auto-classifier.exe")).toBe("C:\\tools\\auto-classifier.exe");
  });

  it("the live gate, run from source, protects this checkout", () => {
    expect(installRoot()).toBe(fs.realpathSync(REPO));
  });
});

describe("isInstallPath", () => {
  const root = pkg(path.join(tmp, "gate"));
  file(path.join(root, "dist", "cli.js"));
  const link = path.join(tmp, "link-to-gate");
  fs.symlinkSync(root, link);

  it("matches the root and anything under it, absolute or relative to a known cwd", () => {
    expect(isInstallPath(root, undefined, root)).toBe(true);
    expect(isInstallPath(path.join(root, "dist", "cli.js"), undefined, root)).toBe(true);
    expect(isInstallPath("dist/cli.js", root, root)).toBe(true);
    expect(isInstallPath("gate/package.json", tmp, root)).toBe(true);
    expect(isInstallPath("../gate/src/new.ts", path.join(tmp, "plugins"), root)).toBe(true);
  });

  it("follows a symlink into the root", () => {
    expect(isInstallPath(path.join(link, "dist", "cli.js"), undefined, root)).toBe(true);
  });

  it("leaves a sibling, a prefix lookalike, and an unplaceable relative path alone", () => {
    expect(isInstallPath(path.join(tmp, "gate-other", "x"), undefined, root)).toBe(false);
    expect(isInstallPath(path.join(tmp, "plugins", "x.js"), undefined, root)).toBe(false);
    expect(isInstallPath("dist/cli.js", undefined, root)).toBe(false);
  });

  it("expands ~ and $HOME", () => {
    const home = os.homedir();
    const under = path.join(home, "x-gate");
    expect(isInstallPath("~/x-gate/dist/cli.js", undefined, under)).toBe(true);
    expect(isInstallPath("$HOME/x-gate/dist/cli.js", undefined, under)).toBe(true);
    expect(isInstallPath("${HOME}/x-gate/dist/cli.js", undefined, under)).toBe(true);
  });
});

describe("bash: commands that change the gate's own code are refused", () => {
  const deny = (cmd: string, cwd?: string) => selfProtectionDenial(analyzeCommand(cmd), cwd);

  it("deletes, moves, copies over, and edits in place", () => {
    expect(deny(`rm -rf ${REPO}/dist`)).toContain("the classifier's own gate");
    expect(deny(`mv ${REPO}/package.json /tmp/p.json`)).not.toBeNull();
    expect(deny(`cp /tmp/evil.js ${REPO}/dist/cli.js`)).not.toBeNull();
    expect(deny(`sed -i s/deny/allow/ ${REPO}/src/rules/fast-rules.ts`)).not.toBeNull();
    expect(deny(`chmod +w ${REPO}/bin/auto-classifier.js`)).not.toBeNull();
    expect(deny(`find ${REPO}/src -name '*.ts' -delete`)).not.toBeNull();
  });

  it("a redirect into it", () => {
    expect(deny(`echo 'export default {}' > ${REPO}/dist/opencode-plugin.js`)).not.toBeNull();
    expect(deny(`cat /tmp/x >> ${REPO}/src/index.ts`)).not.toBeNull();
  });

  it("a relative path, resolved against the command's directory and any cd on the line", () => {
    expect(deny("rm -rf dist", REPO)).not.toBeNull();
    expect(deny("echo x > src/index.ts", REPO)).not.toBeNull();
    expect(deny(`cd ${REPO} && rm bin/auto-classifier.js`, "/tmp")).not.toBeNull();
    expect(deny(`cd ${path.dirname(REPO)} && rm -rf ${path.basename(REPO)}/src`, "/tmp")).not.toBeNull();
  });

  it("git rewriting its working tree", () => {
    expect(deny(`git -C ${REPO} checkout some-branch -- .`)).not.toBeNull();
    expect(deny("git reset --hard HEAD~3", REPO)).not.toBeNull();
    expect(deny(`cd ${REPO} && git pull`, "/tmp")).not.toBeNull();
    expect(deny("git status", REPO)).toBeNull();
    expect(deny(`git -C ${REPO} log --oneline -5`)).toBeNull();
  });

  it("a redirect word, a mode or an owner is not mistaken for a path in it", () => {
    expect(deny("sudo rm -rf /var/log/audit 2>&1 | tail -5", REPO)).toBeNull();
    expect(deny("chown dev:dev /srv/app/data", REPO)).toBeNull();
    expect(deny("chmod 755 /usr/local/bin/tool", REPO)).toBeNull();
    expect(deny("dd if=README.md of=/tmp/copy bs=1M", REPO)).toBeNull();
    expect(deny(`dd if=/dev/zero of=${REPO}/dist/cli.js bs=1k count=1`)).not.toBeNull();
    expect(deny("chmod 000 package.json", REPO)).not.toBeNull();
  });

  it("a relative path is never placed against this process's own directory", () => {
    expect(deny("rm -rf dist")).toBeNull();
    expect(deny("rm -rf dist", "relative/dir")).toBeNull();
  });

  it("reading it, or writing next to it, is not refused", () => {
    expect(deny(`cat ${REPO}/package.json`)).toBeNull();
    expect(deny(`ls -la ${REPO}/dist`)).toBeNull();
    expect(deny(`rm -rf ${REPO}-other/dist`)).toBeNull();
    expect(deny("rm -rf dist", "/tmp/some-project")).toBeNull();
  });

  it("evaluateFastRules denies it before any rule, given the directory it runs in", () => {
    const rules = { fastAllow: ["^\\s*rm\\b"], fastDeny: [] };
    expect(evaluateFastRules("rm -rf dist", rules, REPO)?.matched).toBe("deny");
    expect(evaluateFastRules("rm -rf dist", rules, "/tmp/some-project")?.matched).not.toBe("deny");
  });

  it("the gate refuses it with no model call", async () => {
    const llm = new FakeLlm([], { allow: true });
    const config = testConfig();
    const gate = new AutoClassifier(config, { classifier: llm, stateManager: new StateManager(300000, 3, tmpStateDir()) });
    const out = await gate.evaluate("rm -rf dist", "s1", undefined, { cwd: REPO });
    expect(out.decision).toBe("deny");
    expect(out.reason).toContain("self-protection");
    expect(llm.calls.length).toBe(0);
  });
});

function gate(llm = new FakeLlm([], { allow: true }), policy: Parameters<typeof testConfig>[0] = {}) {
  const config = testConfig(policy);
  return new AutoClassifier(config, { classifier: llm, stateManager: new StateManager(300000, 3, tmpStateDir()) });
}

describe("agy file tools: a write to the gate's own code is refused", () => {
  const workspace = path.dirname(REPO); // the clone sits inside the workspace
  const fileCall = (name: string, target: string) =>
    JSON.stringify({ toolCall: { name, args: { TargetFile: target, CodeContent: "x" } }, conversationId: "conv-1", workspacePaths: [workspace] });

  it("judgeFileWrite denies, absolute or relative to the workspace", () => {
    expect(judgeFileWrite(path.join(REPO, "src", "index.ts"), [workspace]).decision).toBe("deny");
    expect(judgeFileWrite(path.join(path.basename(REPO), "dist", "cli.js"), [workspace]).decision).toBe("deny");
    expect(judgeFileWrite(path.join(workspace, "some-other-project", "a.ts"), [workspace]).decision).toBe("allow");
  });

  for (const tool of ["write_to_file", "replace_file_content", "multi_replace_file_content"]) {
    it(`${tool} is denied`, async () => {
      const out = await handleAgyInput(fileCall(tool, path.join(REPO, "package.json")), gate(), () => null, () => true);
      expect(out.decision).toBe("deny");
      expect(out.reason).toContain("safety classifier itself");
    });
  }

  it("run_command deleting it is denied", async () => {
    const payload = JSON.stringify({ toolCall: { name: "run_command", args: { CommandLine: "rm -rf dist", Cwd: REPO } }, conversationId: "conv-1" });
    const out = await handleAgyInput(payload, gate(), () => null, () => true);
    expect(out.decision).toBe("deny");
  });
});

describe("opencode file tools: a write to the gate's own code is refused", () => {
  const workspace = path.dirname(REPO);
  const hooks = (headless = false) => createOpenCodePlugin(gate(undefined, { headless }))({ client: {}, directory: workspace } as any) as any;
  const call = (h: any, tool: string, args: object) => h["tool.execute.before"]({ tool, sessionID: "ses_1", callID: "c1" }, { args });

  for (const [tool, args] of [
    ["write", { filePath: path.join(REPO, "dist", "opencode-plugin.js"), content: "" }],
    ["edit", { filePath: path.join(REPO, "src", "rules", "self-protection.ts"), oldString: "a", newString: "b" }],
    ["edit", { filePath: path.join(path.basename(REPO), "package.json"), oldString: "a", newString: "b" }],
    ["multiedit", { filePath: path.join(REPO, "bin", "auto-classifier.js") }],
    ["patch", { patchText: `*** Begin Patch\n*** Delete File: ${path.join(REPO, "dist", "cli.js")}\n*** End Patch` }],
    ["apply_patch", { patchText: `*** Begin Patch\n*** Update File: ${path.basename(REPO)}/src/index.ts\n@@\n-a\n+b\n*** End Patch` }],
  ] as const) {
    it(`${tool} ${JSON.stringify(args).slice(0, 60)} is refused`, async () => {
      await expect(call(hooks(), tool, args)).rejects.toThrow(/safety classifier itself|classifier's own gate/);
    });
  }

  it("evaluateFileOp and evaluatePatch deny it too, with the workspace as cwd", async () => {
    const g = gate();
    expect((await g.evaluateFileOp("write", path.join(path.basename(REPO), "dist", "cli.js"), "s", "x", { cwd: workspace })).decision).toBe("deny");
    const patchText = `*** Begin Patch\n*** Add File: ${path.basename(REPO)}/src/evil.ts\n+x\n*** End Patch`;
    expect((await g.evaluatePatch(patchText, "s", { cwd: workspace })).decision).toBe("deny");
  });

  it("reading it is fine", async () => {
    await call(hooks(), "read", { filePath: path.join(REPO, "package.json") });
  });
});

describe("opencode: harness and MCP config inside the workspace escalates, as it does on agy", () => {
  const ws = fs.mkdtempSync(path.join(tmp, "ws-"));
  const hooks = (headless = false, llm = new FakeLlm([], { allow: true })) =>
    ({ h: createOpenCodePlugin(gate(llm, { headless }))({ client: { permission: { reply: async () => {} } }, directory: ws } as any) as any, llm });
  const call = (h: any, tool: string, args: object) => h["tool.execute.before"]({ tool, sessionID: "ses_1", callID: "c1" }, { args });

  for (const target of ["opencode.json", "opencode.jsonc", ".opencode/plugins/x.js", ".mcp.json", ".claude/settings.json", ".gemini/settings.json", ".agents/hooks.json", ".github/workflows/ci.yml", ".git/hooks/pre-commit", ".githooks/pre-push"]) {
    it(`a write to ${target} is escalated with no model call, as agy escalates it`, async () => {
      const llm = new FakeLlm([], { allow: true });
      const out = await gate(llm).evaluateFileOp("write", target, "s", "x", { cwd: ws });
      expect(out.decision).toBe("force_ask");
      expect(out.escalated).toBe(true);
      expect(llm.calls.length).toBe(0);
      expect(judgeFileWrite(target, [ws]).decision).toBe("escalate");
    });
  }

  it("a patch touching one escalates the whole patch", async () => {
    const patchText = "*** Begin Patch\n*** Update File: src/a.ts\n@@\n-a\n+b\n*** Add File: .mcp.json\n+{}\n*** End Patch";
    const out = await gate().evaluatePatch(patchText, "s", { cwd: ws });
    expect(out.decision).toBe("force_ask");
  });

  it("the plugin leaves the escalation for the operator's prompt, or refuses it when headless", async () => {
    const { h } = hooks(false);
    await call(h, "write", { filePath: path.join(ws, "opencode.json"), content: "{}" });
    await expect(call(hooks(true).h, "write", { filePath: path.join(ws, "opencode.json"), content: "{}" })).rejects.toThrow(/headless/);
  });

  it("an ordinary workspace write is still allowed with no model call", async () => {
    const llm = new FakeLlm([], { allow: false });
    const out = await gate(llm).evaluateFileOp("write", "src/a.ts", "s", "x", { cwd: ws });
    expect(out.decision).toBe("allow");
    expect(llm.calls.length).toBe(0);
  });
});

describe("the built shapes, end to end", () => {
  // Build the real CLI into a package-shaped directory and a bare single file,
  // and ask each whether it may delete itself. Fast-deny decides both, so no
  // model is reached; the endpoint points at a closed loopback port anyway.
  const build = (outfile: string) =>
    spawnSync("bun", ["build", path.join(REPO, "src", "cli.ts"), "--outfile", outfile, "--target", "node"], { encoding: "utf-8" });
  const home = fs.mkdtempSync(path.join(tmp, "home-"));
  const env = { ...process.env, HOME: home, USERPROFILE: home, AUTO_CLASSIFIER_PROVIDER: "openai", AUTO_CLASSIFIER_BASE_URL: "http://127.0.0.1:9/v1", AUTO_CLASSIFIER_LOG: "" };
  const check = (entry: string, cmd: string) => {
    const r = spawnSync("node", [entry, "check", cmd], { encoding: "utf-8", env, cwd: tmp });
    return { code: r.status, out: r.stdout + r.stderr };
  };

  it("dist/cli.js run through bin/auto-classifier.js protects its package root", () => {
    const root = pkg(path.join(tmp, "built-pkg"));
    expect(build(path.join(root, "dist", "cli.js")).status).toBe(0);
    fs.mkdirSync(path.join(root, "bin"));
    fs.copyFileSync(path.join(REPO, "bin", "auto-classifier.js"), path.join(root, "bin", "auto-classifier.js"));
    const entry = path.join(root, "bin", "auto-classifier.js");
    const denied = check(entry, `rm -rf ${root}/src`);
    expect(denied.code).toBe(2);
    expect(denied.out).toContain("self-protection");
    const allowed = check(entry, `ls ${root}/dist`);
    expect(allowed.code).toBe(0);
  }, 60000);

  it("a single-file bundle with no package protects that file", () => {
    const bundle = path.join(tmp, "single", "auto-classifier-cli.js");
    expect(build(bundle).status).toBe(0);
    const denied = check(bundle, `cp /dev/null ${bundle}`);
    expect(denied.code).toBe(2);
    expect(denied.out).toContain("self-protection");
  }, 60000);
});
