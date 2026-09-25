import { describe, it, expect, afterAll, afterEach } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadConfig } from "../src/config.js";
import { evaluateFastRules } from "../src/rules/fast-rules.js";
import { buildSystemPrompt } from "../src/classifier/prompt.js";
import { buildRequest } from "../src/classifier/jev-client.js";
import { scriptProvenance, type GitRunner } from "../src/context/script-provenance.js";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { testConfig } from "./helpers/config.js";

// policy.protectedBranches: the branches a force-push or delete on a remote
// counts as data destruction, and a plain push is never fast-allowed to.
// Defaults to main and master; "development" is protected only when a config
// names it.

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-protected-branches-"));
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));
afterEach(() => {
  delete process.env.AUTO_CLASSIFIER_PROTECTED_BRANCHES;
});

function load(body: string) {
  const file = path.join(dir, `c-${Math.random().toString(36).slice(2)}.jsonc`);
  fs.writeFileSync(file, body);
  return loadConfig(file, { overlay: false });
}

const WITH_DEVELOPMENT = `{ "policy": { "protectedBranches": ["main", "master", "development"] } }`;

describe("policy.protectedBranches: config", () => {
  it("defaults to main and master", () => {
    const c = load("{}");
    expect(c.policy.protectedBranches).toEqual(["main", "master"]);
    expect(c.llm.protectedBranches).toEqual(["main", "master"]);
    expect(c.jev.protectedBranches).toEqual(["main", "master"]);
  });

  it("reads a custom list from the config file and hands it to both model paths", () => {
    const c = load(WITH_DEVELOPMENT);
    expect(c.policy.protectedBranches).toEqual(["main", "master", "development"]);
    expect(c.llm.protectedBranches).toEqual(["main", "master", "development"]);
    expect(c.jev.protectedBranches).toEqual(["main", "master", "development"]);
  });

  it("AUTO_CLASSIFIER_PROTECTED_BRANCHES overrides the file, comma-separated", () => {
    process.env.AUTO_CLASSIFIER_PROTECTED_BRANCHES = "main, trunk ,release/1.x";
    expect(load(WITH_DEVELOPMENT).policy.protectedBranches).toEqual(["main", "trunk", "release/1.x"]);
  });

  it("a value that is not a list of branch names falls back to the default, never to nothing", () => {
    expect(load(`{ "policy": { "protectedBranches": "development" } }`).policy.protectedBranches).toEqual(["main", "master"]);
    expect(load(`{ "policy": { "protectedBranches": ["main", "dev elopment", 3] } }`).policy.protectedBranches).toEqual(["main"]);
  });
});

describe("policy.protectedBranches: the default push fast-allow", () => {
  const push = (cfg: ReturnType<typeof load>, cmd: string) => evaluateFastRules(cmd, cfg.rules)?.matched ?? null;

  it("by default, development is NOT protected: a plain push to it is fast-allowed; main and master are not", () => {
    const c = load("{}");
    expect(push(c, "git push origin development")).toBe("allow");
    expect(push(c, "git push origin feature/x")).toBe("allow");
    expect(push(c, "git push origin main")).toBeNull();
    expect(push(c, "git push -u origin master")).toBeNull();
  });

  it("a custom list protects what it names", () => {
    const c = load(WITH_DEVELOPMENT);
    expect(push(c, "git push origin development")).toBeNull();
    expect(push(c, "git push origin main")).toBeNull();
    expect(push(c, "git push origin feature/x")).toBe("allow");
  });

  it("a branch name is matched literally, never as a pattern", () => {
    process.env.AUTO_CLASSIFIER_PROTECTED_BRANCHES = "release/1.x";
    const c = load("{}");
    expect(push(c, "git push origin release/1.x")).toBeNull();
    expect(push(c, "git push origin release/1ax")).toBe("allow");
  });
});

describe("policy.protectedBranches: the model-facing text", () => {
  it("the chat prompt names the default list, and not development", () => {
    const p = buildSystemPrompt();
    expect(p).toContain("force-pushing to or deleting main/master on a remote");
    expect(p).not.toContain("development");
  });

  it("the chat prompt names a custom list", () => {
    const p = buildSystemPrompt(undefined, undefined, ["main", "master", "development"]);
    expect(p).toContain("force-pushing to or deleting main/master/development on a remote");
  });

  it("Jev's verdict criteria and data-destruction question name the configured list", () => {
    const def = buildRequest("x", undefined, { model: "jev-x" }) as any;
    expect(def.questions.verdict.criteria.deny).toContain("force-pushing to or deleting main/master on a remote");
    expect(def.questions.data_destruction.instructions).toContain("force-push to or delete main/master on a remote?");
    expect(JSON.stringify(def.questions)).not.toContain("development");

    const custom = buildRequest("x", undefined, { model: "jev-x", protectedBranches: ["main", "master", "development"] }) as any;
    expect(custom.questions.verdict.criteria.deny).toContain("force-pushing to or deleting main/master/development on a remote");
    expect(custom.questions.data_destruction.instructions).toContain("force-push to or delete main/master/development on a remote?");
  });
});

describe("policy.protectedBranches: script provenance's default-branch fallback", () => {
  // A remote with no HEAD symref whose only branch is `development`.
  const script = path.join(dir, "run.sh");
  fs.writeFileSync(script, "echo hi\n");
  const git: GitRunner = (args) => {
    const a = args.join(" ");
    if (a === "rev-parse --show-toplevel") return { status: 0, stdout: dir };
    if (a.startsWith("ls-files")) return { status: 0, stdout: "run.sh" };
    if (a === "remote") return { status: 0, stdout: "origin" };
    if (a.startsWith("symbolic-ref")) return { status: 1, stdout: "" };
    if (a === "rev-parse -q --verify refs/remotes/origin/development") return { status: 0, stdout: "deadbeef" };
    if (a.startsWith("rev-parse -q --verify refs/remotes/")) return { status: 1, stdout: "" };
    if (a.startsWith("hash-object")) return { status: 0, stdout: "blob1" };
    if (a === "rev-parse -q --verify origin/development:run.sh") return { status: 0, stdout: "blob1" };
    return { status: 1, stdout: "" };
  };

  it("by default only main and master are tried, so a development-only remote has no default branch", () => {
    const p = scriptProvenance("./run.sh", dir, { git })!;
    expect(p.landed).toBe(false);
    expect(p.summary).toContain("no remote default branch");
  });

  it("a configured list is tried in order", () => {
    const p = scriptProvenance("./run.sh", dir, { git, protectedBranches: ["main", "master", "development"] })!;
    expect(p.landed).toBe(true);
    expect(p.ref).toBe("origin/development");
  });

  it("the gate passes policy.protectedBranches through", async () => {
    const stateDir = fs.mkdtempSync(path.join(dir, "state-"));
    const gate = new AutoClassifier(testConfig({ protectedBranches: ["main", "master", "development"] }), {
      git,
      stateManager: new StateManager(300000, 3, stateDir),
      classifier: { classify: async () => ({ allow: false, reason: "model", source: "llm" }) },
    });
    const out = await gate.evaluate("./run.sh", "s1", undefined, { cwd: dir });
    expect(out.decision).toBe("allow");
    expect(out.reason).toContain("origin/development");
  });
});
